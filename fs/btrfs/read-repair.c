// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (c) 2022 Christoph Hellwig.
 */
#include "ctree.h"
#include "volumes.h"
#include "read-repair.h"
#include "btrfs_inode.h"

static struct bio_set read_repair_bioset;

static int next_mirror(struct btrfs_read_repair *rr, int cur_mirror)
{
	if (cur_mirror == rr->num_copies)
		return cur_mirror + 1 - rr->num_copies;
	return cur_mirror + 1;
}

static int prev_mirror(struct btrfs_read_repair *rr, int cur_mirror)
{
	if (cur_mirror == 1)
		return rr->num_copies;
	return cur_mirror - 1;
}

/*
 * Clone a new bio from the src_bbio, using the saved iter in the btrfs_bio
 * instead of using bio->bi_iter like the block layer cloning helpers.
 */
static struct btrfs_bio *btrfs_repair_bio_clone(struct btrfs_bio *src_bbio,
		u64 offset, u32 size, unsigned int op)
{
	struct btrfs_bio *bbio;
	struct bio *bio;

	bio = bio_alloc_bioset(NULL, 0, op | REQ_SYNC, GFP_NOFS,
			       &read_repair_bioset);
	bio_set_flag(bio, BIO_CLONED);

	bio->bi_io_vec = src_bbio->bio.bi_io_vec;
	bio->bi_iter = src_bbio->iter;
	bio_advance(bio, offset);
	bio->bi_iter.bi_size = size;

	bbio = btrfs_bio(bio);
	memset(bbio, 0, offsetof(struct btrfs_bio, bio));
	bbio->iter = bbio->bio.bi_iter;
	bbio->file_offset = src_bbio->file_offset + offset;

	return bbio;
}

static void btrfs_repair_one_mirror(struct btrfs_bio *read_bbio,
		struct btrfs_bio *failed_bbio, struct inode *inode,
		u32 good_size, int bad_mirror)
{
	struct btrfs_fs_info *fs_info = btrfs_sb(inode->i_sb);
	struct btrfs_inode *bi = BTRFS_I(inode);
	u64 logical = read_bbio->iter.bi_sector << SECTOR_SHIFT;
	u64 file_offset = read_bbio->file_offset;
	struct btrfs_bio *write_bbio;
	int ret;

	/*
	 * For zoned file systems repair has to relocate the whole zone.
	 */
	if (btrfs_repair_one_zone(fs_info, logical))
		return;

	/*
	 * Otherwise just clone good part of the read bio and write it back to
	 * the previously bad mirror.
	 */
	write_bbio = btrfs_repair_bio_clone(read_bbio, 0, good_size,
				REQ_OP_WRITE);
	ret = btrfs_map_repair_bio(fs_info, &write_bbio->bio, bad_mirror);
	bio_put(&write_bbio->bio);

	btrfs_info_rl(fs_info,
		"%s: root %lld ino %llu off %llu logical %llu/%u from good mirror %d",
		ret ? "failed to correct read error" : "read error corrected",
		bi->root->root_key.objectid, btrfs_ino(bi),
		file_offset, logical, read_bbio->iter.bi_size, bad_mirror);
}

static bool btrfs_repair_read_bio(struct btrfs_bio *bbio,
		struct btrfs_bio *failed_bbio, struct inode *inode,
		u32 *good_size, int read_mirror)
{
	struct btrfs_fs_info *fs_info = btrfs_sb(inode->i_sb);
	u32 start_offset = bbio->file_offset - failed_bbio->file_offset;
	u8 csum[BTRFS_CSUM_SIZE];
	struct bvec_iter iter;
	struct bio_vec bv;
	u32 offset;

	if (btrfs_map_repair_bio(fs_info, &bbio->bio, read_mirror))
		return false;

	*good_size = bbio->iter.bi_size;
	if (BTRFS_I(inode)->flags & BTRFS_INODE_NODATASUM)
		return true;

	btrfs_bio_for_each_sector(fs_info, bv, bbio, iter, offset) {
		u8 *expected_csum =
			btrfs_csum_ptr(fs_info, failed_bbio->csum,
					start_offset + offset);

		if (btrfs_check_sector_csum(fs_info, bv.bv_page, bv.bv_offset,
				csum, expected_csum)) {
			/*
			 * Just fail if checksum verification failed for the
			 * very first sector.  Else return how much good data we
			 * found so that we can only write back as much to the
			 * bad mirror(s).
			 */
			if (offset == 0)
				return false;
			*good_size = offset;
			break;
		}
	}

	return true;
}

bool __btrfs_read_repair_finish(struct btrfs_read_repair *rr,
		struct btrfs_bio *failed_bbio, struct inode *inode,
		u64 end_offset, repair_endio_t endio)
{
	u8 first_mirror, bad_mirror, read_mirror;
	u64 start_offset = rr->start_offset;
	struct btrfs_bio *read_bbio = NULL;
	bool uptodate = false;
	u32 good_size;

	bad_mirror = first_mirror = failed_bbio->mirror_num;
	while ((read_mirror = next_mirror(rr, bad_mirror)) != first_mirror) {
		if (read_bbio)
			bio_put(&read_bbio->bio);

		/*
		 * Try to read the entire failed range from a presumably good
		 * range.
		 */
		read_bbio = btrfs_repair_bio_clone(failed_bbio,
				start_offset, end_offset - start_offset,
				REQ_OP_READ);
		if (!btrfs_repair_read_bio(read_bbio, failed_bbio, inode,
				&good_size, read_mirror)) {
			/*
			 * If we failed to read any data at all, go straight to
			 * the next mirror.
			 */
			bad_mirror = read_mirror;
			continue;
		}

		/*
		 * If we have some good data write it back to all the previously
		 * bad mirrors.
		 */
		for (;;) {
			btrfs_repair_one_mirror(read_bbio, failed_bbio, inode,
						good_size, bad_mirror);
			if (bad_mirror == first_mirror)
				break;
			bad_mirror = prev_mirror(rr, bad_mirror);
		}

		/*
		 * If the whole bio was good, we are done now.
		 */
		if (good_size == read_bbio->iter.bi_size) {
			uptodate = true;
			break;
		}

		/*
		 * Only the start of the bio was good. Complete the good bytes
		 * and fix up the iter to cover bad sectors so that the bad
		 * range can be passed to the endio handler n case there is no
		 * good mirror left.
		 */
		if (endio)
			endio(read_bbio, inode, true);
		start_offset += good_size;
		read_bbio->file_offset += good_size;
		bio_advance_iter(&read_bbio->bio, &read_bbio->iter, good_size);

		/*
		 * Restart the loop now that we've made some progress.
		 *
		 * This ensures we go back to mirrors that returned bad data for
		 * earlier as they might have good data for subsequent sectors.
		 */
		first_mirror = bad_mirror = read_mirror;
	}

	if (endio)
		endio(read_bbio, inode, uptodate);
	bio_put(&read_bbio->bio);

	rr->in_use = false;
	return uptodate;
}

bool btrfs_read_repair_add(struct btrfs_read_repair *rr,
		struct btrfs_bio *failed_bbio, struct inode *inode,
		u64 start_offset)
{
	if (rr->in_use)
		return true;

	/*
	 * Only set ->num_copies once as it must be the same for the whole
	 * I/O that the repair code iterates over.
	 */
	if (!rr->num_copies) {
		struct btrfs_fs_info *fs_info = btrfs_sb(inode->i_sb);

		rr->num_copies = btrfs_num_copies(fs_info,
				failed_bbio->iter.bi_sector << SECTOR_SHIFT,
				failed_bbio->iter.bi_size);
	}

	/*
	 * If there is no other copy of the data to recovery from, give up now
	 * and don't even try to build up a larget batch.
	 */
	if (rr->num_copies < 2)
		return false;

	rr->in_use = true;
	rr->start_offset = start_offset;
	return true;
}

int __init btrfs_read_repair_init(void)
{
	return bioset_init(&read_repair_bioset, BIO_POOL_SIZE,
			offsetof(struct btrfs_bio, bio), 0);
}

void btrfs_read_repair_exit(void)
{
	bioset_exit(&read_repair_bioset);
}
