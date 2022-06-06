/* SPDX-License-Identifier: GPL-2.0 */
#ifndef BTRFS_READ_REPAIR_H
#define BTRFS_READ_REPAIR_H

struct btrfs_read_repair {
	u64 start_offset;
	bool in_use;
	int num_copies;
};

typedef void (*repair_endio_t)(struct btrfs_bio *repair_bbio,
		struct inode *inode, bool uptodate);

bool btrfs_read_repair_add(struct btrfs_read_repair *rr,
		struct btrfs_bio *failed_bbio, struct inode *inode,
		u64 bio_offset);
bool __btrfs_read_repair_finish(struct btrfs_read_repair *rr,
		struct btrfs_bio *failed_bbio, struct inode *inode,
		u64 end_offset, repair_endio_t end_io);
static inline bool btrfs_read_repair_finish(struct btrfs_read_repair *rr,
		struct btrfs_bio *failed_bbio, struct inode *inode,
		u64 end_offset, repair_endio_t endio)
{
	if (!rr->in_use)
		return true;
	return __btrfs_read_repair_finish(rr, failed_bbio, inode, end_offset,
			endio);
}

int __init btrfs_read_repair_init(void);
void btrfs_read_repair_exit(void);

#endif /* BTRFS_READ_REPAIR_H */
