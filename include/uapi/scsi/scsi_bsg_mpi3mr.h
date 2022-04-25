/* SPDX-License-Identifier: GPL-2.0-or-later WITH Linux-syscall-note */
/*
 * Driver for Broadcom MPI3 Storage Controllers
 *
 * Copyright (C) 2017-2022 Broadcom Inc.
 *  (mailto: mpi3mr-linuxdrv.pdl@broadcom.com)
 *
 */

#ifndef SCSI_BSG_MPI3MR_H_INCLUDED
#define SCSI_BSG_MPI3MR_H_INCLUDED

/* Definitions for BSG commands */
#define MPI3MR_IOCTL_VERSION			0x06

#define MPI3MR_APP_DEFAULT_TIMEOUT		(60) /*seconds*/

#define MPI3MR_BSG_ADPTYPE_UNKNOWN		0
#define MPI3MR_BSG_ADPTYPE_AVGFAMILY		1

#define MPI3MR_BSG_ADPSTATE_UNKNOWN		0
#define MPI3MR_BSG_ADPSTATE_OPERATIONAL		1
#define MPI3MR_BSG_ADPSTATE_FAULT		2
#define MPI3MR_BSG_ADPSTATE_IN_RESET		3
#define MPI3MR_BSG_ADPSTATE_UNRECOVERABLE	4

#define MPI3MR_BSG_ADPRESET_UNKNOWN		0
#define MPI3MR_BSG_ADPRESET_SOFT		1
#define MPI3MR_BSG_ADPRESET_DIAG_FAULT		2

#define MPI3MR_BSG_LOGDATA_MAX_ENTRIES		400
#define MPI3MR_BSG_LOGDATA_ENTRY_HEADER_SZ	4

#define MPI3MR_DRVBSG_OPCODE_UNKNOWN		0
#define MPI3MR_DRVBSG_OPCODE_ADPINFO		1
#define MPI3MR_DRVBSG_OPCODE_ADPRESET		2
#define MPI3MR_DRVBSG_OPCODE_ALLTGTDEVINFO	4
#define MPI3MR_DRVBSG_OPCODE_GETCHGCNT		5
#define MPI3MR_DRVBSG_OPCODE_LOGDATAENABLE	6
#define MPI3MR_DRVBSG_OPCODE_PELENABLE		7
#define MPI3MR_DRVBSG_OPCODE_GETLOGDATA		8
#define MPI3MR_DRVBSG_OPCODE_QUERY_HDB		9
#define MPI3MR_DRVBSG_OPCODE_REPOST_HDB		10
#define MPI3MR_DRVBSG_OPCODE_UPLOAD_HDB		11
#define MPI3MR_DRVBSG_OPCODE_REFRESH_HDB_TRIGGERS	12


#define MPI3MR_BSG_BUFTYPE_UNKNOWN		0
#define MPI3MR_BSG_BUFTYPE_RAIDMGMT_CMD		1
#define MPI3MR_BSG_BUFTYPE_RAIDMGMT_RESP	2
#define MPI3MR_BSG_BUFTYPE_DATA_IN		3
#define MPI3MR_BSG_BUFTYPE_DATA_OUT		4
#define MPI3MR_BSG_BUFTYPE_MPI_REPLY		5
#define MPI3MR_BSG_BUFTYPE_ERR_RESPONSE		6
#define MPI3MR_BSG_BUFTYPE_MPI_REQUEST		0xFE

#define MPI3MR_BSG_MPI_REPLY_BUFTYPE_UNKNOWN	0
#define MPI3MR_BSG_MPI_REPLY_BUFTYPE_STATUS	1
#define MPI3MR_BSG_MPI_REPLY_BUFTYPE_ADDRESS	2

#define MPI3MR_HDB_BUFTYPE_UNKNOWN		0
#define MPI3MR_HDB_BUFTYPE_TRACE		1
#define MPI3MR_HDB_BUFTYPE_FIRMWARE		2
#define MPI3MR_HDB_BUFTYPE_RESERVED		3

#define MPI3MR_HDB_BUFSTATUS_UNKNOWN		0
#define MPI3MR_HDB_BUFSTATUS_NOT_ALLOCATED	1
#define MPI3MR_HDB_BUFSTATUS_POSTED_UNPAUSED	2
#define MPI3MR_HDB_BUFSTATUS_POSTED_PAUSED	3
#define MPI3MR_HDB_BUFSTATUS_RELEASED		4

#define MPI3MR_HDB_TRIGGER_TYPE_UNKNOWN		0
#define MPI3MR_HDB_TRIGGER_TYPE_DIAGFAULT	1
#define MPI3MR_HDB_TRIGGER_TYPE_ELEMENT		2
#define MPI3MR_HDB_TRIGGER_TYPE_MASTER		3


/* Supported BSG commands */
enum command {
	MPI3MR_DRV_CMD = 1,
	MPI3MR_MPT_CMD = 2,
};

/**
 * struct mpi3_driver_info_layout - Information about driver
 *
 * @information_length: Length of this structure in bytes
 * @driver_signature: Driver Vendor name
 * @os_name: Operating System Name
 * @driver_name: Driver name
 * @driver_version: Driver version
 * @driver_release_date: Driver release date
 * @driver_capabilities: Driver capabilities
 */
struct mpi3_driver_info_layout {
	__le32             information_length;
	u8                 driver_signature[12];
	u8                 os_name[16];
	u8                 os_version[12];
	u8                 driver_name[20];
	u8                 driver_version[32];
	u8                 driver_release_date[20];
	__le32             driver_capabilities;
};

/**
 * struct mpi3mr_bsg_in_adpinfo - Adapter information request
 * data returned by the driver.
 *
 * @adp_type: Adapter type
 * @rsvd1: Reserved
 * @pci_dev_id: PCI device ID of the adapter
 * @pci_dev_hw_rev: PCI revision of the adapter
 * @pci_subsys_dev_id: PCI subsystem device ID of the adapter
 * @pci_subsys_ven_id: PCI subsystem vendor ID of the adapter
 * @pci_dev: PCI device
 * @pci_func: PCI function
 * @pci_bus: PCI bus
 * @rsvd2: Reserved
 * @pci_seg_id: PCI segment ID
 * @app_intfc_ver: version of the application interface definition
 * @rsvd3: Reserved
 * @rsvd4: Reserved
 * @rsvd5: Reserved
 * @driver_info: Driver Information (Version/Name)
 */
struct mpi3mr_bsg_in_adpinfo {
	uint32_t adp_type;
	uint32_t rsvd1;
	uint32_t pci_dev_id;
	uint32_t pci_dev_hw_rev;
	uint32_t pci_subsys_dev_id;
	uint32_t pci_subsys_ven_id;
	uint32_t pci_dev:5;
	uint32_t pci_func:3;
	uint32_t pci_bus:8;
	uint16_t rsvd2;
	uint32_t pci_seg_id;
	uint32_t app_intfc_ver;
	uint8_t adp_state;
	uint8_t rsvd3;
	uint16_t rsvd4;
	uint32_t rsvd5[2];
	struct mpi3_driver_info_layout driver_info;
};

/**
 * struct mpi3mr_bsg_adp_reset - Adapter reset request
 * payload data to the driver.
 *
 * @reset_type: Reset type
 * @rsvd1: Reserved
 * @rsvd2: Reserved
 */
struct mpi3mr_bsg_adp_reset {
	uint8_t reset_type;
	uint8_t rsvd1;
	uint16_t rsvd2;
};

/**
 * struct mpi3mr_change_count - Topology change count
 * returned by the driver.
 *
 * @change_count: Topology change count
 * @rsvd: Reserved
 */
struct mpi3mr_change_count {
	uint16_t change_count;
	uint16_t rsvd;
};

/**
 * struct mpi3mr_device_map_info - Target device mapping
 * information
 *
 * @handle: Firmware device handle
 * @perst_id: Persistent ID assigned by the firmware
 * @target_id: Target ID assigned by the driver
 * @bus_id: Bus ID assigned by the driver
 * @rsvd1: Reserved
 * @rsvd2: Reserved
 */
struct mpi3mr_device_map_info {
	uint16_t handle;
	uint16_t perst_id;
	uint32_t target_id;
	uint8_t bus_id;
	uint8_t rsvd1;
	uint16_t rsvd2;
};

/**
 * struct mpi3mr_all_tgt_info - Target device mapping
 * information returned by the driver
 *
 * @num_devices: The number of devices in driver's inventory
 * @rsvd1: Reserved
 * @rsvd2: Reserved
 * @dmi: Variable length array of mapping information of targets
 */
struct mpi3mr_all_tgt_info {
	uint16_t num_devices;
	uint16_t rsvd1;
	uint32_t rsvd2;
	struct mpi3mr_device_map_info dmi[1];
};

/**
 * struct mpi3mr_logdata_enable - Number of log data
 * entries saved by the driver returned as payload data for
 * enable logdata BSG request by the driver.
 *
 * @max_entries: Number of log data entries cached by the driver
 * @rsvd: Reserved
 */
struct mpi3mr_logdata_enable {
	uint16_t max_entries;
	uint16_t rsvd;
};

/**
 * struct mpi3mr_bsg_out_pel_enable - PEL enable request payload
 * data to the driver.
 *
 * @pel_locale: PEL locale to the firmware
 * @pel_class: PEL class to the firmware
 * @rsvd: Reserved
 */
struct mpi3mr_bsg_out_pel_enable {
	uint16_t pel_locale;
	uint8_t pel_class;
	uint8_t rsvd;
};

/**
 * struct mpi3mr_logdata_entry - Log data entry cached by the
 * driver.
 *
 * @valid_entry: Is the entry valid
 * @rsvd1: Reserved
 * @rsvd2: Reserved
 * @data: Variable length Log entry data
 */
struct mpi3mr_logdata_entry {
	uint8_t valid_entry;
	uint8_t rsvd1;
	uint16_t rsvd2;
	uint8_t data[1]; /* Variable length Array */
};

/**
 * struct mpi3mr_bsg_in_log_data - Log data entries saved by
 * the driver returned as payload data for Get logdata request
 * by the driver.
 *
 * @entry: Variable length Log data entry array
 */
struct mpi3mr_bsg_in_log_data {
	struct mpi3mr_logdata_entry entry[1];
};

/**
 * struct mpi3mr_hdb_entry - host diag buffer entry.
 *
 * @buf_type: Buffer type
 * @status: Buffer status
 * @trigger_type: Trigger type
 * @rsvd1: Reserved
 * @size: Buffer size
 * @rsvd2: Reserved
 * @trigger_data: Trigger specific data
 * @rsvd3: Reserved
 * @rsvd4: Reserved
 */
struct mpi3mr_hdb_entry {
	uint8_t buf_type;
	uint8_t status;
	uint8_t trigger_type;
	uint8_t rsvd1;
	uint16_t size;
	uint16_t rsvd2;
	uint64_t trigger_data;
	uint32_t rsvd3;
	uint32_t rsvd4;
};


/**
 * struct mpi3mr_bsg_in_hdb_status - This structure contains
 * return data for the BSG request to retrieve the number of host
 * diagnostic buffers supported by the driver and their current
 * status and additional status specific data if any in forms of
 * multiple hdb entries.
 *
 * @num_hdb_types: Number of host diag buffer types supported
 * @rsvd1: Reserved
 * @rsvd2: Reserved
 * @rsvd3: Reserved
 * @entry: Variable length Diag buffer status entry array
 */
struct mpi3mr_bsg_in_hdb_status {
	uint8_t num_hdb_types;
	uint8_t rsvd1;
	uint16_t rsvd2;
	uint32_t rsvd3;
	struct mpi3mr_hdb_entry entry[1];
};

/**
 * struct mpi3mr_bsg_out_repost_hdb - Repost host diagnostic
 * buffer request payload data to the driver.
 *
 * @buf_type: Buffer type
 * @rsvd1: Reserved
 * @rsvd2: Reserved
 */
struct mpi3mr_bsg_out_repost_hdb {
	uint8_t buf_type;
	uint8_t rsvd1;
	uint16_t rsvd2;
};

/**
 * struct mpi3mr_bsg_out_upload_hdb - Upload host diagnostic
 * buffer request payload data to the driver.
 *
 * @buf_type: Buffer type
 * @rsvd1: Reserved
 * @rsvd2: Reserved
 * @start_offset: Start offset of the buffer from where to copy
 * @length: Length of the buffer to copy
 */
struct mpi3mr_bsg_out_upload_hdb {
	uint8_t buf_type;
	uint8_t rsvd1;
	uint16_t rsvd2;
	uint32_t start_offset;
	uint32_t length;
};

/**
 * struct mpi3mr_bsg_out_refresh_hdb_triggers - Refresh host
 * diagnostic buffer triggers request payload data to the driver.
 *
 * @page_type: Page type
 * @rsvd1: Reserved
 * @rsvd2: Reserved
 */
struct mpi3mr_bsg_out_refresh_hdb_triggers {
	uint8_t page_type;
	uint8_t rsvd1;
	uint16_t rsvd2;
};
/**
 * struct mpi3mr_bsg_drv_cmd -  Generic bsg data
 * structure for all driver specific requests.
 *
 * @mrioc_id: Controller ID
 * @opcode: Driver specific opcode
 * @rsvd1: Reserved
 * @rsvd2: Reserved
 */
struct mpi3mr_bsg_drv_cmd {
	uint8_t mrioc_id;
	uint8_t opcode;
	uint16_t rsvd1;
	uint32_t rsvd2[4];
};
/**
 * struct mpi3mr_bsg_in_reply_buf - MPI reply buffer returned
 * for MPI Passthrough request .
 *
 * @mpi_reply_type: Type of MPI reply
 * @rsvd1: Reserved
 * @rsvd2: Reserved
 * @reply_buf: Variable Length buffer based on mpirep type
 */
struct mpi3mr_bsg_in_reply_buf {
	uint8_t mpi_reply_type;
	uint8_t rsvd1;
	uint16_t rsvd2;
	uint8_t reply_buf[1];
};

/**
 * struct mpi3mr_buf_entry - User buffer descriptor for MPI
 * Passthrough requests.
 *
 * @buf_type: Buffer type
 * @rsvd1: Reserved
 * @rsvd2: Reserved
 * @buf_len: Buffer length
 */
struct mpi3mr_buf_entry {
	uint8_t buf_type;
	uint8_t rsvd1;
	uint16_t rsvd2;
	uint32_t buf_len;
};
/**
 * struct mpi3mr_bsg_buf_entry_list - list of user buffer
 * descriptor for MPI Passthrough requests.
 *
 * @num_of_entries: Number of buffer descriptors
 * @rsvd1: Reserved
 * @rsvd2: Reserved
 * @rsvd3: Reserved
 * @buf_entry: Variable length array of buffer descriptors
 */
struct mpi3mr_buf_entry_list {
	uint8_t num_of_entries;
	uint8_t rsvd1;
	uint16_t rsvd2;
	uint32_t rsvd3;
	struct mpi3mr_buf_entry buf_entry[1];
};
/**
 * struct mpi3mr_bsg_mptcmd -  Generic bsg data
 * structure for all MPI Passthrough requests.
 *
 * @mrioc_id: Controller ID
 * @rsvd1: Reserved
 * @timeout: MPI request timeout
 * @buf_entry_list: Buffer descriptor list
 */
struct mpi3mr_bsg_mptcmd {
	uint8_t mrioc_id;
	uint8_t rsvd1;
	uint16_t timeout;
	uint32_t rsvd2;
	struct mpi3mr_buf_entry_list buf_entry_list;
};

/**
 * struct mpi3mr_bsg_packet -  Generic bsg data
 * structure for all supported requests .
 *
 * @cmd_type: represents drvrcmd or mptcmd
 * @rsvd1: Reserved
 * @rsvd2: Reserved
 * @drvrcmd: driver request structure
 * @mptcmd: mpt request structure
 */
struct mpi3mr_bsg_packet {
	uint8_t cmd_type;
	uint8_t rsvd1;
	uint16_t rsvd2;
	uint32_t rsvd3;
	union {
		struct mpi3mr_bsg_drv_cmd drvrcmd;
		struct mpi3mr_bsg_mptcmd mptcmd;
	} cmd;
};


/* MPI3: NVMe Encasulation related definitions */
#ifndef MPI3_NVME_ENCAP_CMD_MAX
#define MPI3_NVME_ENCAP_CMD_MAX               (1)
#endif

struct mpi3_nvme_encapsulated_request {
	__le16                     host_tag;
	u8                         ioc_use_only02;
	u8                         function;
	__le16                     ioc_use_only04;
	u8                         ioc_use_only06;
	u8                         msg_flags;
	__le16                     change_count;
	__le16                     dev_handle;
	__le16                     encapsulated_command_length;
	__le16                     flags;
	__le32                     data_length;
	__le32                     reserved14[3];
	__le32                     command[MPI3_NVME_ENCAP_CMD_MAX];
};

struct mpi3_nvme_encapsulated_error_reply {
	__le16                     host_tag;
	u8                         ioc_use_only02;
	u8                         function;
	__le16                     ioc_use_only04;
	u8                         ioc_use_only06;
	u8                         msg_flags;
	__le16                     ioc_use_only08;
	__le16                     ioc_status;
	__le32                     ioc_log_info;
	__le32                     nvme_completion_entry[4];
};

/* MPI3: task management related definitions */
struct mpi3_scsi_task_mgmt_request {
	__le16                     host_tag;
	u8                         ioc_use_only02;
	u8                         function;
	__le16                     ioc_use_only04;
	u8                         ioc_use_only06;
	u8                         msg_flags;
	__le16                     change_count;
	__le16                     dev_handle;
	__le16                     task_host_tag;
	u8                         task_type;
	u8                         reserved0f;
	__le16                     task_request_queue_id;
	__le16                     reserved12;
	__le32                     reserved14;
	u8                         lun[8];
};

#define MPI3_SCSITASKMGMT_MSGFLAGS_DO_NOT_SEND_TASK_IU      (0x08)
#define MPI3_SCSITASKMGMT_TASKTYPE_ABORT_TASK               (0x01)
#define MPI3_SCSITASKMGMT_TASKTYPE_ABORT_TASK_SET           (0x02)
#define MPI3_SCSITASKMGMT_TASKTYPE_TARGET_RESET             (0x03)
#define MPI3_SCSITASKMGMT_TASKTYPE_LOGICAL_UNIT_RESET       (0x05)
#define MPI3_SCSITASKMGMT_TASKTYPE_CLEAR_TASK_SET           (0x06)
#define MPI3_SCSITASKMGMT_TASKTYPE_QUERY_TASK               (0x07)
#define MPI3_SCSITASKMGMT_TASKTYPE_CLEAR_ACA                (0x08)
#define MPI3_SCSITASKMGMT_TASKTYPE_QUERY_TASK_SET           (0x09)
#define MPI3_SCSITASKMGMT_TASKTYPE_QUERY_ASYNC_EVENT        (0x0a)
#define MPI3_SCSITASKMGMT_TASKTYPE_I_T_NEXUS_RESET          (0x0b)
struct mpi3_scsi_task_mgmt_reply {
	__le16                     host_tag;
	u8                         ioc_use_only02;
	u8                         function;
	__le16                     ioc_use_only04;
	u8                         ioc_use_only06;
	u8                         msg_flags;
	__le16                     ioc_use_only08;
	__le16                     ioc_status;
	__le32                     ioc_log_info;
	__le32                     termination_count;
	__le32                     response_data;
	__le32                     reserved18;
};

#define MPI3_SCSITASKMGMT_RSPCODE_TM_COMPLETE                (0x00)
#define MPI3_SCSITASKMGMT_RSPCODE_INVALID_FRAME              (0x02)
#define MPI3_SCSITASKMGMT_RSPCODE_TM_FUNCTION_NOT_SUPPORTED  (0x04)
#define MPI3_SCSITASKMGMT_RSPCODE_TM_FAILED                  (0x05)
#define MPI3_SCSITASKMGMT_RSPCODE_TM_SUCCEEDED               (0x08)
#define MPI3_SCSITASKMGMT_RSPCODE_TM_INVALID_LUN             (0x09)
#define MPI3_SCSITASKMGMT_RSPCODE_TM_OVERLAPPED_TAG          (0x0a)
#define MPI3_SCSITASKMGMT_RSPCODE_IO_QUEUED_ON_IOC           (0x80)
#define MPI3_SCSITASKMGMT_RSPCODE_TM_NVME_DENIED             (0x81)

/* MPI3: PEL related definitions */
#define MPI3_PEL_LOCALE_FLAGS_NON_BLOCKING_BOOT_EVENT   (0x0200)
#define MPI3_PEL_LOCALE_FLAGS_BLOCKING_BOOT_EVENT       (0x0100)
#define MPI3_PEL_LOCALE_FLAGS_PCIE                      (0x0080)
#define MPI3_PEL_LOCALE_FLAGS_CONFIGURATION             (0x0040)
#define MPI3_PEL_LOCALE_FLAGS_CONTROLER                 (0x0020)
#define MPI3_PEL_LOCALE_FLAGS_SAS                       (0x0010)
#define MPI3_PEL_LOCALE_FLAGS_EPACK                     (0x0008)
#define MPI3_PEL_LOCALE_FLAGS_ENCLOSURE                 (0x0004)
#define MPI3_PEL_LOCALE_FLAGS_PD                        (0x0002)
#define MPI3_PEL_LOCALE_FLAGS_VD                        (0x0001)
#define MPI3_PEL_CLASS_DEBUG                            (0x00)
#define MPI3_PEL_CLASS_PROGRESS                         (0x01)
#define MPI3_PEL_CLASS_INFORMATIONAL                    (0x02)
#define MPI3_PEL_CLASS_WARNING                          (0x03)
#define MPI3_PEL_CLASS_CRITICAL                         (0x04)
#define MPI3_PEL_CLASS_FATAL                            (0x05)
#define MPI3_PEL_CLASS_FAULT                            (0x06)

/* MPI3: Function definitions */
#define MPI3_BSG_FUNCTION_MGMT_PASSTHROUGH              (0x0a)
#define MPI3_BSG_FUNCTION_SCSI_IO                       (0x20)
#define MPI3_BSG_FUNCTION_SCSI_TASK_MGMT                (0x21)
#define MPI3_BSG_FUNCTION_SMP_PASSTHROUGH               (0x22)
#define MPI3_BSG_FUNCTION_NVME_ENCAPSULATED             (0x24)

#endif
