// SPDX-License-Identifier: GPL-2.0+

/*
 * Copyright (C) 1999 VA Linux Systems
 * Copyright (C) 1999 Walt Drummond <drummond@valinux.com>
 * Copyright (C) 1999, 2002-2003 Hewlett-Packard Co.
 * David Mosberger-Tang <davidm@hpl.hp.com>
 * Stephane Eranian <eranian@hpl.hp.com>
 *  Copyright (c) 2023 ARM Ltd.
 */

#ifndef EFI_TABLE_H
#define EFI_TABLE_H

#include "efi_defines.h"
#include "efi_guid.h"
#include "efi_object.h"
#include "efi_memory.h"
#include "efi_protocol.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

// Generic EFI table header
struct efi_table_hdr {
	u64 signature;
	u32 revision;
	u32 headersize;
	u32 crc32;
	u32 reserved;
};

/*
 * EFI Configuration Table
 * This table contains a set of GUID/pointer pairs.
 * The EFI Configuration Table may contain at most one instance of each table type.
 *
 * @guid:  GUID that uniquely identifies the system configuration table
 * @table: A pointer to the table associated with guid
 */
struct efi_configuration_table {
	efi_guid_t guid;
	void *table;
} __packed;

/*
 * EFI System Table
 * EFI System Table contains pointers to the runtime and boot services tables.
 *
 * @hdr:            The table header for the EFI System Table
 * @fw_vendor:      A pointer to a null terminated string that identifies the vendor that
 *                  produces the system firmware
 * @fw_revision:    The revision of the system firmware
 * @con_in_handle:  The handle for the active console input device
 * @con_in:         A pointer to the EFI_SIMPLE_TEXT_INPUT_PROTOCOL interface that is
 *                  associated with con_in_handle
 * @con_out_handle: The handle for the active console output device
 * @con_out:        A pointer to the EFI_SIMPLE_TEXT_OUTPUT_PROTOCOL interface that is
 *                  associated with con_out_handle
 * @stderr_handle:  The handle for the active standard error console device
 * @std_err:        A pointer to the EFI_SIMPLE_TEXT_OUTPUT_PROTOCOL interface that is
 *                  associated with stderr_handle
 * @runtime:        A pointer to the EFI Runtime Services Table
 * @boottime:       A pointer to the EFI Boot Services Table
 * @nr_tables:      The number of system configuration tables
 * @tables:         A pointer to the system configuration tables
 */
struct efi_system_table {
	struct efi_table_hdr hdr;
	u16 *fw_vendor;   // physical addr of wchar_t vendor string
	u32 fw_revision;
	efi_handle_t con_in_handle;
	struct efi_simple_text_input_protocol *con_in;
	efi_handle_t con_out_handle;
	struct efi_simple_text_output_protocol *con_out;
	efi_handle_t stderr_handle;
	struct efi_simple_text_output_protocol *std_err;
	struct efi_runtime_services *runtime;
	struct efi_boot_services *boottime;
	size_t nr_tables;
	struct efi_configuration_table *tables;
};

struct efi_conformance_profiles_table {
	u16 version;
	u16 number_of_profiles;
	efi_guid_t conformance_profiles[];
} __packed;

struct efi_rt_properties_table {
	u16 version;
	u16 length;
	u32 runtime_services_supported;
};

// EFI Boot Services table
struct efi_boot_services {
	struct efi_table_hdr hdr;

	efi_status_t (EFIAPI *raise_tpl)(size_t new_tpl);
	void (EFIAPI *restore_tpl)(size_t old_tpl);

	efi_status_t (EFIAPI *allocate_pages)(
		int type,
		int memory_type,
		size_t pages,
		efi_physical_addr_t *memory);
	efi_status_t (EFIAPI *free_pages)(efi_physical_addr_t, size_t);
	efi_status_t (EFIAPI *get_memory_map)(
		size_t *memory_map_size,
		struct efi_mem_desc *desc,
		size_t *key,
		size_t *desc_size,
		u32 *desc_version);
	efi_status_t (EFIAPI *allocate_pool)(int, size_t, void **);
	efi_status_t (EFIAPI *free_pool)(void *);

	efi_status_t (EFIAPI *create_event)(uint32_t type,
		size_t notify_tpl,
		void (EFIAPI *notify_function) (
			void *event,
			void *context),
		void *notify_context, void **event);
	efi_status_t (EFIAPI *set_timer)(
		void *event,
		enum efi_timer_delay type,
		uint64_t trigger_time);
	efi_status_t (EFIAPI *wait_for_event)(
		size_t number_of_events,
		void **event,
		size_t *index);
	efi_status_t (EFIAPI *signal_event)(void *event);
	efi_status_t (EFIAPI *close_event)(void *event);
	efi_status_t (EFIAPI *check_event)(void *event);

	efi_status_t (EFIAPI *install_protocol_interface)(
		efi_handle_t *handle, const efi_guid_t *protocol,
		int protocol_interface_type, void *protocol_interface);
	efi_status_t (EFIAPI *reinstall_protocol_interface)(
		efi_handle_t handle, const efi_guid_t *protocol,
		void *old_interface, void *new_interface);
	efi_status_t (EFIAPI *uninstall_protocol_interface)(
		efi_handle_t handle, const efi_guid_t *protocol,
		void *protocol_interface);
	efi_status_t (EFIAPI *handle_protocol)(
		efi_handle_t handle, const efi_guid_t *protocol,
		void **protocol_interface);
	void *reserved;
	efi_status_t (EFIAPI *register_protocol_notify)(
		const efi_guid_t *protocol,
		void *event,
		void **registration);
	efi_status_t (EFIAPI *locate_handle)(
		enum efi_locate_search_type search_type,
		const efi_guid_t *protocol, void *search_key,
		size_t *buffer_size, efi_handle_t *buffer);
	efi_status_t (EFIAPI *locate_device_path)(
		const efi_guid_t *protocol,
		void **device_path,
		efi_handle_t *device);
	efi_status_t (EFIAPI *install_configuration_table)(const efi_guid_t *guid, void *table);

	efi_status_t (EFIAPI *load_image)(
		bool boot_policiy,
		efi_handle_t parent_image,
		void *file_path, void *source_buffer,
		size_t source_size, efi_handle_t *image);
	efi_status_t (EFIAPI *start_image)(
		efi_handle_t handle,
		size_t *exitdata_size,
		u16 **exitdata);
	efi_status_t (EFIAPI *exit)(
		efi_handle_t handle,
		efi_status_t exit_status,
		size_t exitdata_size, u16 *exitdata);
	efi_status_t (EFIAPI *unload_image)(efi_handle_t image_handle);
	efi_status_t (EFIAPI *exit_boot_services)(efi_handle_t image_handle, size_t map_key);

	efi_status_t (EFIAPI *get_next_monotonic_count)(u64 *count);
	efi_status_t (EFIAPI *stall)(unsigned long usecs);
	efi_status_t (EFIAPI *set_watchdog_timer)(
		unsigned long timeout,
		uint64_t watchdog_code, unsigned long data_size,
		uint16_t *watchdog_data);
	efi_status_t(EFIAPI *connect_controller)(
		efi_handle_t controller_handle,
		efi_handle_t *driver_image_handle,
		void *remaining_device_path,
		bool recursive);
	efi_status_t (EFIAPI *disconnect_controller)(
		efi_handle_t controller_handle,
		efi_handle_t driver_image_handle,
		efi_handle_t child_handle);
	efi_status_t (EFIAPI *open_protocol)(
		efi_handle_t handle,
		const efi_guid_t *protocol, void **interface,
		efi_handle_t agent_handle,
		efi_handle_t controller_handle, u32 attributes);
	efi_status_t (EFIAPI *close_protocol)(
		efi_handle_t handle, const efi_guid_t *protocol,
		efi_handle_t agent_handle,
		efi_handle_t controller_handle);
	efi_status_t (EFIAPI *open_protocol_information)(
		efi_handle_t handle,
		const efi_guid_t *protocol,
		struct efi_open_protocol_info_entry **entry_buffer,
		size_t *entry_count);
	efi_status_t (EFIAPI *protocols_per_handle)(
		efi_handle_t handle,
		efi_guid_t ***protocol_buffer,
		size_t *protocols_buffer_count);
	efi_status_t (EFIAPI *locate_handle_buffer) (
		enum efi_locate_search_type search_type,
		const efi_guid_t *protocol,
		void *search_key,
		size_t *no_handles, efi_handle_t **buffer);
	efi_status_t (EFIAPI *locate_protocol)(
		const efi_guid_t *protocol,
		void *registration,
		void **protocol_interface);
	efi_status_t (EFIAPI *install_multiple_protocol_interfaces)(efi_handle_t *handle, ...);
	efi_status_t (EFIAPI *uninstall_multiple_protocol_interfaces)(efi_handle_t handle, ...);
	efi_status_t (EFIAPI *calculate_crc32)(const void *data, size_t data_size, u32 *crc32);
	void (EFIAPI *copy_mem)(void *destination, const void *source, size_t length);
	void (EFIAPI *set_mem)(void *buffer, size_t size, uint8_t value);
	efi_status_t (EFIAPI *create_event_ex)(
		uint32_t type,
		size_t notify_tpl,
		void (EFIAPI *notify_function) (
			void *event,
			void *context),
		void *notify_context,
		efi_guid_t *event_group,
		void **event);
};

void efi_remove_configuration_table(int i);
efi_status_t efi_install_configuration_table(const efi_guid_t *guid, void *table);
efi_status_t EFIAPI efi_install_configuration_table_ext(const efi_guid_t *guid, void *table);
efi_status_t efi_initialize_system_table(void);
void efi_update_table_header_crc32(struct efi_table_hdr *table);

#endif
