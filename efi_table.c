// SPDX-License-Identifier: GPL-2.0+

/*
 *  Copyright (c) 2016 Alexander Graf
 *  Copyright (c) 2023 ARM Ltd.
 *
 * This file is derived from the U-Boot project
 */

#include "efi_table.h"
#include "efi_defines.h"
#include "efi_guid.h"
#include "efi_memory.h"
#include "efi_boot_services.h"
#include "efi_runtime.h"
#include "efi_runtime_services.h"
#include "crc.h"
#include "efi_console.h"

#include <stdint.h>
#include <libpayload.h>

extern struct efi_system_table systab;
extern efi_handle_t efi_root;

struct efi_simple_text_output_protocol efi_con_out = {
	.reset =               (void *)efi_device_error,
	.output_string =       efi_cout_output_string,
	.test_string =         (void *)efi_unimplemented,
	.query_mode =          (void *)efi_unimplemented,
	.set_mode =            (void *)efi_unimplemented,
	.set_attribute =       (void *)efi_device_error,
	.clear_screen =        (void *)efi_unimplemented,
	.set_cursor_position = (void *)efi_unimplemented,
	.enable_cursor =       (void *)efi_unimplemented,
	.mode =                NULL,
};

// removes configuration table at index i from the system configuration table
void efi_remove_configuration_table(int i)
{
	struct efi_configuration_table *this = &systab.tables[i];
	struct efi_configuration_table *next = &systab.tables[i + 1];
	struct efi_configuration_table *end = &systab.tables[systab.nr_tables];

	memmove(this, next, (unsigned long)end - (unsigned long)next);
	systab.nr_tables--;
}

/*
 * adds, updates, or removes a configuration table
 * This function is used for internal calls. For the API implementation of the
 * InstallConfigurationTable service see efi_install_configuration_table_ext.
 *
 * @guid:  GUID of the installed table
 * @table: table to be installed
 *
 * Return: status code
 */
efi_status_t efi_install_configuration_table(const efi_guid_t *guid,
					     void *table)
{
	size_t i;

	if (!guid)
		return EFI_INVALID_PARAMETER;

	// Check for GUID override
	for (i = 0; i < systab.nr_tables; i++) {
		if (!guidcmp(guid, &systab.tables[i].guid)) {
			if (table)
				systab.tables[i].table = table;
			else
				efi_remove_configuration_table(i);
			goto out;
		}
	}

	if (!table)
		return EFI_NOT_FOUND;

	// No override, check for overflow
	if (i >= EFI_MAX_CONFIGURATION_TABLES)
		return EFI_OUT_OF_RESOURCES;

	// Add a new entry
	guidcpy(&systab.tables[i].guid, guid);
	systab.tables[i].table = table;
	systab.nr_tables = i + 1;

out:
	// systab.nr_tables may have changed. So we need to update the CRC32
	efi_update_table_header_crc32(&systab.hdr);

	return EFI_SUCCESS;
}

// Update crc32 in table header
void __efi_runtime efi_update_table_header_crc32(struct efi_table_hdr *table)
{
	table->crc32 = 0;
	table->crc32 = crc32(0, (const unsigned char *)table, table->headersize);
}

// Initialize system table
efi_status_t efi_initialize_system_table(void)
{
	efi_status_t ret;

	// Allocate configuration table array
	ret = efi_allocate_pool(EFI_RUNTIME_SERVICES_DATA,
				EFI_MAX_CONFIGURATION_TABLES *
				sizeof(struct efi_configuration_table),
				(void **)&systab.tables);

	/*
	 * These entries will be set to NULL in ExitBootServices(). To avoid
	 * relocation in SetVirtualAddressMap(), set them dynamically.
	 */
	systab.con_in_handle = NULL;
	systab.con_in = NULL;
	systab.con_out_handle = efi_root;
	systab.con_out = &efi_con_out;
	systab.stderr_handle = efi_root;
	systab.std_err = &efi_con_out;
	systab.boottime = &efi_boot_services;

	// Set CRC32 field in table headers
	efi_update_table_header_crc32(&systab.hdr);
	efi_update_table_header_crc32(&efi_runtime_services.hdr);
	efi_update_table_header_crc32(&efi_boot_services.hdr);

	return ret;
}
