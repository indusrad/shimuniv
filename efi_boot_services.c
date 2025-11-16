// SPDX-License-Identifier: GPL-2.0+
/*
 * EFI application boot time services
 *
 * Copyright (c) 2016 Alexander Graf
 * Copyright (C) 2023 ARM Ltd.
 *
 * This file is derived from the U-Boot project
 */

#include "efi_defines.h"
#include "efi_guid.h"
#include "efi_console.h"
#include "efi_runtime.h"
#include "efi_table.h"
#include "efi_runtime_services.h"

/**
 * efi_install_configuration_table_ext() - Adds, updates, or removes a configuration table.
 * @guid:  GUID of the installed table
 * @table: table to be installed
 *
 * This function implements the InstallConfigurationTable service.
 * See the Unified Extensible Firmware Interface (UEFI) specification for details.
 *
 * Return: status code
 */
efi_status_t EFIAPI efi_install_configuration_table_ext(const efi_guid_t *guid, void *table)
{
	return efi_install_configuration_table(guid, table);
}

/**
 * efi_exit_boot_services() - stop all boot services
 * @image_handle: handle of the loaded image
 * @map_key:      key of the memory map
 *
 * This function implements the ExitBootServices service.
 *
 * See the Unified Extensible Firmware Interface (UEFI) specification
 * for details.
 *
 * All timer events are disabled. For exit boot services events the
 * notification function is called. The boot services are disabled in the
 * system table.
 *
 * Return: status code
 */
efi_status_t EFIAPI efi_exit_boot_services(efi_handle_t image_handle, size_t map_key)
{
	(void)image_handle;
	efi_status_t ret = EFI_SUCCESS;

	// Check that the caller has read the current memory map
	if (map_key != efi_memory_map_key) {
		ret = EFI_INVALID_PARAMETER;
		goto out;
	}

	// Check if ExitBootServices has already been called
	if (!systab.boottime)
		goto out;

	// Disable boot time services
	systab.con_in_handle = NULL;
	systab.con_in = NULL;
	systab.con_out_handle = NULL;
	systab.con_out = NULL;
	systab.stderr_handle = NULL;
	systab.std_err = NULL;
	systab.boottime = NULL;

	// Recalculate CRC32
	efi_update_table_header_crc32(&systab.hdr);

out:
	return ret;
}

// This function is used for all unimplemented boot services
efi_status_t EFIAPI efi_unimplemented(void)
{
	printf("Called unimplemented service\n");
	return EFI_UNSUPPORTED;
}

/*
 * For some reason some functions are required (by the UEFI spec) to return
 * EFI_DEVICE_ERROR instead of EFI_UNSUPPORTED, if they are not implemented
 */
efi_status_t __efi_runtime EFIAPI efi_device_error(void)
{
	printf("Called unimplemented service\n");
	return EFI_DEVICE_ERROR;
}

struct efi_boot_services efi_boot_services = {
	.hdr = {
		.signature = EFI_BOOT_SERVICES_SIGNATURE,
		.revision = EFI_SPECIFICATION_VERSION,
		.headersize = sizeof(struct efi_boot_services),
	},

	/* From here on are the boot services that are not used by Linux (neither optional nor required) */
	/*************************************************************************************************/

	.reserved = NULL,

	// image related boot services
	.load_image =   (void *)efi_unimplemented,
	.start_image =  (void *)efi_unimplemented,
	.unload_image = (void *)efi_unimplemented,

	// Event and Timer related boot services
	.raise_tpl =                 (void *)efi_unimplemented,
	.restore_tpl =               (void *)efi_unimplemented,
	.create_event =              (void *)efi_unimplemented,
	.set_timer =                 (void *)efi_unimplemented,
	.wait_for_event =            (void *)efi_unimplemented,
	.signal_event =              (void *)efi_unimplemented,
	.close_event =               (void *)efi_unimplemented,
	.check_event =               (void *)efi_unimplemented,
	.create_event_ex =           (void *)efi_unimplemented,
	.set_watchdog_timer =        (void *)efi_unimplemented,
	.register_protocol_notify =  (void *)efi_unimplemented,

	// protocol related boot services
	.open_protocol =                (void *)efi_unimplemented,
	.close_protocol =               (void *)efi_unimplemented,
	.install_protocol_interface =   (void *)efi_unimplemented,
	.reinstall_protocol_interface = (void *)efi_unimplemented,
	.uninstall_protocol_interface = (void *)efi_unimplemented,
	.open_protocol_information =    (void *)efi_unimplemented,
	.protocols_per_handle =         (void *)efi_unimplemented,
	.locate_handle_buffer =         (void *)efi_unimplemented,
	.connect_controller =           (void *)efi_unimplemented,

	// miscellaneous boot services
	.get_next_monotonic_count = (void *)efi_unimplemented,
	.stall =                    (void *)efi_unimplemented,
	.calculate_crc32 =          (void *)efi_unimplemented,

	/* From here on are the boot services that may be used by Linux but are not required */
	/*************************************************************************************/

	// used by Linux to detach PCI controller before exiting boot services.
	// It is an optional Linux Kconfig option that is usually disabled.
	.disconnect_controller = (void *)efi_unimplemented,

	// required by the Linux zboot on arm platforms to add a LOAD_FILE2_PROTOCOL
	.install_multiple_protocol_interfaces =   (void *)efi_unimplemented, //efi_install_multiple_protocol_interfaces_ext,
	.uninstall_multiple_protocol_interfaces = (void *)efi_unimplemented, //efi_uninstall_multiple_protocol_interfaces_ext,

	// used by Linux to get protocol interface (functions):
	// of the EFI_RNG_PROTOCOL protocol: used by Linux to:
	//     - relocate itself to a random base address as part of KASLR
	//     - relocate the efi runtime services to a random base
	// of the EFI_RISCV_BOOT_PROTOCOL protocol.
	// of the EFI_TCG2_PROTOCOL protocol. TODO use/extend libpayload TPM support
	// of the APPLE_PROPERTIES_PROTOCOL protocol
	.locate_protocol = efi_locate_protocol,

	// used by Linux to get all handles implementing the EFI_PCI_IO_PROTOCOL as well as the
	// EFI_GRAPHICS_OUTPUT_PROTOCOL (or EFI_UGA_PROTOCOL if that doesn' work)
	.locate_handle = (void *)efi_unimplemented, //efi_locate_handle_ext,

	// used by Linux to optionally get the initrd from UEFI. That is for example used by
	// systemd-boot to supply the initrd to the linux kernel by registering an
	// FILE2_LOAD protocol interface with a device path.
	// currently this raises an error in the Linux EFI stub (it still boots though) because Linux only accepts EFI_NOT_FOUND as failure return code in order to not recognize this as failure... So maybe just do the same thing as efi_unimplmented but with efi_not_found ??? TODO
	.locate_device_path = (void *)efi_unimplemented, //efi_locate_device_path,

	// used by Linux to return to UEFI firmware in case of a failure
	.exit = (void *)efi_unimplemented, //efi_exit TODO

	/* From here on are the boot services that are required to boot Linux aarch64 */
	/******************************************************************************/

	// memory allocation related boot services
	.allocate_pages = efi_allocate_pages_ext,
	.free_pages =     efi_free_pages_ext,
	.allocate_pool =  efi_allocate_pool_ext,
	.free_pool =      efi_free_pool_ext,
	.copy_mem =       efi_copy_mem,
	.set_mem =        efi_set_mem,

	// miscellaneous boot services
	.get_memory_map =              efi_get_memory_map_ext,
	.handle_protocol =             efi_handle_protocol,
	.install_configuration_table = efi_install_configuration_table_ext,
	.exit_boot_services =          efi_exit_boot_services,
};
