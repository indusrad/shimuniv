// SPDX-License-Identifier: GPL-2.0-only

/*
 *  Copyright (c) 2016 Alexander Graf
 *  Copyright (c) 2023 ARM Ltd.
 */

#include "efi_boot_services.h"
#include "efi_runtime.h"
#include "efi_image_loader.h"
#include "efi_conformance.h"
#include "efi_rng.h"
#include "efi_root_node.h"
#include "efi_fdt.h"

extern char _payload;
extern char _epayload;

// GUID of the SMBIOS table
const efi_guid_t smbios_guid = SMBIOS_TABLE_GUID;
// GUID of the SMBIOS3 table
const efi_guid_t smbios3_guid = SMBIOS3_TABLE_GUID;

efi_status_t convert_coreboot_mmap_to_uefi(void)
{
	// convert coreboot table memory map to UEFI memory map
	// iterate from end to start, since efi_add_memory_map inserts memory map at the beginning (head).
	// Therefore we will put the memory map in ascending order into the list without having to sort it.
	for (int i = lib_sysinfo.n_memranges-1; i >= 0; i--) {
		struct memrange *mr = &lib_sysinfo.memrange[i];
		enum efi_memory_type efi_mtype;
		switch (mr->type) {
		case CB_MEM_RAM:
			efi_mtype = EFI_CONVENTIONAL_MEMORY;
			break;
		case CB_MEM_RESERVED: //TODO check what coreboot marks as reserved
			//efi_mtype = EFI_RUNTIME_SERVICES_DATA;
			efi_mtype = EFI_UNUSABLE_MEMORY;
			break;
		case CB_MEM_ACPI:
			efi_mtype = EFI_ACPI_RECLAIM_MEMORY;
			break;
		case CB_MEM_NVS:
			efi_mtype = EFI_ACPI_MEMORY_NVS;
			break;
		case CB_MEM_UNUSABLE:
			efi_mtype = EFI_UNUSABLE_MEMORY;
			break;
		case CB_MEM_VENDOR_RSVD:
		case CB_MEM_TABLE:
			efi_mtype = EFI_RUNTIME_SERVICES_DATA;
			break;
		}
		efi_status_t ret = efi_add_memory_map(mr->base, mr->size, efi_mtype);
		if (ret != EFI_SUCCESS) {
			return ret;
		}
	}
	return EFI_SUCCESS;
}

efi_status_t convert_coreboot_acpi_to_uefi(void)
{
	efi_status_t ret;

	const efi_guid_t acpi_guid = EFI_ACPI_TABLE_GUID;
	if (!lib_sysinfo.acpi_rsdp) {
		return EFI_NOT_FOUND;
	}
	ret = efi_install_configuration_table(&acpi_guid, (void *)lib_sysinfo.acpi_rsdp);
	if (ret != EFI_SUCCESS) {
		return ret;
	}
	return EFI_SUCCESS;
}

efi_status_t convert_coreboot_smbios_to_uefi(void)
{
	efi_status_t ret;

	if (!lib_sysinfo.smbios) {
		return EFI_NOT_FOUND;
	}

	// coreboot usually supplies both SMBIOS 2.1 and SMBIOS 3 entry point (like suggested by spec)
	if (!memcmp((void *)lib_sysinfo.smbios, "_SM3_", 5)) {
		const efi_guid_t smbios3_guid = SMBIOS3_TABLE_GUID;
		uintptr_t smbios3 = lib_sysinfo.smbios;
		ret = efi_install_configuration_table(&smbios3_guid, (void *)smbios3);
		if (ret != EFI_SUCCESS) {
			return ret;
		}
	} else if (!memcmp((void *)lib_sysinfo.smbios, "_SM_", 4)) {
		const efi_guid_t smbios_guid = SMBIOS_TABLE_GUID;
		uintptr_t smbios = lib_sysinfo.smbios;
		ret = efi_install_configuration_table(&smbios_guid, (void *)smbios);
		if (ret != EFI_SUCCESS) {
			return ret;
		}
	} else {
		return EFI_NOT_FOUND;
	}
	return EFI_SUCCESS;
}

void convert_coreboot_tables_to_uefi(void)
{
	if (convert_coreboot_acpi_to_uefi() != EFI_SUCCESS) {
		printf("WARN: no ACPI supplied by coreboot\n");
	}

	if (convert_coreboot_smbios_to_uefi() != EFI_SUCCESS) {
		printf("WARN: no SMBIOS supplied by coreboot\n");
	}
}

/**
 * efi_init_obj_list() - Initialize and populate EFI object list
 *
 * Return:	status code
 */
efi_status_t efi_init_obj_list(void)
{
	efi_status_t ret;

	convert_coreboot_mmap_to_uefi();
	efi_memory_init();

	// Initialize root node
	ret = efi_root_node_register();
	if (ret != EFI_SUCCESS)
		goto out;

	// Initialize system table
	ret = efi_initialize_system_table();
	if (ret != EFI_SUCCESS)
		goto out;

	convert_coreboot_tables_to_uefi();

	if (CONFIG(LEANEFI_FDT))
		efi_fdt_register();

	if (CONFIG(LEANEFI_ECPT)) {
		ret = efi_ecpt_register();
		if (ret != EFI_SUCCESS)
			goto out;
	}

	// Install EFI_RNG_PROTOCOL
	ret = efi_rng_register(efi_root);
	if (ret != EFI_SUCCESS)
		goto out;

	// Indicate supported runtime services
	ret = efi_init_runtime_supported();
	if (ret != EFI_SUCCESS)
		goto out;

out:
	return ret;
}

int main(int argc, char **argv)
{
	(void)argc;
	(void)argv;

	// init EFI drivers
	efi_init_obj_list();

	if (CONFIG(LEANEFI_PAYLOAD)) {
		efi_run_image((void *)&_payload, (size_t)((&_epayload) - (&_payload)));
	} else {
		printf("ERROR: No payload selected (CONFIG_LEANEFI_PAYLOAD)\n");
	}

	return 0;
}
