// SPDX-License-Identifier: GPL-2.0-only
/*
 *  EFI conformance profile table
 *
 *  Copyright (C) 2023 Arm Ltd.
 *
 * This file is derived from the U-Boot project
 */

#include "efi_conformance.h"
#include "efi_table.h"
#include "efi_memory.h"
#include <malloc.h>

static const efi_guid_t efi_ecpt_guid = EFI_CONFORMANCE_PROFILES_TABLE_GUID;
static const efi_guid_t efi_ebbr_2_1_guid = EFI_CONFORMANCE_PROFILE_EBBR_2_1_GUID;

/**
 * efi_ecpt_register() - Install the ECPT system table.
 *
 * Return: status code
 */
efi_status_t efi_ecpt_register(void)
{
	struct efi_conformance_profiles_table *ecpt;
	efi_status_t ret;
	size_t ecpt_size;

	ecpt_size = sizeof(efi_guid_t) + sizeof(struct efi_conformance_profiles_table);
	ret = efi_allocate_pool(EFI_BOOT_SERVICES_DATA, ecpt_size, (void **)&ecpt);

	if (ret != EFI_SUCCESS) {
		printf("%s: out of memory\n", __func__);
		return ret;
	}

	guidcpy(&ecpt->conformance_profiles[0], &efi_ebbr_2_1_guid);
	ecpt->number_of_profiles = 1;
	ecpt->version = EFI_CONFORMANCE_PROFILES_TABLE_VERSION;

	// Install the ECPT in the system configuration table.
	ret = efi_install_configuration_table(&efi_ecpt_guid, (void *)ecpt);
	if (ret != EFI_SUCCESS) {
		printf("Failed to install ECPT\n");
		efi_free_pool(ecpt);
		return ret;
	}

	printf("ECPT created\n");

	return EFI_SUCCESS;
}
