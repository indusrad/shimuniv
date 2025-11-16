// SPDX-License-Identifier: GPL-2.0+
/*
 *  Root node for system services
 *
 *  Copyright (c) 2018 Heinrich Schuchardt
 *  Copyright (c) 2023 ARM Ltd.
 *
 * This file is derived from the U-Boot project
 */

#include "efi_defines.h"
#include "efi_enum.h"
#include "efi_object.h"
#include "efi_protocol.h"

const efi_guid_t efi_leanefi_guid = LEANEFI_GUID;

efi_handle_t efi_root = NULL;

/*
 * Create the root node on which we install all protocols that are not related to a loaded
 * image or a driver.
 *
 * Return: status code
 */
efi_status_t efi_root_node_register(void)
{
	// Create root node and install protocols
	efi_status_t ret = efi_create_handle(&efi_root);
	efi_root->type = EFI_OBJECT_TYPE_LEANEFI_FIRMWARE;
	return ret;
}
