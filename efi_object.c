// SPDX-License-Identifier: GPL-2.0+

/*
 *  Copyright (c) 2016 Alexander Graf
 *  Copyright (c) 2023 ARM Ltd.
 *
 * This file is derived from the U-Boot project
 */

#include "efi_object.h"
#include "efi_protocol.h"

#include <queue.h>

// This list contains all the EFI objects our payload has access to
struct efi_object_list efi_obj_list;

// check if a given handle is part of the internal EFI object list
_Bool efi_obj_in_list(const efi_handle_t handle)
{
	if (!handle)
		return false;

	struct efi_object *efiobj;
	LIST_FOREACH(efiobj, &efi_obj_list, link) {
		if (efiobj == handle)
			return true;
	}
	return false;
}

/*
 * add a new handle to the object list
 *
 * @handle: handle to be added
 */
void efi_add_handle(efi_handle_t handle)
{
	if (!handle)
		return;
	// The protocols list is initialized.
	LIST_INIT(&handle->protocols);
	// The handle is added to the list of known UEFI objects.
	LIST_INSERT_HEAD(&efi_obj_list, handle, link);
}

efi_status_t efi_create_handle(efi_handle_t *handle)
{
	struct efi_object *obj = calloc(1, sizeof(struct efi_object));
	if (!obj)
		return EFI_OUT_OF_RESOURCES;

	efi_add_handle(obj);
	*handle = obj;

	return EFI_SUCCESS;
}

void efi_delete_handle(efi_handle_t handle)
{
	efi_status_t ret = efi_remove_all_protocols(handle);
	if (ret == EFI_INVALID_PARAMETER) {
		printf("Can't remove invalid handle %p\n", handle);
		return;
	}

	LIST_REMOVE(handle, link);
	free(handle);
}
