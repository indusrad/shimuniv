// SPDX-License-Identifier: GPL-2.0+

/*
 *  Copyright (c) 2016 Alexandar Graf
 *  Copyright (c) 2023 ARM Ltd.
 */

#ifndef EFI_OBJECT_H
#define EFI_OBJECT_H

#include "efi_defines.h"
#include "efi_enum.h"
#include <queue.h>

struct efi_handler;
LIST_HEAD(efi_handler_list, efi_handler);
/*
 * dereferenced EFI handle
 * UEFI offers a flexible and expandable object model. struct efi_object is our storage
 * structure for all kinds of objects. When including this structure into a larger structure
 * always put it first so that when deleting a handle the whole encompassing structure can be
 * freed. A pointer to this structure is referred to as a handle. typedef efi_handle_t has
 * been created for such pointers.
 *
 * @link:      pointers to put the handle into a linked list
 * @protocols: linked list with the protocol interfaces installed on this handle
 * @type:      image type if the handle relates to an image
 * @dev:       pointer to the DM device which is associated with this EFI handle
 */
struct efi_object {
	LIST_ENTRY(efi_object) link;       // every UEFI object is part of a global object list
	struct efi_handler_list protocols; // the list of protocols
	enum efi_object_type type;
};
LIST_HEAD(efi_object_list, efi_object);
typedef struct efi_object *efi_handle_t;

_Bool efi_obj_in_list(const efi_handle_t handle);
void efi_add_handle(efi_handle_t handle);
efi_status_t efi_create_handle(efi_handle_t *handle);
void efi_delete_handle(efi_handle_t handle);

#endif // EFI_OBJECT_H
