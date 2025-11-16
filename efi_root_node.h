// SPDX-License-Identifier: GPL-2.0+

#ifndef EFI_ROOT_NODE_H
#define EFI_ROOT_NODE_H

#include "efi_enum.h"
#include "efi_object.h"

extern efi_handle_t efi_root;

efi_status_t efi_root_node_register(void);

#endif
