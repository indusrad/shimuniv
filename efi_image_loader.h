// SPDX-License-Identifier: GPL-2.0+

/*
 * Copyright (C) 1999 VA Linux Systems
 * Copyright (C) 1999 Walt Drummond <drummond@valinux.com>
 * Copyright (C) 1999, 2002-2003 Hewlett-Packard Co.
 * David Mosberger-Tang <davidm@hpl.hp.com>
 * Stephane Eranian <eranian@hpl.hp.com>
 *  Copyright (c) 2023 ARM Ltd.
 */


#ifndef EFI_IMAGE_LOADER_H
#define EFI_IMAGE_LOADER_H

#include "efi_defines.h"
#include "efi_object.h"
#include "efi_table.h"

#include <stddef.h>

/*
 * handle of a loaded image
 *
 * @header:         EFI object header
 * @exit_status:    exit status passed to Exit()
 * @exit_data_size: exit data size passed to Exit()
 * @exit_data:      exit data passed to Exit()
 * @exit_jmp:       long jump buffer for returning from started image
 * @entry:          entry address of the relocated image
 * @image_type:     indicates if the image is an applicition or a driver
 */
struct efi_loaded_image_obj {
	struct efi_object header;
	efi_status_t *exit_status;
	size_t *exit_data_size;
	u16 **exit_data;
	struct jmp_buf_data *exit_jmp;
	EFIAPI efi_status_t (*entry)(efi_handle_t image_handle, struct efi_system_table *st);
	u16 image_type;
};

/*
 * efi_loaded_image is populated by leanEFI and queried by Linux early on
 */
struct efi_loaded_image {
	u32 revision;
	efi_handle_t parent_handle;
	struct efi_system_table *system_table;
	efi_handle_t device_handle;
	void *file_path;
	void *reserved;
	u32 load_options_size;
	void *load_options;
	void *image_base;
	aligned_u64 image_size;
	unsigned int image_code_type;
	unsigned int image_data_type;
	efi_status_t (EFIAPI *unload)(efi_handle_t image_handle);
};

efi_status_t EFIAPI efi_unload_image(efi_handle_t image_handle);
efi_status_t EFIAPI efi_exit(efi_handle_t image_handle,
				    efi_status_t exit_status,
				    size_t exit_data_size,
				    u16 *exit_data);
efi_status_t EFIAPI efi_start_image(efi_handle_t image_handle,
				    size_t *exit_data_size,
				    u16 **exit_data);
efi_status_t EFIAPI efi_load_image(bool boot_policy,
				   efi_handle_t parent_image,
				   void *file_path,
				   void *source_buffer,
				   size_t source_size,
				   efi_handle_t *image_handle);
efi_status_t efi_run_image(void *source_buffer, size_t source_size);
efi_status_t efi_load_pe(struct efi_loaded_image_obj *handle,
			 void *efi, size_t efi_size,
			 struct efi_loaded_image *loaded_image_info);

#endif
