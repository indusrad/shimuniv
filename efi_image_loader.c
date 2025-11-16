// SPDX-License-Identifier: GPL-2.0+
/*
 *  EFI device path
 *
 *  Copyright (c) 2016 Alexander Graf
 *  Copyright (c) 2023 ARM Ltd.
 *
 * This file is derived from the U-Boot project
 */

#include "efi_image_loader.h"
#include "efi_defines.h"
#include "efi_guid.h"
#include "efi_boot_services.h"
#include "efi_memory.h"
#include "efi_table.h"
#include "pe.h"
#include <arch/cache.h>
#include <libpayload.h>
#include <setjmp.h>

const efi_guid_t efi_guid_loaded_image = EFI_LOADED_IMAGE_PROTOCOL_GUID;
const efi_guid_t efi_guid_loaded_image_device_path = EFI_LOADED_IMAGE_DEVICE_PATH_PROTOCOL_GUID;
const efi_guid_t efi_simple_file_system_protocol_guid = EFI_SIMPLE_FILE_SYSTEM_PROTOCOL_GUID;
const efi_guid_t efi_file_info_guid = EFI_FILE_INFO_GUID;

extern struct efi_system_table systab;

static int machines[] = {
#if defined(__aarch64__)
	IMAGE_FILE_MACHINE_ARM64,
#elif defined(__arm__)
	IMAGE_FILE_MACHINE_ARM,
	IMAGE_FILE_MACHINE_THUMB,
	IMAGE_FILE_MACHINE_ARMNT,
#endif

#if defined(__x86_64__)
	IMAGE_FILE_MACHINE_AMD64,
#elif defined(__i386__)
	IMAGE_FILE_MACHINE_I386,
#endif

#if defined(__riscv) && (__riscv_xlen == 32)
	IMAGE_FILE_MACHINE_RISCV32,
#endif

#if defined(__riscv) && (__riscv_xlen == 64)
	IMAGE_FILE_MACHINE_RISCV64,
#endif
	0};

/*
 * relocate UEFI binary
 *
 * @rel:          pointer to the relocation table
 * @rel_size:     size of the relocation table in bytes
 * @efi_reloc:    actual load address of the image
 * @pref_address: preferred load address of the image
 * Return:        status code
 */
static efi_status_t efi_loader_relocate(
	const struct image_base_relocation *rel,
	unsigned long rel_size,
	void *efi_reloc,
	unsigned long pref_address)
{
	unsigned long delta = (unsigned long)efi_reloc - pref_address;
	const struct image_base_relocation *end;
	int i;

	printf("relocate efi binary from %p to %ld (offset: %ld)\n", efi_reloc, pref_address, ((unsigned long)efi_reloc) - pref_address);
	if (delta == 0)
		return EFI_SUCCESS;

	end = (const struct image_base_relocation *)((const char *)rel + rel_size);
	while (rel < end && rel->size_of_block) {
		const uint16_t *relocs = (const uint16_t *)(rel + 1);
		i = (rel->size_of_block - sizeof(*rel)) / sizeof(uint16_t);
		while (i--) {
			uint32_t offset = (uint32_t)(*relocs & 0xfff) + rel->virtual_address;
			int type = *relocs >> EFI_PAGE_SHIFT;
			uint64_t *x64 = efi_reloc + offset;
			uint32_t *x32 = efi_reloc + offset;
			uint16_t *x16 = efi_reloc + offset;

			switch (type) {
			case IMAGE_REL_BASED_ABSOLUTE:
				break;
			case IMAGE_REL_BASED_HIGH:
				*x16 += ((uint32_t)delta) >> 16;
				break;
			case IMAGE_REL_BASED_LOW:
				*x16 += (uint16_t)delta;
				break;
			case IMAGE_REL_BASED_HIGHLOW:
				*x32 += (uint32_t)delta;
				break;
			case IMAGE_REL_BASED_DIR64:
				*x64 += (uint64_t)delta;
				break;
#ifdef __riscv
			case IMAGE_REL_BASED_RISCV_HI20:
				*x32 = ((*x32 & 0xfffff000) + (uint32_t)delta) |
					(*x32 & 0x00000fff);
				break;
			case IMAGE_REL_BASED_RISCV_LOW12I:
			case IMAGE_REL_BASED_RISCV_LOW12S:
				// We know that we're 4k aligned
				if (delta & 0xfff) {
					printf("Unsupported reloc offset\n");
					return EFI_LOAD_ERROR;
				}
				break;
#endif
			default:
				printf("Unknown Relocation off %x type %x\n", offset, type);
				return EFI_LOAD_ERROR;
			}
			relocs++;
		}
		rel = (const struct image_base_relocation *)relocs;
	}
	return EFI_SUCCESS;
}

/*
 * determine the memory types to be used for code and data.
 *
 * @loaded_image_info: image descriptor
 * @image_type:        field Subsystem of the optional header for Windows specific field
 */
static void efi_set_code_and_data_type(
			struct efi_loaded_image *loaded_image_info,
			uint16_t image_type)
{
	switch (image_type) {
	case IMAGE_SUBSYSTEM_EFI_APPLICATION:
		loaded_image_info->image_code_type = EFI_LOADER_CODE;
		loaded_image_info->image_data_type = EFI_LOADER_DATA;
		break;
	case IMAGE_SUBSYSTEM_EFI_BOOT_SERVICE_DRIVER:
		loaded_image_info->image_code_type = EFI_BOOT_SERVICES_CODE;
		loaded_image_info->image_data_type = EFI_BOOT_SERVICES_DATA;
		break;
	case IMAGE_SUBSYSTEM_EFI_RUNTIME_DRIVER:
	case IMAGE_SUBSYSTEM_EFI_ROM:
		loaded_image_info->image_code_type = EFI_RUNTIME_SERVICES_CODE;
		loaded_image_info->image_data_type = EFI_RUNTIME_SERVICES_DATA;
		break;
	default:
		printf("invalid image type: %u\n", image_type);
		// Let's assume it is an application
		loaded_image_info->image_code_type = EFI_LOADER_CODE;
		loaded_image_info->image_data_type = EFI_LOADER_DATA;
		break;
	}
}

/*
 * check if a memory buffer contains a PE-COFF image
 *
 * @buffer:    buffer to check
 * @size:      size of buffer
 * @nt_header: on return pointer to NT header of PE-COFF image
 * Return:     EFI_SUCCESS if the buffer contains a PE-COFF image
 */
static efi_status_t efi_check_pe(void *buffer, size_t size, void **nt_header)
{
	struct image_dos_header *dos = buffer;
	struct image_nt_headers32 *nt;

	if (size < sizeof(*dos))
		return EFI_INVALID_PARAMETER;

	// Check for DOS magix
	if (dos->e_magic != IMAGE_DOS_SIGNATURE)
		return EFI_INVALID_PARAMETER;

	/*
	 * Check if the image section header fits into the file. Knowing that at
	 * least one section header follows we only need to check for the length
	 * of the 64bit header which is longer than the 32bit header.
	 */
	if (size < dos->e_lfanew + sizeof(struct image_nt_headers32))
		return EFI_INVALID_PARAMETER;
	nt = (struct image_nt_headers32 *)((u8 *)buffer + dos->e_lfanew);

	// Check for PE-COFF magic
	if (nt->signature != IMAGE_NT_SIGNATURE)
		return EFI_INVALID_PARAMETER;

	if (nt_header)
		*nt_header = nt;

	return EFI_SUCCESS;
}

/*
 * determine size of section
 * The size of a section in memory if normally given by VirtualSize.
 * If virtual_size is not provided, use size_of_raw_data.
 *
 * @sec:   section header
 * Return: size of section in memory
 */
static u32 section_size(struct image_section_header *sec)
{
	if (sec->misc.virtual_size)
		return sec->misc.virtual_size;
	else
		return sec->size_of_raw_data;
}

/*
 * relocate EFI binary
 * This function loads all sections from a PE binary into a newly reserved
 * piece of memory. On success the entry point is returned as handle->entry.
 *
 * @handle:             loaded image handle
 * @efi:                pointer to the EFI binary
 * @efi_size:           size of @efi binary
 * @loaded_image_info:  loaded image protocol
 * Return:              status code
 */
efi_status_t efi_load_pe(struct efi_loaded_image_obj *handle,
			 void *efi, size_t efi_size,
			 struct efi_loaded_image *loaded_image_info)
{
	struct image_nt_headers32 *nt;
	struct image_dos_header *dos;
	struct image_section_header *sections;
	int num_sections;
	void *efi_reloc;
	int i;
	const struct image_base_relocation *rel;
	unsigned long rel_size;
	int rel_idx = IMAGE_DIRECTORY_ENTRY_BASERELOC;
	uint64_t image_base;
	unsigned long virt_size = 0;
	int supported = 0;
	efi_status_t ret;

	ret = efi_check_pe(efi, efi_size, (void **)&nt);
	if (ret != EFI_SUCCESS) {
		printf("Not a PE-COFF file\n");
		return EFI_LOAD_ERROR;
	}

	for (i = 0; machines[i]; i++)
		if (machines[i] == nt->file_header.machine) {
			supported = 1;
			break;
		}

	if (!supported) {
		printf("Machine type 0x%04x is not supported\n", nt->file_header.machine);
		return EFI_LOAD_ERROR;
	}

	num_sections = nt->file_header.number_of_sections;
	sections = (void *)&nt->optional_header +
			    nt->file_header.size_of_optional_header;

	if (efi_size < (size_t)((void *)sections + sizeof(sections[0]) * num_sections - efi)) {
		printf("Invalid number of sections: %d\n", num_sections);
		return EFI_LOAD_ERROR;
	}

	// Calculate upper virtual address boundary
	for (i = num_sections - 1; i >= 0; i--) {
		struct image_section_header *sec = &sections[i];

		virt_size = MAX(virt_size, sec->virtual_address + section_size(sec));
	}

	// Read 32/64bit specific header bits
	if (nt->optional_header.magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC) {
		struct image_nt_headers64 *nt64 = (void *)nt;
		struct image_optional_header64 *opt = &nt64->optional_header;
		image_base = opt->image_base;
		efi_set_code_and_data_type(loaded_image_info, opt->subsystem);
		handle->image_type = opt->subsystem;
		efi_reloc = efi_alloc_aligned_pages(
			virt_size,
			loaded_image_info->image_code_type,
			opt->section_alignment);
		if (!efi_reloc) {
			printf("Out of memory\n");
			ret = EFI_OUT_OF_RESOURCES;
			goto err;
		}
		handle->entry = efi_reloc + opt->address_of_entry_point;
		rel_size = opt->data_directory[rel_idx].size;
		rel = efi_reloc + opt->data_directory[rel_idx].virtual_address;

	} else if (nt->optional_header.magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC) {
		struct image_optional_header32 *opt = &nt->optional_header;
		image_base = opt->image_base;
		efi_set_code_and_data_type(loaded_image_info, opt->subsystem);
		handle->image_type = opt->subsystem;
		efi_reloc = efi_alloc_aligned_pages(
			virt_size,
			loaded_image_info->image_code_type,
			opt->section_alignment);
		if (!efi_reloc) {
			printf("Out of memory\n");
			ret = EFI_OUT_OF_RESOURCES;
			goto err;
		}
		handle->entry = efi_reloc + opt->address_of_entry_point;
		rel_size = opt->data_directory[rel_idx].size;
		rel = efi_reloc + opt->data_directory[rel_idx].virtual_address;
	} else {
		printf("Invalid optional header magic %x\n",
			nt->optional_header.magic);
		ret = EFI_LOAD_ERROR;
		goto err;
	}

	// copy PE headers
	memcpy(efi_reloc, efi,
		sizeof(*dos)
		 + sizeof(*nt)
		 + nt->file_header.size_of_optional_header
		 + num_sections * sizeof(struct image_section_header));

	// load sections into RAM
	for (i = num_sections - 1; i >= 0; i--) {
		struct image_section_header *sec = &sections[i];
		u32 copy_size = section_size(sec);

		if (copy_size > sec->size_of_raw_data) {
			copy_size = sec->size_of_raw_data;
			memset(efi_reloc + sec->virtual_address, 0,
			       sec->misc.virtual_size);
		}
		memcpy(efi_reloc + sec->virtual_address,
		       efi + sec->pointer_to_raw_data,
		       copy_size);

	}

	// run through relocations
	if (efi_loader_relocate(rel, rel_size, efi_reloc, (unsigned long)image_base)
			!= EFI_SUCCESS) {
		efi_free_pages((uintptr_t) efi_reloc,
			       (virt_size + EFI_PAGE_MASK) >> EFI_PAGE_SHIFT);
		ret = EFI_LOAD_ERROR;
		goto err;
	}

	// flush cache
	//flush_cache((unsigned long)efi_reloc, ALIGN(virt_size, EFI_CACHELINE_SIZE));
	dcache_clean_invalidate_all();
	//invalidate_icache_all(); TODO
	tlb_invalidate_all();

	// populate the loaded image interface bits
	loaded_image_info->image_base = efi_reloc;
	loaded_image_info->image_size = virt_size;

	return EFI_SUCCESS;
err:
	return ret;
}

/*
 * load an EFI image into memory
 * This function implements the LoadImage service.
 * See the Unified Extensible Firmware Interface (UEFI) specification for details.
 *
 * @boot_policy:   true for request originating from the boot manager
 * @parent_image:  the caller's image handle
 * @file_path:     the path of the image to load
 * @source_buffer: memory location from which the image is installed
 * @source_size:   size of the memory area from which the image is installed
 * @image_handle:  handle for the newly installed image
 *
 * Return: status code
 */
efi_status_t EFIAPI efi_load_image(bool boot_policy,
				   efi_handle_t parent_image,
				   void *file_path,
				   void *source_buffer,
				   size_t source_size,
				   efi_handle_t *image_handle)
{
	(void) file_path;
	(void) boot_policy;
	efi_status_t ret = EFI_SUCCESS;

	// The parent image handle must refer to a loaded image
	if (!image_handle
	|| (!source_buffer && !file_path)
	|| !efi_obj_in_list(parent_image)
	|| !parent_image->type) {
		return EFI_INVALID_PARAMETER;
	}

	// leanEFI does not support loading an image via file path
	if (!source_buffer)
		return EFI_UNSUPPORTED;

	struct efi_loaded_image *info = calloc(1, sizeof(*info));
	if (!info)
		return EFI_OUT_OF_RESOURCES;

	struct efi_loaded_image_obj *obj = calloc(1, sizeof(*obj));
	if (!obj) {
		free(info);
		return EFI_OUT_OF_RESOURCES;
	}

	obj->header.type = EFI_OBJECT_TYPE_LOADED_IMAGE;

	// Add internal object to object list
	efi_add_handle(&obj->header);

	info->revision =  EFI_LOADED_IMAGE_PROTOCOL_REVISION;
	info->system_table = &systab;

	/*
	 * When asking for the loaded_image interface, just
	 * return handle which points to loaded_image_info
	 */
	ret = efi_add_protocol(&obj->header, &efi_guid_loaded_image, info);
	if (ret != EFI_SUCCESS) {
		goto free_error;
	}

	ret = efi_load_pe(obj, source_buffer, source_size, info);

	if (ret != EFI_SUCCESS && ret != EFI_SECURITY_VIOLATION) {
		// The image is invalid. Release all associated resources.
		goto free_error;
	}
	info->system_table = &systab;
	info->parent_handle = parent_image;

	*image_handle = (efi_handle_t)obj;
	return EFI_SUCCESS;

free_error:
	efi_delete_handle(&obj->header);
	free(obj);
	free(info);
	return ret;
}

// Handle of the currently executing image
static efi_handle_t current_image;

/*
 * call the entry point of an image
 * This function implements the StartImage service.
 * See the Unified Extensible Firmware Interface (UEFI) specification for
 * details.
 *
 * @image_handle:   handle of the image
 * @exit_data_size: size of the buffer
 * @exit_data:      buffer to receive the exit data of the called image
 *
 * Return: status code
 */
efi_status_t EFIAPI efi_start_image(
	efi_handle_t image_handle,
	size_t *exit_data_size,
	u16 **exit_data)
{
	struct efi_loaded_image_obj *image_obj = (struct efi_loaded_image_obj *)image_handle;
	efi_status_t ret;
	void *info;
	efi_handle_t parent_image = current_image;
	efi_status_t exit_status;
	struct jmp_buf_data exit_jmp;

	if (!efi_obj_in_list(image_handle))
		return EFI_INVALID_PARAMETER;

	// Check parameters
	if (image_obj->header.type != EFI_OBJECT_TYPE_LOADED_IMAGE)
		return EFI_INVALID_PARAMETER;

	ret = efi_open_protocol(image_handle, &efi_guid_loaded_image,
					 &info, NULL, NULL,
					 EFI_OPEN_PROTOCOL_GET_PROTOCOL);
	if (ret != EFI_SUCCESS)
		return EFI_INVALID_PARAMETER;

	image_obj->exit_data_size = exit_data_size;
	image_obj->exit_data = exit_data;
	image_obj->exit_status = &exit_status;
	image_obj->exit_jmp = &exit_jmp;

	// call the image!
	if (setjmp(&exit_jmp)) {
		/*
		 * The child image called the Exit() boot
		 * service efi_exit() which executed the long jump that brought
		 * us to the current line.
		 */
		printf("%lu returned by started image\n",
			  (unsigned long)((uintptr_t)exit_status));
		current_image = parent_image;
		return exit_status;
	}

	current_image = image_handle;
	image_obj->header.type = EFI_OBJECT_TYPE_STARTED_IMAGE;
	printf("Jumping into %p\n", image_obj->entry);
	ret = image_obj->entry(image_handle, &systab);

	/*
	 * Control is returned from a started UEFI image either by calling
	 * Exit() (where exit data can be provided) or by simply returning from
	 * the entry point. In the latter case call Exit() on behalf of the
	 * image.
	 */
	return systab.boottime->exit(image_handle, ret, 0, NULL);
}

extern struct efi_object_list efi_obj_list;

/*
 * delete loaded image from memory)
 *
 * @image_obj:             handle of the loaded image
 * @loaded_image_protocol: loaded image protocol
 */
static efi_status_t efi_delete_image(
	struct efi_loaded_image_obj *image_obj,
	struct efi_loaded_image *loaded_image_protocol)
{
	struct efi_object *efiobj;
	efi_status_t r, ret = EFI_SUCCESS;

close_next:
	LIST_FOREACH(efiobj, &efi_obj_list, link) {
		struct efi_handler *protocol;

		LIST_FOREACH(protocol, &efiobj->protocols, link) {
			struct efi_open_protocol_info_item *info;

			LIST_FOREACH(info, &protocol->open_infos, link) {
				if (info->info.agent_handle !=
				    (efi_handle_t)image_obj)
					continue;
				r = efi_close_protocol(
						efiobj, &protocol->guid,
						info->info.agent_handle,
						NULL);
				if (r !=  EFI_SUCCESS)
					ret = r;
				/*
				 * Closing protocols may results in further
				 * items being deleted. To play it safe loop
				 * over all elements again.
				 */
				goto close_next;
			}
		}
	}

	efi_free_pages((uintptr_t)loaded_image_protocol->image_base,
		       efi_size_in_pages(loaded_image_protocol->image_size));
	efi_delete_handle(&image_obj->header);

	return ret;
}

/*
 * unload an EFI image
 * This function implements the UnloadImage service.
 * See the Unified Extensible Firmware Interface (UEFI) specification for
 * details.
 *
 * @image_handle: handle of the image to be unloaded
 *
 * Return: status code
 */
efi_status_t EFIAPI efi_unload_image(efi_handle_t image_handle)
{
	efi_status_t ret = EFI_SUCCESS;
	struct efi_loaded_image *loaded_image_protocol;

	if (!efi_obj_in_list(image_handle)) {
		ret = EFI_INVALID_PARAMETER;
		goto out;
	}
	// Find the loaded image protocol
	ret = efi_open_protocol(image_handle, &efi_guid_loaded_image,
					 (void **)&loaded_image_protocol,
					 NULL, NULL,
					 EFI_OPEN_PROTOCOL_GET_PROTOCOL);
	if (ret != EFI_SUCCESS) {
		ret = EFI_INVALID_PARAMETER;
		goto out;
	}
	switch (image_handle->type) {
	case EFI_OBJECT_TYPE_STARTED_IMAGE:
		// Call the unload function
		if (!loaded_image_protocol->unload) {
			ret = EFI_UNSUPPORTED;
			goto out;
		}
		ret = loaded_image_protocol->unload(image_handle);
		if (ret != EFI_SUCCESS)
			goto out;
		break;
	case EFI_OBJECT_TYPE_LOADED_IMAGE:
		break;
	default:
		ret = EFI_INVALID_PARAMETER;
		goto out;
	}
	efi_delete_image((struct efi_loaded_image_obj *)image_handle, loaded_image_protocol);
out:
	return ret;
}

/*
 * fill exit data parameters of StartImage()
 *
 * @image_obj:      image handle
 * @exit_data_size: size of the exit data buffer
 * @exit_data:      buffer with data returned by UEFI payload
 * Return:          status code
 */
static efi_status_t efi_update_exit_data(struct efi_loaded_image_obj *image_obj,
					 size_t exit_data_size,
					 u16 *exit_data)
{
	efi_status_t ret;

	// If exit_data is not provided to StartImage(), exit_data_size must be ignored.
	if (!image_obj->exit_data)
		return EFI_SUCCESS;
	if (image_obj->exit_data_size)
		*image_obj->exit_data_size = exit_data_size;
	if (exit_data_size && exit_data) {
		ret = efi_allocate_pool(EFI_BOOT_SERVICES_DATA,
					exit_data_size,
					(void **)image_obj->exit_data);
		if (ret != EFI_SUCCESS)
			return ret;
		memcpy(*image_obj->exit_data, exit_data, exit_data_size);
	} else {
		image_obj->exit_data = NULL;
	}
	return EFI_SUCCESS;
}


/*
 * TODO this needs some testing
 * leave an EFI application or driver
 * This function implements the Exit service.
 * See the Unified Extensible Firmware Interface (UEFI) specification for
 * details.
 *
 * @image_handle:   handle of the application or driver that is exiting
 * @exit_status:    status code
 * @exit_data_size: size of the buffer in bytes
 * @exit_data:      buffer with data describing an error
 *
 * Return: status code
 */
efi_status_t EFIAPI efi_exit(efi_handle_t image_handle,
				    efi_status_t exit_status,
				    size_t exit_data_size,
				    u16 *exit_data)
{
	//TODO We should call the unload procedure of the loaded image protocol.
	efi_status_t ret;
	struct efi_loaded_image *loaded_image_protocol;
	struct efi_loaded_image_obj *image_obj = (struct efi_loaded_image_obj *)image_handle;
	struct jmp_buf_data *exit_jmp;

	// Check parameters
	ret = efi_open_protocol(image_handle, &efi_guid_loaded_image,
					 (void **)&loaded_image_protocol,
					 NULL, NULL,
					 EFI_OPEN_PROTOCOL_GET_PROTOCOL);
	if (ret != EFI_SUCCESS) {
		ret = EFI_INVALID_PARAMETER;
		goto out;
	}

	// Unloading of unstarted images
	switch (image_obj->header.type) {
	case EFI_OBJECT_TYPE_STARTED_IMAGE:
		break;
	case EFI_OBJECT_TYPE_LOADED_IMAGE:
		efi_delete_image(image_obj, loaded_image_protocol);
		ret = EFI_SUCCESS;
		goto out;
	default:
		// Handle does not refer to loaded image
		ret = EFI_INVALID_PARAMETER;
		goto out;
	}
	// A started image can only be unloaded it is the last one started.
	if (image_handle != current_image) {
		ret = EFI_INVALID_PARAMETER;
		goto out;
	}

	// Exit data is only foreseen in case of failure.
	if (exit_status != EFI_SUCCESS) {
		ret = efi_update_exit_data(image_obj, exit_data_size,
					   exit_data);
		// Exiting has priority. Don't return error to caller.
		if (ret != EFI_SUCCESS)
			printf("%s: out of memory\n", __func__);
	}
	// efi_delete_image() frees image_obj. Copy before the call.
	exit_jmp = image_obj->exit_jmp;
	*image_obj->exit_status = exit_status;
	if (image_obj->image_type == IMAGE_SUBSYSTEM_EFI_APPLICATION ||
	    exit_status != EFI_SUCCESS)
		efi_delete_image(image_obj, loaded_image_protocol);

	longjmp(exit_jmp, 1);
out:
	return ret;
}

extern efi_handle_t efi_root;

/*
 * run loaded UEFI image
 *
 * @source_buffer: memory address of the UEFI image
 * @source_size:   size of the UEFI image
 * Return:         status code
 */
efi_status_t efi_run_image(void *source_buffer, size_t source_size)
{
	efi_handle_t handle = NULL;
	efi_status_t ret;

	ret = efi_load_image(false, efi_root, NULL, source_buffer, source_size, &handle);
	if (ret != EFI_SUCCESS) {
		printf("Loading image failed\n");
		goto out;
	}

	size_t exit_data_size = 0;
	u16 *exit_data = NULL;

	// On ARM switch from EL3 or secure mode to EL2 or non-secure mode
	//TODO check if it makes sense to leave that task up to the payload, otherwise
	// implement it in libpayload
	//switch_to_non_secure_mode();

	// Call our payload
	ret = efi_start_image(handle, &exit_data_size, &exit_data);
	if (ret != EFI_SUCCESS) {
		printf("## Application failed, r = %lu\n", ret);
		if (exit_data) {
			//TODO I don't think libpayload printf supports printing UTF-16
			printf("## %ls\n", (wchar_t *)exit_data);
			efi_free_pool(exit_data);
		}
	}

out:
	printf("returned. This should not happen\n");
	//TODO panic or restart or something
	return EFI_SUCCESS;
}
