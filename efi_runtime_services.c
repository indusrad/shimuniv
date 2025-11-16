// SPDX-License-Identifier: GPL-2.0+
/*
 *  EFI application runtime services
 *
 *  Copyright (c) 2016 Alexander Graf
 *  Copyright (c) 2023 ARM Ltd.
 *
 * This file is derived from the U-Boot project
 */

#include "efi_runtime_services.h"
#include "efi_runtime.h"
#include "efi_defines.h"
#include "efi_guid.h"
#include "efi_object.h"
#include "elf.h"

#include <queue.h>

static __efi_runtime_data struct efi_mem_desc *efi_virtmap;
static __efi_runtime_data size_t efi_descriptor_count;
static __efi_runtime_data size_t efi_descriptor_size;

static u16 __efi_runtime_data firmware_vendor[] = u"leanEFI";

struct efi_system_table __efi_runtime_data systab = {
	.hdr = {
		.signature = EFI_SYSTEM_TABLE_SIGNATURE,
		.revision = EFI_SPECIFICATION_VERSION,
		.headersize = sizeof(struct efi_system_table),
	},
	.fw_vendor = firmware_vendor,
	.fw_revision = FW_VERSION << 16 | FW_PATCHLEVEL << 8,
	.runtime = &efi_runtime_services,
	.nr_tables = 0,
	.tables = NULL,
};

// This function is used for all unimplemented runtime services
static efi_status_t __efi_runtime EFIAPI efi_unimplemented(void)
{
	printf("Called unimplemented service\n");
	return EFI_UNSUPPORTED;
}

/*
 * For some reason some functions are required (by the UEFI spec) to return
 * EFI_DEVICE_ERROR instead of EFI_UNSUPPORTED, if they are not implemented
 */
static efi_status_t __efi_runtime EFIAPI efi_device_error(void)
{
	printf("Called unimplemented service\n");
	return EFI_DEVICE_ERROR;
}

void __efi_runtime efi_relocate_runtime_table(unsigned long offset)
{
	unsigned long patchoff;
	void **pos;

	// Relocate the runtime services pointers
	// TODO remove since we don't implement any runtime services anyway.
	//      We can also remove the entire runtime footprint of leanEFI
	patchoff = offset;
	for (pos = (void **)&efi_runtime_services.get_time;
	     pos <= (void **)&efi_runtime_services.query_variable_info; ++pos) {
		if (*pos)
			*pos += patchoff;
	}

	/*
	 * The entry for SetVirtualAddress() must point to a physical address.
	 * After the first execution the service must return EFI_UNSUPPORTED.
	 */
	efi_runtime_services.set_virtual_address_map = (void *)&efi_unimplemented;

	/*
	 * The entry for ConvertPointer() must point to a physical address.
	 * The service is not usable after SetVirtualAddress().
	 */
	efi_runtime_services.convert_pointer = (void *)&efi_unimplemented;

	// Update CRC32
	efi_update_table_header_crc32(&efi_runtime_services.hdr);
}

/*
 * convert from physical to virtual pointer
 * This function implements the ConvertPointer() runtime service until the first call to
 * SetVirtualAddressMap().
 * See the Unified Extensible Firmware Interface (UEFI) specification for details.
 *
 * @debug_disposition: indicates if pointer may be converted to NULL
 * @address:           pointer to be converted
 *
 * Return: status code
 */
static __efi_runtime efi_status_t EFIAPI
efi_convert_pointer(size_t debug_disposition, void **address)
{
	efi_physical_addr_t addr;
	size_t i;
	efi_status_t ret = EFI_NOT_FOUND;

	if (!efi_virtmap) {
		ret = EFI_UNSUPPORTED;
		goto out;
	}

	if (!address) {
		ret = EFI_INVALID_PARAMETER;
		goto out;
	}
	if (!*address) {
		if (debug_disposition & EFI_OPTIONAL_PTR)
			return EFI_SUCCESS;
		else
			return EFI_INVALID_PARAMETER;
	}

	addr = (uintptr_t)*address;
	for (i = 0; i < efi_descriptor_count; i++) {
		struct efi_mem_desc *map = (void *)efi_virtmap +
					   (efi_descriptor_size * i);

		if (addr >= map->physical_start &&
		    (addr < map->physical_start
			    + (map->num_pages << EFI_PAGE_SHIFT))) {
			*address = (void *)(uintptr_t)
				   (addr + map->virtual_start -
				    map->physical_start);

			ret = EFI_SUCCESS;
			break;
		}
	}

out:
	return ret;
}

/*
 * change from physical to virtual mapping
 * This function implements the SetVirtualAddressMap() runtime service.
 * See the Unified Extensible Firmware Interface (UEFI) specification for details.
 *
 * @memory_map_size:    size of the virtual map
 * @descriptor_size:    size of an entry in the map
 * @descriptor_version: version of the map entries
 * @virtmap:            virtual address mapping information
 *
 * Return: status code
 */
static efi_status_t EFIAPI efi_set_virtual_address_map(
			size_t memory_map_size,
			size_t descriptor_size,
			uint32_t descriptor_version,
			struct efi_mem_desc *virtmap)
{
	size_t n = memory_map_size / descriptor_size;
	size_t i;
	efi_status_t ret = EFI_INVALID_PARAMETER;
	int rt_code_sections = 0;

	if (descriptor_version != EFI_MEMORY_DESCRIPTOR_VERSION ||
	    descriptor_size < sizeof(struct efi_mem_desc))
		goto out;

	efi_virtmap = virtmap;
	efi_descriptor_size = descriptor_size;
	efi_descriptor_count = n;

	for (i = 0; i < n; i++) {
		struct efi_mem_desc *map = (void *)virtmap +
					   (descriptor_size * i);

		if (map->type == EFI_RUNTIME_SERVICES_CODE)
			rt_code_sections++;
	}

	if (rt_code_sections != 1) {
		/*
		 * We expose exactly one single runtime code section, so
		 * something is definitely going wrong.
		 */
		goto out;
	}

	// Rebind mmio pointers
	for (i = 0; i < n; i++) {
		struct efi_mem_desc *map = (void *)virtmap +
					   (descriptor_size * i);
		struct efi_runtime_mmio *lhandle;
		efi_physical_addr_t map_start = map->physical_start;
		efi_physical_addr_t map_len = map->num_pages << EFI_PAGE_SHIFT;
		efi_physical_addr_t map_end = map_start + map_len;
		u64 off = map->virtual_start - map_start;

		// Adjust all mmio pointers in this region
		LIST_FOREACH(lhandle, &efi_runtime_mmio_list, link) {
			struct efi_runtime_mmio *lmmio;

			lmmio = lhandle;
			if ((map_start <= lmmio->paddr) &&
			    (map_end >= lmmio->paddr)) {
				uintptr_t new_addr = lmmio->paddr + off;
				*lmmio->ptr = (void *)new_addr;
			}
		}
		if ((map_start <= (uintptr_t)systab.tables) &&
		    (map_end >= (uintptr_t)systab.tables)) {
			char *ptr = (char *)systab.tables;

			ptr += off;
			systab.tables = (struct efi_configuration_table *)ptr;
		}
	}

	for (i = 0; i < n; i++) {
		struct efi_mem_desc *map;

		map = (void *)virtmap + (descriptor_size * i);
		if (map->type == EFI_RUNTIME_SERVICES_CODE) {
			unsigned long new_offset = map->virtual_start - map->physical_start;

			efi_relocate_runtime_table(new_offset);
			efi_runtime_relocate(new_offset, map);
			ret = EFI_SUCCESS;
			goto out;
		}
	}

out:
	return ret;
}

struct efi_runtime_services __efi_runtime_data efi_runtime_services = {
	.hdr = {
		.signature = EFI_RUNTIME_SERVICES_SIGNATURE,
		.revision = EFI_SPECIFICATION_VERSION,
		.headersize = sizeof(struct efi_runtime_services),
	},
	.set_virtual_address_map =  efi_set_virtual_address_map,
	.convert_pointer =          efi_convert_pointer,
	.get_time =                 (void *)&efi_unimplemented,
	.set_time =                 (void *)&efi_unimplemented,
	.get_wakeup_time =          (void *)&efi_unimplemented,
	.set_wakeup_time =          (void *)&efi_unimplemented,
	.get_variable =             (void *)&efi_unimplemented,
	.get_next_variable_name =   (void *)&efi_unimplemented,
	.set_variable =             (void *)&efi_unimplemented,
	.get_next_high_mono_count = (void *)&efi_device_error,
	.reset_system =             (void *)&efi_unimplemented,
	.update_capsule =           (void *)&efi_unimplemented,
	.query_capsule_caps =       (void *)&efi_unimplemented,
	.query_variable_info =      (void *)&efi_unimplemented,
};
