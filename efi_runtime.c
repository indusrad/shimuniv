// SPDX-License-Identifier: GPL-2.0+

/*
 *  Copyright (c) 2016 Alexander Graf
 *  Copyright (c) 2023 ARM Ltd.
 *
 * This file is derived from the U-Boot project
 */

#include "efi_defines.h"
#include "efi_runtime_services.h"
#include "efi_memory.h"
#include "elf.h"

#include <queue.h>

// This list contains all runtime available mmio regions
LIST_HEAD(efi_runtime_mmio_list, efi_runtime_mmio) efi_runtime_mmio_list;

// GUID of the runtime properties table
static const efi_guid_t efi_rt_properties_table_guid = EFI_RT_PROPERTIES_TABLE_GUID;

/*
 * Create a configuration table specifying which services are available at runtime.
 *
 * Return: status code
 */
efi_status_t efi_init_runtime_supported(void)
{
	efi_status_t ret;
	struct efi_rt_properties_table *rt_table;

	ret = efi_allocate_pool(EFI_RUNTIME_SERVICES_DATA,
				sizeof(struct efi_rt_properties_table),
				(void **)&rt_table);
	if (ret != EFI_SUCCESS)
		return ret;

	rt_table->version = EFI_RT_PROPERTIES_TABLE_VERSION;
	rt_table->length = sizeof(struct efi_rt_properties_table);
	rt_table->runtime_services_supported =
				EFI_RT_SUPPORTED_SET_VIRTUAL_ADDRESS_MAP |
				EFI_RT_SUPPORTED_CONVERT_POINTER;

	ret = efi_install_configuration_table(&efi_rt_properties_table_guid,
					      rt_table);
	return ret;
}

// Return true if the pointer points to a service function pointer in the runtime table
static bool efi_is_runtime_service_pointer(void *p)
{
	return (p >= (void *)&efi_runtime_services.get_time && \
		p <= (void *)&efi_runtime_services.query_variable_info);
}

extern char __efi_runtime_rel_start;
extern char __efi_runtime_rel_end;

// Relocate EFI runtime to uboot_reloc_base = offset
void efi_runtime_relocate(unsigned long offset, struct efi_mem_desc *map)
{
#ifdef IS_RELA
	struct elf_rela *rel = (void *)&__efi_runtime_rel_start;
#else
	struct elf_rel *rel = (void *)&__efi_runtime_rel_start;
	static unsigned long lastoff = CONFIG_BASE_ADDRESS;
#endif

	printf("%s: Relocating to offset=%lx\n", __func__, offset);
	for (; (unsigned long)rel < (unsigned long)&__efi_runtime_rel_end; rel++) {
		unsigned long base = CONFIG_LP_BASE_ADDRESS;
		unsigned long *p;
		unsigned long newaddr;

		p = (void *)((unsigned long)rel->offset - base);

		// The runtime services table is updated in efi_relocate_runtime_table()
		if (map && efi_is_runtime_service_pointer(p))
			continue;

		printf("%s: rel->info=%#lx *p=%#lx rel->offset=%p\n", __func__,
		      rel->info, *p, rel->offset);

		switch (rel->info & R_MASK) {
		case R_RELATIVE:
#ifdef IS_RELA
		newaddr = rel->addend + offset - CONFIG_LP_BASE_ADDRESS;
#else
		newaddr = *p - lastoff + offset;
#endif
			break;
		default:
			printf("%s: Unknown relocation type %llx\n",
			       __func__, rel->info & R_MASK);
			continue;
		}

		// Check if the relocation is inside bounds
		if (map && ((newaddr < map->virtual_start) ||
		    newaddr > (map->virtual_start +
			      (map->num_pages << EFI_PAGE_SHIFT)))) {
			printf("%s: Relocation at %p is out of range (%lx)\n",
			       __func__, p, newaddr);
			continue;
		}

		printf("%s: Setting %p to %lx\n", __func__, p, newaddr);
		*p = newaddr;
		//flush_dcache_range((unsigned long)p & ~(EFI_CACHELINE_SIZE - 1),
		//	ALIGN((unsigned long)&p[1], EFI_CACHELINE_SIZE)); TODO
		dcache_clean_invalidate_all();
	}

#ifndef IS_RELA
	lastoff = offset;
#endif

	//invalidate_icache_all(); TODO
	tlb_invalidate_all();
}

/*
 * This function adds a memory-mapped IO region to the memory map to make it available
 * at runtime.
 *
 * @mmio_ptr: pointer to a pointer to the start of the memory-mapped IO region
 * @len:      size of the memory-mapped IO region
 *
 * Returns: status code
 */
efi_status_t efi_add_runtime_mmio(void *mmio_ptr, u64 len)
{
	struct efi_runtime_mmio *newmmio;
	uint64_t addr = *(uintptr_t *)mmio_ptr;
	efi_status_t ret;

	ret = efi_add_memory_map(addr, len, EFI_MMAP_IO);
	if (ret != EFI_SUCCESS)
		return EFI_OUT_OF_RESOURCES;

	newmmio = calloc(1, sizeof(*newmmio));
	if (!newmmio)
		return EFI_OUT_OF_RESOURCES;
	newmmio->ptr = mmio_ptr;
	newmmio->paddr = *(uintptr_t *)mmio_ptr;
	newmmio->len = len;
	LIST_INSERT_HEAD(&efi_runtime_mmio_list, newmmio, link);

	return EFI_SUCCESS;
}
