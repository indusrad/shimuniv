// SPDX-License-Identifier: GPL-2.0+
/*
 *  EFI application memory management
 *
 *  Copyright (c) 2016 Alexander Graf
 *  Copyright (c) 2023 ARM Ltd.
 *
 * This file is derived from the U-Boot project
 */

#include "efi_memory.h"
#include "helpers.h"
#include "efi_protocol.h"

#include <cache.h>
#include <stdint.h>
#include <stdlib.h>
#include <queue.h>

// Magic number identifying memory allocated from pool
#define EFI_ALLOC_POOL_MAGIC 0x1fe67ddf6491caa2

size_t efi_memory_map_key;

struct efi_mem_list {
	LIST_ENTRY(efi_mem_list) link;
	struct efi_mem_desc desc;
};
// This list contains all memory map items
static LIST_HEAD(efi_mem_list_list, efi_mem_list) efi_mem;


#define EFI_CARVE_NO_OVERLAP		-1
#define EFI_CARVE_LOOP_AGAIN		-2
#define EFI_CARVE_OVERLAPS_NONRAM	-3

/*
 * memory block allocated from pool
 *
 * leanEFI services each UEFI AllocatePool() request as a separate
 * (multiple) page allocation. We have to track the number of pages
 * to be able to free the correct amount later.
 *
 * The checksum calculated in function checksum() is used in FreePool() to avoid
 * freeing memory not allocated by AllocatePool() and duplicate freeing.
 *
 * EFI requires 8 byte alignment for pool allocations, so we can
 * prepend each allocation with these header fields.
 *
 * @num_pages: number of pages allocated
 * @checksum:  checksum
 * @data:      allocated pool memory
 */
struct efi_pool_allocation {
	u64 num_pages;
	u64 checksum;
	char data[] __aligned(ARCH_DMA_MINALIGN);
};

/*
 * calculate checksum for memory allocated from pool
 *
 * @alloc: allocation header
 * Return: checksum, always non-zero
 */
static u64 checksum(struct efi_pool_allocation *alloc)
{
	u64 addr = (uintptr_t)alloc;
	u64 ret = (addr >> 32) ^ (addr << 32) ^ alloc->num_pages ^
		  EFI_ALLOC_POOL_MAGIC;
	if (!ret)
		++ret;
	return ret;
}

/*
 * get end address of memory area
 *
 * @desc:   memory descriptor
 * Return:  end address + 1
 */
static uint64_t desc_get_end(struct efi_mem_desc *desc)
{
	return desc->physical_start + (desc->num_pages << EFI_PAGE_SHIFT);
}

// insertion sort TODO put into libpayload
#define LIST_SORT(head, type, field, cmp_func) { \
	struct type *item_to_sort; \
	for((item_to_sort)  = LIST_FIRST(head); \
	    (item_to_sort) != LIST_END(head); \
	    (item_to_sort)  = LIST_NEXT(item_to_sort, field))  { \
\
		struct type *sorted_item; \
		for((sorted_item)  = LIST_FIRST(head); \
		    (sorted_item) != item_to_sort; \
		    (sorted_item)  = LIST_NEXT(sorted_item, field))  { \
\
			if (cmp_func(item_to_sort, sorted_item) < 0) { \
				LIST_REMOVE(item_to_sort, field); \
				LIST_INSERT_BEFORE(sorted_item, item_to_sort, field); \
				break; \
			} \
		} \
	} \
}

// comparator function for a memory region
int efi_mem_cmp(struct efi_mem_list *a, struct efi_mem_list *b)
{
	if (a->desc.physical_start < b->desc.physical_start)
		return -1;
	if (a->desc.physical_start > b->desc.physical_start)
		return 1;
	return 0;
}

// sort the memory map and then try to merge adjacent memory areas.
static void efi_mem_sort(void)
{
	LIST_SORT(&efi_mem, efi_mem_list, link, efi_mem_cmp);

	struct efi_mem_list *lhandle;
	struct efi_mem_list *prevmem = NULL;
	bool merge_again = true;

	// Now merge entries that can be merged
	while (merge_again) {
		merge_again = false;
		LIST_FOREACH(lhandle, &efi_mem, link) {
			struct efi_mem_list *lmem;
			struct efi_mem_desc *prev = &prevmem->desc;
			struct efi_mem_desc *cur;
			uint64_t pages;

			lmem = lhandle;
			if (!prevmem) {
				prevmem = lmem;
				continue;
			}

			cur = &lmem->desc;

			if ((desc_get_end(cur) == prev->physical_start) &&
			    (prev->type == cur->type) &&
			    (prev->attribute == cur->attribute)) {
				// There is an existing map before, reuse it
				pages = cur->num_pages;
				prev->num_pages += pages;
				prev->physical_start -= pages << EFI_PAGE_SHIFT;
				prev->virtual_start -= pages << EFI_PAGE_SHIFT;
				LIST_REMOVE(lmem, link);
				free(lmem);

				merge_again = true;
				break;
			}
			prevmem = lmem;
		}
	}
}

/*
 * Unmaps all memory occupied by the carve_desc region from the list entry pointed to by map.
 *
 * @map:               memory map
 * @carve_desc:        memory region to unmap
 * @overlap_only_ram:  the carved out region may only overlap RAM

 * Return:  the number of overlapping pages which have been removed from the map,
 *          EFI_CARVE_NO_OVERLAP: if the regions don't overlap,
 *          EFI_CARVE_OVERLAPS_NONRAM: if the carve and map overlap, and the map contains
 *                                     anything but free ram (only when overlap_only_ram is
 *                                     true), it is the callers responsibility to re-add the
 *                                     already carved out pages to the mapping.
 *          EFI_CARVE_LOOP_AGAIN: if the mapping list should be traversed again, as it has
 *                                been altered.
 */
static s64 efi_mem_carve_out(struct efi_mem_list *map,
			     struct efi_mem_desc *carve_desc,
			     bool overlap_only_ram)
{
	struct efi_mem_list *newmap;
	struct efi_mem_desc *map_desc = &map->desc;
	uint64_t map_start = map_desc->physical_start;
	uint64_t map_end = map_start + (map_desc->num_pages << EFI_PAGE_SHIFT);
	uint64_t carve_start = carve_desc->physical_start;
	uint64_t carve_end = carve_start +
			     (carve_desc->num_pages << EFI_PAGE_SHIFT);

	// check whether we're overlapping
	if ((carve_end <= map_start) || (carve_start >= map_end))
		return EFI_CARVE_NO_OVERLAP;

	// We're overlapping with non-RAM, warn the caller if desired
	if (overlap_only_ram && (map_desc->type != EFI_CONVENTIONAL_MEMORY))
		return EFI_CARVE_OVERLAPS_NONRAM;

	// Sanitize carve_start and carve_end to lie within our bounds
	carve_start = MAX(carve_start, map_start);
	carve_end = MIN(carve_end, map_end);

	// Carving at the beginning of our map? Just move it!
	if (carve_start == map_start) {
		if (map_end == carve_end) {
			// Full overlap, just remove map
			LIST_REMOVE(map, link);
			free(map);
		} else {
			map->desc.physical_start = carve_end;
			map->desc.virtual_start = carve_end;
			map->desc.num_pages = (map_end - carve_end)
					      >> EFI_PAGE_SHIFT;
		}

		return (carve_end - carve_start) >> EFI_PAGE_SHIFT;
	}

	/*
	 * Overlapping maps, just split the list map at carve_start,
	 * it will get moved or removed in the next iteration.
	 *
	 * [ map_desc |__carve_start__| newmap ]
	 */

	// Create a new map from [ carve_start ... map_end ]
	newmap = calloc(1, sizeof(*newmap));
	newmap->desc = map->desc;
	newmap->desc.physical_start = carve_start;
	newmap->desc.virtual_start = carve_start;
	newmap->desc.num_pages = (map_end - carve_start) >> EFI_PAGE_SHIFT;
	// Insert before current entry (descending address order)
	LIST_INSERT_AFTER(map, newmap, link);
	//list_append(&newmap->link, &map->link);

	// Shrink the map to [ map_start ... carve_start ]
	map_desc->num_pages = (carve_start - map_start) >> EFI_PAGE_SHIFT;

	return EFI_CARVE_LOOP_AGAIN;
}

/*
 * add pages to the memory map
 *
 * @start:            start address, must be a multiple of EFI_PAGE_SIZE
 * @pages:            number of pages to add
 * @memory_type:      type of memory added
 * @overlap_only_ram: region may only overlap RAM
 *
 * Return:            status code
 */
static efi_status_t efi_add_memory_map_pg(u64 start, u64 pages,
					  int memory_type,
					  bool overlap_only_ram)
{
	struct efi_mem_list *newlist;
	bool carve_again;
	uint64_t carved_pages = 0;

	printf("%s: 0x%llx 0x%llx %d %s\n", __func__,
		  start, pages, memory_type, overlap_only_ram ? "yes" : "no");

	if (memory_type >= EFI_MAX_MEMORY_TYPE)
		return EFI_INVALID_PARAMETER;

	if (!pages)
		return EFI_SUCCESS;

	++efi_memory_map_key;
	newlist = calloc(1, sizeof(*newlist));
	newlist->desc.type = memory_type;
	newlist->desc.physical_start = start;
	newlist->desc.virtual_start = start;
	newlist->desc.num_pages = pages;

	switch (memory_type) {
	case EFI_RUNTIME_SERVICES_CODE:
	case EFI_RUNTIME_SERVICES_DATA:
		newlist->desc.attribute = EFI_MEMORY_WB | EFI_MEMORY_RUNTIME;
		break;
	case EFI_MMAP_IO:
		newlist->desc.attribute = EFI_MEMORY_RUNTIME;
		break;
	default:
		newlist->desc.attribute = EFI_MEMORY_WB;
		break;
	}

	// Add our new map
	do {
		carve_again = false;
		struct efi_mem_list *lmem;
		LIST_FOREACH(lmem, &efi_mem, link) {
			s64 r;

			r = efi_mem_carve_out(lmem, &newlist->desc,
					      overlap_only_ram);
			switch (r) {
			case EFI_CARVE_OVERLAPS_NONRAM:
				/*
				 * The user requested to only have RAM overlaps,
				 * but we hit a non-RAM region. Error out.
				 */
				return EFI_NO_MAPPING;
			case EFI_CARVE_NO_OVERLAP:
				// Just ignore this list entry
				break;
			case EFI_CARVE_LOOP_AGAIN:
				/*
				 * We split an entry, but need to loop through
				 * the list again to actually carve it.
				 */
				carve_again = true;
				break;
			default:
				// We carved a number of pages
				carved_pages += r;
				carve_again = true;
				break;
			}

			if (carve_again) {
				// The list changed, we need to start over
				break;
			}
		}
	} while (carve_again);

	if (overlap_only_ram && (carved_pages != pages)) {
		/*
		 * The payload wanted to have RAM overlaps, but we overlapped
		 * with an unallocated region. Error out.
		 */
		return EFI_NO_MAPPING;
	}

	// Add our new map
	LIST_INSERT_HEAD(&efi_mem, newlist, link);

	// And make sure memory is listed in descending order
	efi_mem_sort();

	return EFI_SUCCESS;
}

/*
 * add memory area to the memory map
 * This function automatically aligns the start and size of the memory area
 * to EFI_PAGE_SIZE.
 *
 * @start:       start address of the memory area
 * @size:        length in bytes of the memory area
 * @memory_type: type of memory added
 *
 * Return:       status code
 */
efi_status_t efi_add_memory_map(u64 start, u64 size, int memory_type)
{
	u64 pages;

	pages = efi_size_in_pages(size + (start & EFI_PAGE_MASK));
	start &= ~EFI_PAGE_MASK;

	return efi_add_memory_map_pg(start, pages, memory_type, false);
}

/*
 * validate address to be freed
 * Check that the address is within allocated memory:
 * * The address must be in a range of the memory map.
 * * The address may not point to EFI_CONVENTIONAL_MEMORY.
 *
 * Page alignment is not checked as this is not a requirement of efi_free_pool().
 *
 * @addr:              address of page to be freed
 * @must_be_allocated: return success if the page is allocated
 *
 * Return:             status code
 */
static efi_status_t efi_check_allocated(u64 addr, bool must_be_allocated)
{
	struct efi_mem_list *item;

	LIST_FOREACH(item, &efi_mem, link) {
		u64 start = item->desc.physical_start;
		u64 end = start + (item->desc.num_pages << EFI_PAGE_SHIFT);

		if (addr >= start && addr < end) {
			if (must_be_allocated ^
			    (item->desc.type == EFI_CONVENTIONAL_MEMORY))
				return EFI_SUCCESS;
			else
				return EFI_NOT_FOUND;
		}
	}

	return EFI_NOT_FOUND;
}

/*
 * find free memory pages
 *
 * @len:      size of memory area needed
 * @max_addr: highest address to allocate
 * Return:    pointer to free memory area or 0
 */
static uint64_t efi_find_free_memory(uint64_t len, uint64_t max_addr)
{
	/*
	 * Prealign input max address, so we simplify our matching
	 * logic below and can just reuse it as return pointer.
	 */
	max_addr &= ~EFI_PAGE_MASK;

	struct efi_mem_list *lmem;
	LIST_FOREACH(lmem, &efi_mem, link) {
		struct efi_mem_desc *desc = &lmem->desc;
		uint64_t desc_len = desc->num_pages << EFI_PAGE_SHIFT;
		uint64_t desc_end = desc->physical_start + desc_len;
		uint64_t curmax = MIN(max_addr, desc_end);
		uint64_t ret = curmax - len;

		// We only take memory from free RAM
		if (desc->type != EFI_CONVENTIONAL_MEMORY)
			continue;

		// Out of bounds for max_addr
		if ((ret + len) > max_addr)
			continue;

		// Out of bounds for upper map limit
		if ((ret + len) > desc_end)
			continue;

		// Out of bounds for lower map limit
		if (ret < desc->physical_start)
			continue;

		// Return the highest address in this map within bounds
		return ret;
	}

	return 0;
}

/*
 * allocate memory pages
 *
 * @type:        type of allocation to be performed
 * @memory_type: usage type of the allocated memory
 * @pages:       number of pages to be allocated
 * @memory:      allocated memory
 * Return:       status code
 */
efi_status_t efi_allocate_pages(enum efi_allocate_type type,
				enum efi_memory_type memory_type,
				size_t pages, uint64_t *memory)
{
	u64 len = pages << EFI_PAGE_SHIFT;
	efi_status_t ret;
	uint64_t addr;

	// Check import parameters
	if (memory_type >= EFI_PERSISTENT_MEMORY_TYPE &&
	    memory_type <= 0x6FFFFFFF)
		return EFI_INVALID_PARAMETER;
	if (!memory)
		return EFI_INVALID_PARAMETER;

	switch (type) {
	case EFI_ALLOCATE_ANY_PAGES:
		// Any page
		addr = efi_find_free_memory(len, -1ULL);
		if (!addr)
			return EFI_OUT_OF_RESOURCES;
		break;
	case EFI_ALLOCATE_MAX_ADDRESS:
		// Max address
		addr = efi_find_free_memory(len, *memory);
		if (!addr)
			return EFI_OUT_OF_RESOURCES;
		break;
	case EFI_ALLOCATE_ADDRESS:
		if (*memory & EFI_PAGE_MASK)
			return EFI_NOT_FOUND;
		// Exact address, reserve it. The addr is already in *memory.
		ret = efi_check_allocated(*memory, false);
		if (ret != EFI_SUCCESS)
			return EFI_NOT_FOUND;
		addr = *memory;
		break;
	default:
		// UEFI doesn't specify other allocation types
		return EFI_INVALID_PARAMETER;
	}

	// Reserve that map in our memory maps
	ret = efi_add_memory_map_pg(addr, pages, memory_type, true);
	if (ret != EFI_SUCCESS)
		// Map would overlap, bail out
		return  EFI_OUT_OF_RESOURCES;

	*memory = addr;

	return EFI_SUCCESS;
}

/*
 * free memory pages
 *
 * @memory: start of the memory area to be freed
 * @pages:  number of pages to be freed
 * Return:  status code
 */
efi_status_t efi_free_pages(uint64_t memory, size_t pages)
{
	efi_status_t ret;

	ret = efi_check_allocated(memory, true);
	if (ret != EFI_SUCCESS)
		return ret;

	// Sanity check
	if (!memory || (memory & EFI_PAGE_MASK) || !pages) {
		printf("%s: illegal free 0x%llx, 0x%zx\n", __func__,
		       memory, pages);
		return EFI_INVALID_PARAMETER;
	}

	ret = efi_add_memory_map_pg(memory, pages, EFI_CONVENTIONAL_MEMORY,
				    false);
	if (ret != EFI_SUCCESS)
		return EFI_NOT_FOUND;

	return ret;
}

/*
 * allocate aligned memory pages
 *
 * @len:         len in bytes
 * @memory_type: usage type of the allocated memory
 * @align:       alignment in bytes
 * Return:       aligned memory or NULL
 */
void *efi_alloc_aligned_pages(u64 len, int memory_type, size_t align)
{
	u64 req_pages = efi_size_in_pages(len);
	u64 true_pages = req_pages + efi_size_in_pages(align) - 1;
	u64 free_pages;
	u64 aligned_mem;
	efi_status_t r;
	u64 mem;

	// align must be zero or a power of two
	if (align & (align - 1))
		return NULL;

	// Check for overflow
	if (true_pages < req_pages)
		return NULL;

	if (align < EFI_PAGE_SIZE) {
		r = efi_allocate_pages(EFI_ALLOCATE_ANY_PAGES, memory_type,
				       req_pages, &mem);
		return (r == EFI_SUCCESS) ? (void *)(uintptr_t)mem : NULL;
	}

	r = efi_allocate_pages(EFI_ALLOCATE_ANY_PAGES, memory_type,
			       true_pages, &mem);
	if (r != EFI_SUCCESS)
		return NULL;

	aligned_mem = ALIGN(mem, align);
	// Free pages before alignment
	free_pages = efi_size_in_pages(aligned_mem - mem);
	if (free_pages)
		efi_free_pages(mem, free_pages);

	// Free trailing pages
	free_pages = true_pages - (req_pages + free_pages);
	if (free_pages) {
		mem = aligned_mem + req_pages * EFI_PAGE_SIZE;
		efi_free_pages(mem, free_pages);
	}

	return (void *)(uintptr_t)aligned_mem;
}

/*
 * efi_allocate_pool - allocate memory from pool
 *
 * @pool_type: type of the pool from which memory is to be allocated
 * @size:      number of bytes to be allocated
 * @buffer:    allocated memory
 * Return:     status code
 */
efi_status_t efi_allocate_pool(enum efi_memory_type pool_type, size_t size, void **buffer)
{
	efi_status_t r;
	u64 addr;
	struct efi_pool_allocation *alloc;
	u64 num_pages = efi_size_in_pages(size +
					  sizeof(struct efi_pool_allocation));

	if (!buffer)
		return EFI_INVALID_PARAMETER;

	if (size == 0) {
		*buffer = NULL;
		return EFI_SUCCESS;
	}

	r = efi_allocate_pages(EFI_ALLOCATE_ANY_PAGES, pool_type, num_pages,
			       &addr);
	if (r == EFI_SUCCESS) {
		alloc = (struct efi_pool_allocation *)(uintptr_t)addr;
		alloc->num_pages = num_pages;
		alloc->checksum = checksum(alloc);
		*buffer = alloc->data;
	}

	return r;
}

/*
 * allocate boot services data pool memory
 *
 * Allocate memory from pool and zero it out.
 *
 * @size:  number of bytes to allocate
 * Return: pointer to allocated memory or NULL
 */
void *efi_alloc(size_t size)
{
	void *buf;

	if (efi_allocate_pool(EFI_BOOT_SERVICES_DATA, size, &buf) !=
	    EFI_SUCCESS) {
		printf("out of memory");
		return NULL;
	}
	memset(buf, 0, size);

	return buf;
}

/*
 * free memory from pool
 *
 * @buffer: start of memory to be freed
 * Return:  status code
 */
efi_status_t efi_free_pool(void *buffer)
{
	efi_status_t ret;
	struct efi_pool_allocation *alloc;

	if (!buffer)
		return EFI_INVALID_PARAMETER;

	ret = efi_check_allocated((uintptr_t)buffer, true);
	if (ret != EFI_SUCCESS)
		return ret;

	alloc = container_of(buffer, struct efi_pool_allocation, data);

	// Check that this memory was allocated by efi_allocate_pool()
	if (((uintptr_t)alloc & EFI_PAGE_MASK) ||
	    alloc->checksum != checksum(alloc)) {
		printf("%s: illegal free 0x%p\n", __func__, buffer);
		return EFI_INVALID_PARAMETER;
	}
	// Avoid double free
	alloc->checksum = 0;

	ret = efi_free_pages((uintptr_t)alloc, alloc->num_pages);

	return ret;
}

/*
 * get map describing memory usage.
 *
 * @memory_map_size:    on entry the size, in bytes, of the memory map buffer,
 *                      on exit the size of the copied memory map
 * @memory_map:         buffer to which the memory map is written
 * @map_key:            key for the memory map
 * @descriptor_size:    size of an individual memory descriptor
 * @descriptor_version: version number of the memory descriptor structure
 *
 * Return:              status code
 */
static efi_status_t efi_get_memory_map(size_t *memory_map_size,
				struct efi_mem_desc *memory_map,
				size_t *map_key,
				size_t *descriptor_size,
				uint32_t *descriptor_version)
{
	size_t map_size = 0;
	int map_entries = 0;
	size_t provided_map_size;

	if (!memory_map_size)
		return EFI_INVALID_PARAMETER;

	provided_map_size = *memory_map_size;

	struct efi_mem_list *lmem;
	LIST_FOREACH(lmem, &efi_mem, link)
		map_entries++;

	map_size = map_entries * sizeof(struct efi_mem_desc);

	*memory_map_size = map_size;

	if (descriptor_size)
		*descriptor_size = sizeof(struct efi_mem_desc);

	if (descriptor_version)
		*descriptor_version = EFI_MEMORY_DESCRIPTOR_VERSION;

	if (provided_map_size < map_size)
		return EFI_BUFFER_TOO_SMALL;

	if (!memory_map)
		return EFI_INVALID_PARAMETER;

	// Copy list into array
	// Return the list in ascending order
	memory_map = &memory_map[map_entries - 1];

	LIST_FOREACH(lmem, &efi_mem, link) {
		*memory_map = lmem->desc;
		memory_map--;
	}

	if (map_key)
		*map_key = efi_memory_map_key;

	return EFI_SUCCESS;
}

/*
 * get map describing memory usage
 * This function implements the GetMemoryMap service.
 * See the Unified Extensible Firmware Interface (UEFI) specification for
 * details.
 *
 * @memory_map_size:    on entry the size, in bytes, of the memory map buffer,
 *                      on exit the size of the copied memory map
 * @memory_map:         buffer to which the memory map is written
 * @map_key:            key for the memory map
 * @descriptor_size:    size of an individual memory descriptor
 * @descriptor_version: version number of the memory descriptor structure
 *
 * Return: status code
 */
efi_status_t EFIAPI efi_get_memory_map_ext(
					size_t *memory_map_size,
					struct efi_mem_desc *memory_map,
					size_t *map_key,
					size_t *descriptor_size,
					uint32_t *descriptor_version)
{
	efi_status_t r;

	r = efi_get_memory_map(memory_map_size, memory_map, map_key,
			       descriptor_size, descriptor_version);
	return r;
}

/*
 * Free memory pages.
 * This function implements the FreePages service.
 * See the Unified Extensible Firmware Interface (UEFI) specification for
 * details.
 *
 * @memory: start of the memory area to be freed
 * @pages:  number of pages to be freed
 *
 * Return: status code
 */
efi_status_t EFIAPI efi_free_pages_ext(uint64_t memory,
					      size_t pages)
{
	efi_status_t r;

	r = efi_free_pages(memory, pages);
	return r;
}

/*
 * allocate memory from pool
 * This function implements the AllocatePool service.
 * See the Unified Extensible Firmware Interface (UEFI) specification for
 * details.
 *
 * @pool_type: type of the pool from which memory is to be allocated
 * @size:      number of bytes to be allocated
 * @buffer:    allocated memory
 *
 * Return: status code
 */
efi_status_t EFIAPI efi_allocate_pool_ext(int pool_type,
						 size_t size,
						 void **buffer)
{
	return efi_allocate_pool(pool_type, size, buffer);
}

/*
 * free memory from pool
 * This function implements the FreePool service.
 * See the Unified Extensible Firmware Interface (UEFI) specification for
 * details.
 *
 * @buffer: start of memory to be freed
 *
 * Return: status code
 */
efi_status_t EFIAPI efi_free_pool_ext(void *buffer)
{
	return efi_free_pool(buffer);
}

/*
 * allocate memory pages
 * This function implements the AllocatePages service.
 * See the Unified Extensible Firmware Interface (UEFI) specification for
 * details.
 *
 * @type:        type of allocation to be performed
 * @memory_type: usage type of the allocated memory
 * @pages:       number of pages to be allocated
 * @memory:      allocated memory
 *
 * Return: status code
 */
efi_status_t EFIAPI efi_allocate_pages_ext(int type, int memory_type,
						  size_t pages,
						  uint64_t *memory)
{
	efi_status_t r;

	r = efi_allocate_pages(type, memory_type, pages, memory);
	return r;
}

/*
 * allocate map describing memory usage
 * The caller is responsible for calling FreePool() if the call succeeds.
 *
 * @map_size:   size of the memory map
 * @memory_map: buffer to which the memory map is written
 *
 * Return:      status code
 */
efi_status_t efi_get_memory_map_alloc(size_t *map_size,
				      struct efi_mem_desc **memory_map)
{
	efi_status_t ret;

	*memory_map = NULL;
	*map_size = 0;
	ret = efi_get_memory_map(map_size, *memory_map, NULL, NULL, NULL);
	if (ret == EFI_BUFFER_TOO_SMALL) {
		*map_size += sizeof(struct efi_mem_desc); // for the map
		ret = efi_allocate_pool(EFI_BOOT_SERVICES_DATA, *map_size,
					(void **)memory_map);
		if (ret != EFI_SUCCESS)
			return ret;
		ret = efi_get_memory_map(map_size, *memory_map,
					 NULL, NULL, NULL);
		if (ret != EFI_SUCCESS) {
			efi_free_pool(*memory_map);
			*memory_map = NULL;
		}
	}

	return ret;
}

// Add memory regions for leanEFI's memory and for the runtime services code.
int efi_memory_init(void)
{
	unsigned long runtime_start, runtime_end, runtime_pages;
	unsigned long runtime_mask = EFI_PAGE_MASK;

	// Add coreboot
	extern char _ebootservices, _bootservices; // Defined in the ldscript.
	unsigned long uboot_pages = (uintptr_t)((&_ebootservices) - (&_bootservices) + EFI_PAGE_MASK) >> EFI_PAGE_SHIFT;
	efi_add_memory_map_pg((unsigned long)&_bootservices, uboot_pages, EFI_BOOT_SERVICES_CODE, false);

#if defined(__aarch64__)
	/*
	 * Runtime Services must be 64KiB aligned according to the
	 * "AArch64 Platforms" section in the UEFI spec (2.7+).
	 */

	runtime_mask = 0x00010000 - 1; // 64 KB
#endif

	/*
	 * Add Runtime Services. We mark surrounding boottime code as runtime as
	 * well to fulfill the runtime alignment constraints but avoid padding.
	 */
	extern char __efi_runtime_start; // defined in linker script
	extern char __efi_runtime_end;
	runtime_start = (unsigned long)(&__efi_runtime_start) & ~runtime_mask;
	runtime_end   = (unsigned long)(&__efi_runtime_end);
	runtime_end   = (runtime_end + runtime_mask) & ~runtime_mask;
	runtime_pages = (runtime_end - runtime_start) >> EFI_PAGE_SHIFT;
	efi_add_memory_map_pg(runtime_start, runtime_pages, EFI_RUNTIME_SERVICES_CODE, false);
	return 0;
}

/*
 * copy memory
 * This function implements the CopyMem service.
 * See the Unified Extensible Firmware Interface (UEFI) specification for details.
 *
 * @destination: destination of the copy operation
 * @source:      source of the copy operation
 * @length:      number of bytes to copy
 */
void EFIAPI efi_copy_mem(void *destination, const void *source,
				size_t length)
{
	memmove(destination, source, length);
}

/*
 * Fill memory with a byte value.
 * This function implements the SetMem service.
 * See the Unified Extensible Firmware Interface (UEFI) specification for details.
 *
 * @buffer: buffer to fill
 * @size:   size of buffer in bytes
 * @value:  byte to copy to the buffer
 */
void EFIAPI efi_set_mem(void *buffer, size_t size, uint8_t value)
{
	memset(buffer, value, size);
}
