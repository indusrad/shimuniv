// SPDX-License-Identifier: GPL-2.0+

/*
 * Copyright (C) 1999 VA Linux Systems
 * Copyright (C) 1999 Walt Drummond <drummond@valinux.com>
 * Copyright (C) 1999, 2002-2003 Hewlett-Packard Co.
 * David Mosberger-Tang <davidm@hpl.hp.com>
 * Stephane Eranian <eranian@hpl.hp.com>
 *  Copyright (c) 2023 ARM Ltd.
 */

#ifndef EFI_ENUM_H
#define EFI_ENUM_H

// Types and defines for EFI CreateEvent
enum efi_timer_delay {
	EFI_TIMER_STOP = 0,
	EFI_TIMER_PERIODIC = 1,
	EFI_TIMER_RELATIVE = 2
};

/*
 * enum efi_object_type - type of EFI object
 * In UnloadImage we must be able to identify if the handle relates to a started image.
 */
enum efi_object_type {
	EFI_OBJECT_TYPE_UNDEFINED = 0,     // undefined image type
	EFI_OBJECT_TYPE_LEANEFI_FIRMWARE,  // leanEFI firmware
	EFI_OBJECT_TYPE_LOADED_IMAGE,      // loaded image (not started)
	EFI_OBJECT_TYPE_STARTED_IMAGE,     // started image
};

// Allocation types for calls to boottime->allocate_pages
// enum efi_allocate_type - address restriction for memory allocation
enum efi_allocate_type {
	// Allocate any block of sufficient size. Ignore memory address.
	EFI_ALLOCATE_ANY_PAGES,
	// Allocate a memory block with an uppermost address less or equal to the indicated address.
	EFI_ALLOCATE_MAX_ADDRESS,
	// Allocate a memory block starting at the indicatged address.
	EFI_ALLOCATE_ADDRESS,
	// Value use for range checking.
	EFI_MAX_ALLOCATE_TYPE,
};

// Enumeration of memory types introduced in UEFI
enum efi_memory_type {
	EFI_RESERVED_MEMORY_TYPE,
	// The code portions of a loaded application.
	// (Note that UEFI OS loaders are UEFI applications.)
	EFI_LOADER_CODE,
	// The data portions of a loaded application and
	// the default data allocation type used by an application
	// to allocate pool memory.
	EFI_LOADER_DATA,
	// The code portions of a loaded Boot Services Driver
	EFI_BOOT_SERVICES_CODE,
	// The data portions of a loaded Boot Services Driver and
	// the default data allocation type used by a Boot Services
	// Driver to allocate pool memory.
	EFI_BOOT_SERVICES_DATA,
	// The code portions of a loaded Runtime Services Driver
	EFI_RUNTIME_SERVICES_CODE,
	// The data portions of a loaded Runtime Services Driver and
	// the default data allocation type used by a Runtime Services
	// Driver to allocate pool memory.
	EFI_RUNTIME_SERVICES_DATA,
	// Free (unallocated) memory
	EFI_CONVENTIONAL_MEMORY,
	// Memory in which errors have been detected
	EFI_UNUSABLE_MEMORY,
	// Memory that holds the ACPI tables
	EFI_ACPI_RECLAIM_MEMORY,
	// Address space reserved for use by the firmware
	EFI_ACPI_MEMORY_NVS,
	// Used by system firmware to request that a memory-mapped IO region
	// be mapped by the OS to a virtual address so it can be accessed by
	// EFI runtime services.
	EFI_MMAP_IO,
	// System memory-mapped IO region that is used to translate
	// memory cycles to IO cycles by the processor.
	EFI_MMAP_IO_PORT,
	// Address space reserved by the firmware for code that is part of the processor.
	EFI_PAL_CODE,
	// Byte addressable non-volatile memory.
	EFI_PERSISTENT_MEMORY_TYPE,
	// Unaccepted memory must be accepted by boot target before usage.
	EFI_UNACCEPTED_MEMORY_TYPE,

	EFI_MAX_MEMORY_TYPE,
};

enum efi_locate_search_type {
	ALL_HANDLES,
	BY_REGISTER_NOTIFY,
	BY_PROTOCOL
};

// Types and defines for EFI ResetSystem
enum efi_reset_type {
	EFI_RESET_COLD = 0,
	EFI_RESET_WARM = 1,
	EFI_RESET_SHUTDOWN = 2,
	EFI_RESET_PLATFORM_SPECIFIC = 3,
};

#endif // EFI_ENUM_H
