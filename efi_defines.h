// SPDX-License-Identifier: GPL-2.0+

/*
 * Copyright (C) 1999 VA Linux Systems
 * Copyright (C) 1999 Walt Drummond <drummond@valinux.com>
 * Copyright (C) 1999, 2002-2003 Hewlett-Packard Co.
 * David Mosberger-Tang <davidm@hpl.hp.com>
 * Stephane Eranian <eranian@hpl.hp.com>
 *  Copyright (c) 2023 ARM Ltd.
 */

#ifndef EFI_DEFINES
#define EFI_DEFINES

#include <stdio.h>
#include <stdarg.h>

//TODO properly sort this file

#ifdef CONFIG_LP_ARCH_ARM64
  #define BITS_PER_LONG 64
#elif CONFIG_LP_ARCH_ARM || CONFIG_LP_ARCH_X86
  #define BITS_PER_LONG 32
#else
  #error "unknown architecture"
#endif

typedef unsigned long efi_status_t;
#define EFI_ERROR_BIT (1UL << (BITS_PER_LONG - 1))

// Status codes returned by EFI protocols
#define EFI_SUCCESS              0
#define EFI_LOAD_ERROR           (EFI_ERROR_BIT | 1)
#define EFI_INVALID_PARAMETER    (EFI_ERROR_BIT | 2)
#define EFI_UNSUPPORTED          (EFI_ERROR_BIT | 3)
#define EFI_BAD_BUFFER_SIZE      (EFI_ERROR_BIT | 4)
#define EFI_BUFFER_TOO_SMALL     (EFI_ERROR_BIT | 5)
#define EFI_NOT_READY            (EFI_ERROR_BIT | 6)
#define EFI_DEVICE_ERROR         (EFI_ERROR_BIT | 7)
#define EFI_WRITE_PROTECTED      (EFI_ERROR_BIT | 8)
#define EFI_OUT_OF_RESOURCES     (EFI_ERROR_BIT | 9)
#define EFI_VOLUME_CORRUPTED     (EFI_ERROR_BIT | 10)
#define EFI_VOLUME_FULL          (EFI_ERROR_BIT | 11)
#define EFI_NO_MEDIA             (EFI_ERROR_BIT | 12)
#define EFI_MEDIA_CHANGED        (EFI_ERROR_BIT | 13)
#define EFI_NOT_FOUND            (EFI_ERROR_BIT | 14)
#define EFI_ACCESS_DENIED        (EFI_ERROR_BIT | 15)
#define EFI_NO_RESPONSE          (EFI_ERROR_BIT | 16)
#define EFI_NO_MAPPING           (EFI_ERROR_BIT | 17)
#define EFI_TIMEOUT              (EFI_ERROR_BIT | 18)
#define EFI_NOT_STARTED          (EFI_ERROR_BIT | 19)
#define EFI_ALREADY_STARTED      (EFI_ERROR_BIT | 20)
#define EFI_ABORTED              (EFI_ERROR_BIT | 21)
#define EFI_ICMP_ERROR           (EFI_ERROR_BIT | 22)
#define EFI_TFTP_ERROR           (EFI_ERROR_BIT | 23)
#define EFI_PROTOCOL_ERROR       (EFI_ERROR_BIT | 24)
#define EFI_INCOMPATIBLE_VERSION (EFI_ERROR_BIT | 25)
#define EFI_SECURITY_VIOLATION   (EFI_ERROR_BIT | 26)
#define EFI_CRC_ERROR            (EFI_ERROR_BIT | 27)
#define EFI_END_OF_MEDIA         (EFI_ERROR_BIT | 28)
#define EFI_END_OF_FILE          (EFI_ERROR_BIT | 31)
#define EFI_INVALID_LANGUAGE     (EFI_ERROR_BIT | 32)
#define EFI_COMPROMISED_DATA     (EFI_ERROR_BIT | 33)
#define EFI_IP_ADDRESS_CONFLICT  (EFI_ERROR_BIT | 34)
#define EFI_HTTP_ERROR           (EFI_ERROR_BIT | 35)


/*
 * EFI on x86_64 uses the Microsoft ABI which is not the default for GCC.
 * There are two scenarios for EFI on x86_64: building a 64-bit EFI stub
 * codes (CONFIG_EFI_STUB_64BIT) and building a 64-bit U-Boot (CONFIG_X86_64).
 * Either needs to be properly built with the '-m64' compiler flag, and hence
 * it is enough to only check the compiler provided define __x86_64__ here.
 */
#ifdef __x86_64__
#define EFIAPI __attribute__((ms_abi))
#define efi_va_list __builtin_ms_va_list
#define efi_va_start __builtin_ms_va_start
#define efi_va_copy __builtin_ms_va_copy
#define efi_va_arg __builtin_va_arg
#define efi_va_end __builtin_ms_va_end
#else
#define EFIAPI
#define efi_va_list va_list
#define efi_va_start va_start
#define efi_va_copy va_copy
#define efi_va_arg va_arg
#define efi_va_end va_end
#endif // __x86_64__

#define EFI_GUID(a, b, c, d0, d1, d2, d3, d4, d5, d6, d7) \
	{{ (a) & 0xff, ((a) >> 8) & 0xff, ((a) >> 16) & 0xff, \
		((a) >> 24) & 0xff, \
		(b) & 0xff, ((b) >> 8) & 0xff, \
		(c) & 0xff, ((c) >> 8) & 0xff, \
		(d0), (d1), (d2), (d3), (d4), (d5), (d6), (d7) } }

// Attribute values
#define EFI_MEMORY_UC		 ((u64)0x0000000000000001ULL) // uncached
#define EFI_MEMORY_WC		 ((u64)0x0000000000000002ULL) // write-coalescing
#define EFI_MEMORY_WT		 ((u64)0x0000000000000004ULL) // write-through
#define EFI_MEMORY_WB		 ((u64)0x0000000000000008ULL) // write-back
#define EFI_MEMORY_UCE		 ((u64)0x0000000000000010ULL) // uncached, exported
#define EFI_MEMORY_WP		 ((u64)0x0000000000001000ULL) // write-protect
#define EFI_MEMORY_RP		 ((u64)0x0000000000002000ULL) // read-protect
#define EFI_MEMORY_XP		 ((u64)0x0000000000004000ULL) // execute-protect
#define EFI_MEMORY_NV		 ((u64)0x0000000000008000ULL) // non-volatile
#define EFI_MEMORY_MORE_RELIABLE ((u64)0x0000000000010000ULL) // higher reliability
#define EFI_MEMORY_RO		 ((u64)0x0000000000020000ULL) // read-only
#define EFI_MEMORY_SP		 ((u64)0x0000000000040000ULL) // specific-purpose memory (SPM)
#define EFI_MEMORY_CPU_CRYPTO	 ((u64)0x0000000000080000ULL) // cryptographically protectable
#define EFI_MEMORY_RUNTIME	 ((u64)0x8000000000000000ULL) // range requires runtime mapping
#define EFI_MEM_DESC_VERSION     1

#define EFI_PAGE_SHIFT 12
#define EFI_PAGE_SIZE  (1ULL << EFI_PAGE_SHIFT)
#define EFI_PAGE_MASK  (EFI_PAGE_SIZE - 1)


#define EFI_MEMORY_DESCRIPTOR_VERSION 1

#define aligned_u64 u64 __aligned(8)

/*
 * This macro indicates that a variable should go into the EFI runtime section, and thus
 * still be available when the OS is running.
 * Only use on variables not declared const.
 *
 * Example:
 *   static __efi_runtime_data my_computed_table[256];
 */
#define __efi_runtime_data __attribute__((used, __section__(".data.efi_runtime")))

/*
 * This macro indicates that a variable is read-only (const) and should go into
 * the EFI runtime section, and thus still be available when the OS is running.
 * Only use on variables also declared const.
 *
 * Example:
 *   static const __efi_runtime_rodata my_const_table[] = { 1, 2, 3 };
 */
#define __efi_runtime_rodata __attribute__((used, __section__(".rodata.efi_runtime")))

/*
 * This macro indicates that a function should go into the EFI runtime section
 * and thus still be available when the OS is running.
 *
 * Example:
 *   static __efi_runtime compute_my_table(void);
 */
#define __efi_runtime __attribute__((used, __section__(".text.efi_runtime")))

// Maximum number of configuration tables
#define EFI_MAX_CONFIGURATION_TABLES 16

// GUID used by the root node
#define LEANEFI_GUID \
	EFI_GUID(0x869be981, 0xafdd, 0x4e65, \
		 0x80, 0xa5, 0x63, 0xa1, 0x63, 0x59, 0x1c, 0x82)

/*
 * This macro returns the number of EFI memory pages required to hold 'size' bytes.
 *
 * @size:  size in bytes
 * Return: size in pages
 */
#define efi_size_in_pages(size) (((size) + EFI_PAGE_MASK) >> EFI_PAGE_SHIFT)

#define EFI_DP_TYPE(_dp, _type, _subtype) \
	(((_dp)->type == DEVICE_PATH_TYPE_##_type) && \
	 ((_dp)->sub_type == DEVICE_PATH_SUB_TYPE_##_subtype))

// UEFI spec version 2.9
#define EFI_SPECIFICATION_VERSION (2 << 16 | 100)

#define EFI_BOOT_SERVICES_SIGNATURE 0x56524553544f4f42

#define EFI_NATIVE_INTERFACE 0x00000000

#define EFI_OPEN_PROTOCOL_BY_HANDLE_PROTOCOL  0x00000001
#define EFI_OPEN_PROTOCOL_GET_PROTOCOL        0x00000002
#define EFI_OPEN_PROTOCOL_TEST_PROTOCOL       0x00000004
#define EFI_OPEN_PROTOCOL_EXCLUSIVE           0x00000020

// EFI Runtime Services table
#define EFI_RUNTIME_SERVICES_SIGNATURE 0x56524553544e5552ULL

#define EFI_CONFORMANCE_PROFILES_TABLE_GUID \
	EFI_GUID(0x36122546, 0xf7ef, 0x4c8f, 0xbd, 0x9b, \
		 0xeb, 0x85, 0x25, 0xb5, 0x0c, 0x0b)

#define EFI_CONFORMANCE_PROFILES_TABLE_VERSION 1

#define EFI_CONFORMANCE_PROFILE_EBBR_2_1_GUID \
	EFI_GUID(0xcce33c35, 0x74ac, 0x4087, 0xbc, 0xe7, \
		 0x8b, 0x29, 0xb0, 0x2e, 0xeb, 0x27)

#define EFI_RT_SUPPORTED_GET_TIME			0x0001
#define EFI_RT_SUPPORTED_SET_TIME			0x0002
#define EFI_RT_SUPPORTED_GET_WAKEUP_TIME		0x0004
#define EFI_RT_SUPPORTED_SET_WAKEUP_TIME		0x0008
#define EFI_RT_SUPPORTED_GET_VARIABLE			0x0010
#define EFI_RT_SUPPORTED_GET_NEXT_VARIABLE_NAME		0x0020
#define EFI_RT_SUPPORTED_SET_VARIABLE			0x0040
#define EFI_RT_SUPPORTED_SET_VIRTUAL_ADDRESS_MAP	0x0080
#define EFI_RT_SUPPORTED_CONVERT_POINTER		0x0100
#define EFI_RT_SUPPORTED_GET_NEXT_HIGH_MONOTONIC_COUNT	0x0200
#define EFI_RT_SUPPORTED_RESET_SYSTEM			0x0400
#define EFI_RT_SUPPORTED_UPDATE_CAPSULE			0x0800
#define EFI_RT_SUPPORTED_QUERY_CAPSULE_CAPABILITIES	0x1000
#define EFI_RT_SUPPORTED_QUERY_VARIABLE_INFO		0x2000

#define EFI_RT_PROPERTIES_TABLE_GUID \
	EFI_GUID(0xeb66918a, 0x7eef, 0x402a, 0x84, 0x2e, \
		 0x93, 0x1d, 0x21, 0xc3, 0x8a, 0xe9)

#define EFI_RT_PROPERTIES_TABLE_VERSION 0x1

#define EFI_OPTIONAL_PTR 0x00000001


// EFI Configuration Table and GUID definitions
// ============================================


#define NULL_GUID \
	EFI_GUID(0x00000000, 0x0000, 0x0000, 0x00, 0x00, \
		 0x00, 0x00, 0x00, 0x00, 0x00, 0x00)

#define EFI_ACPI_TABLE_GUID \
	EFI_GUID(0x8868e871, 0xe4f1, 0x11d3, \
		 0xbc, 0x22, 0x00, 0x80, 0xc7, 0x3c, 0x88, 0x81)

#define SMBIOS_TABLE_GUID \
	EFI_GUID(0xeb9d2d31, 0x2d88, 0x11d3,  \
		 0x9a, 0x16, 0x00, 0x90, 0x27, 0x3f, 0xc1, 0x4d)

#define SMBIOS3_TABLE_GUID \
	EFI_GUID(0xf2fd1544, 0x9794, 0x4a2c,  \
		0x99, 0x2e, 0xe5, 0xbb, 0xcf, 0x20, 0xe3, 0x94)

#define EFI_LOAD_FILE_PROTOCOL_GUID \
	EFI_GUID(0x56ec3091, 0x954c, 0x11d2, \
		 0x8e, 0x3f, 0x00, 0xa0, 0xc9, 0x69, 0x72, 0x3b)

#define EFI_LOAD_FILE2_PROTOCOL_GUID \
	EFI_GUID(0x4006c0c1, 0xfcb3, 0x403e, \
		 0x99, 0x6d, 0x4a, 0x6c, 0x87, 0x24, 0xe0, 0x6d)

#define EFI_RNG_PROTOCOL_GUID \
	EFI_GUID(0x3152bca5, 0xeade, 0x433d, 0x86, 0x2e, \
		 0xc0, 0x1c, 0xdc, 0x29, 0x1f, 0x44)

#define RISCV_EFI_BOOT_PROTOCOL_GUID \
	EFI_GUID(0xccd15fec, 0x6f73, 0x4eec, 0x83, \
		 0x95, 0x3e, 0x69, 0xe4, 0xb9, 0x40, 0xbf)

#define EFI_SYSTEM_TABLE_SIGNATURE ((u64)0x5453595320494249ULL)

#define EFI_LOADED_IMAGE_PROTOCOL_GUID \
	EFI_GUID(0x5b1b31a1, 0x9562, 0x11d2, \
		 0x8e, 0x3f, 0x00, 0xa0, 0xc9, 0x69, 0x72, 0x3b)

#define EFI_LOADED_IMAGE_DEVICE_PATH_PROTOCOL_GUID \
	EFI_GUID(0xbc62157e, 0x3e33, 0x4fec, \
		 0x99, 0x20, 0x2d, 0x3b, 0x36, 0xd7, 0x50, 0xdf)

#define EFI_LOADED_IMAGE_PROTOCOL_REVISION 0x1000

#define EFI_DEVICE_PATH_PROTOCOL_GUID \
	EFI_GUID(0x09576e91, 0x6d3f, 0x11d2, \
		 0x8e, 0x39, 0x00, 0xa0, 0xc9, 0x69, 0x72, 0x3b)

#define DEVICE_PATH_TYPE_END			0x7f
#  define DEVICE_PATH_SUB_TYPE_INSTANCE_END	0x01
#  define DEVICE_PATH_SUB_TYPE_END		0xff

#define DEVICE_PATH_TYPE_HARDWARE_DEVICE	0x01
#  define DEVICE_PATH_SUB_TYPE_MEMORY		0x03
#  define DEVICE_PATH_SUB_TYPE_VENDOR		0x04
#  define DEVICE_PATH_SUB_TYPE_CONTROLLER	0x05

#define DEVICE_PATH_TYPE_ACPI_DEVICE		0x02
#  define DEVICE_PATH_SUB_TYPE_ACPI_DEVICE	0x01

#define DEVICE_PATH_TYPE_MESSAGING_DEVICE	0x03
#  define DEVICE_PATH_SUB_TYPE_MSG_ATAPI	0x01
#  define DEVICE_PATH_SUB_TYPE_MSG_SCSI		0x02
#  define DEVICE_PATH_SUB_TYPE_MSG_USB		0x05
#  define DEVICE_PATH_SUB_TYPE_MSG_MAC_ADDR	0x0b
#  define DEVICE_PATH_SUB_TYPE_MSG_UART		0x0e
#  define DEVICE_PATH_SUB_TYPE_MSG_USB_CLASS	0x0f
#  define DEVICE_PATH_SUB_TYPE_MSG_USB_WWI	0x10
#  define DEVICE_PATH_SUB_TYPE_MSG_SATA		0x12
#  define DEVICE_PATH_SUB_TYPE_MSG_NVME		0x17
#  define DEVICE_PATH_SUB_TYPE_MSG_URI		0x18
#  define DEVICE_PATH_SUB_TYPE_MSG_SD		0x1a
#  define DEVICE_PATH_SUB_TYPE_MSG_MMC		0x1d

#define DEVICE_PATH_TYPE_MEDIA_DEVICE		0x04
#  define DEVICE_PATH_SUB_TYPE_HARD_DRIVE_PATH	0x01
#  define DEVICE_PATH_SUB_TYPE_CDROM_PATH	0x02
#  define DEVICE_PATH_SUB_TYPE_VENDOR_PATH	0x03
#  define DEVICE_PATH_SUB_TYPE_FILE_PATH	0x04

#define EFI_BLOCK_IO_PROTOCOL_GUID \
	EFI_GUID(0x964e5b21, 0x6459, 0x11d2, \
		 0x8e, 0x39, 0x00, 0xa0, 0xc9, 0x69, 0x72, 0x3b)

#define EFI_BLOCK_IO_PROTOCOL_REVISION2	0x00020001
#define EFI_BLOCK_IO_PROTOCOL_REVISION3	0x0002001f

#define EFI_SIMPLE_TEXT_OUTPUT_PROTOCOL_GUID \
	EFI_GUID(0x387477c2, 0x69c7, 0x11d2, \
		 0x8e, 0x39, 0x0, 0xa0, 0xc9, 0x69, 0x72, 0x3b)

#define EFI_SIMPLE_TEXT_INPUT_PROTOCOL_GUID \
	EFI_GUID(0x387477c1, 0x69c7, 0x11d2, \
		 0x8e, 0x39, 0x0, 0xa0, 0xc9, 0x69, 0x72, 0x3b)

#define EFI_SIMPLE_FILE_SYSTEM_PROTOCOL_GUID \
	EFI_GUID(0x964e5b22, 0x6459, 0x11d2, \
		 0x8e, 0x39, 0x0, 0xa0, 0xc9, 0x69, 0x72, 0x3b)

#define EFI_FILE_PROTOCOL_REVISION        0x00010000
#define EFI_FILE_PROTOCOL_REVISION2       0x00020000
#define EFI_FILE_PROTOCOL_LATEST_REVISION EFI_FILE_PROTOCOL_REVISION2

#define EFI_SIMPLE_FILE_SYSTEM_PROTOCOL_REVISION 0x00010000

#define EFI_FILE_INFO_GUID \
	EFI_GUID(0x9576e92, 0x6d3f, 0x11d2, \
		 0x8e, 0x39, 0x0, 0xa0, 0xc9, 0x69, 0x72, 0x3b)

//TODO could be taken from coreboot
#define FW_VERSION 1
#define FW_PATCHLEVEL 1

#endif // EFI_DEFINES
