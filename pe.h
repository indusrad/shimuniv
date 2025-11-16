// SPDX-License-Identifier: GPL-2.0+
/*
 *  Portable Executable and Common Object Constants
 *  Portable Executable binary format structures
 *
 *  Copyright (c) 2016 Alexander Graf
 *  Copyright (c) 2018 Heinrich Schuchardt
 *
 *  based on the "Microsoft Portable Executable and Common Object File Format
 *  Specification", revision 11, 2017-01-23
 *
 *  Based on wine code
 *  copied from u-boot and modified
 */

#ifndef _PE_H
#define _PE_H

// Characteristics
#define IMAGE_FILE_RELOCS_STRIPPED         0x0001
#define IMAGE_FILE_EXECUTABLE_IMAGE        0x0002
#define IMAGE_FILE_LINE_NUMS_STRIPPED      0x0004
#define IMAGE_FILE_LOCAL_SYMS_STRIPPED     0x0008
#define IMAGE_FILE_AGGRESSIVE_WS_TRIM      0x0010
#define IMAGE_FILE_LARGE_ADDRESS_AWARE     0x0020
// Reserved                                0x0040
#define IMAGE_FILE_BYTES_REVERSED_LO       0x0080
#define IMAGE_FILE_32BIT_MACHINE           0x0100
#define IMAGE_FILE_DEBUG_STRIPPED          0x0200
#define IMAGE_FILE_REMOVABLE_RUN_FROM_SWAP 0x0400
#define IMAGE_FILE_NET_RUN_FROM_SWAP       0x0800
#define IMAGE_FILE_SYSTEM                  0x1000
#define IMAGE_FILE_DLL                     0x2000
#define IMAGE_FILE_UP_SYSTEM_ONLY          0x4000
#define IMAGE_FILE_BYTES_REVERSED_HI       0x8000

// Machine types
#define IMAGE_FILE_MACHINE_I386    0x014c
#define IMAGE_FILE_MACHINE_ARM     0x01c0
#define IMAGE_FILE_MACHINE_THUMB   0x01c2
#define IMAGE_FILE_MACHINE_ARMNT   0x01c4
#define IMAGE_FILE_MACHINE_AMD64   0x8664
#define IMAGE_FILE_MACHINE_ARM64   0xaa64
#define IMAGE_FILE_MACHINE_RISCV32 0x5032
#define IMAGE_FILE_MACHINE_RISCV64 0x5064

// Header magic constants
#define IMAGE_NT_OPTIONAL_HDR32_MAGIC 0x010b
#define IMAGE_NT_OPTIONAL_HDR64_MAGIC 0x020b
#define IMAGE_DOS_SIGNATURE           0x5a4d     // MZ
#define IMAGE_NT_SIGNATURE            0x00004550 // PE00

// Subsystem type
#define IMAGE_SUBSYSTEM_EFI_APPLICATION         10
#define IMAGE_SUBSYSTEM_EFI_BOOT_SERVICE_DRIVER 11
#define IMAGE_SUBSYSTEM_EFI_RUNTIME_DRIVER      12
#define IMAGE_SUBSYSTEM_EFI_ROM                 13

// Section flags
#define IMAGE_SCN_CNT_CODE                0x00000020
#define IMAGE_SCN_CNT_INITIALIZED_DATA    0x00000040
#define IMAGE_SCN_CNT_UNINITIALIZED_DATA  0x00000080
#define IMAGE_SCN_LNK_NRELOC_OVFL         0x01000000
#define IMAGE_SCN_MEM_DISCARDABLE         0x02000000
#define IMAGE_SCN_MEM_NOT_CACHED          0x04000000
#define IMAGE_SCN_MEM_NOT_PAGED           0x08000000
#define IMAGE_SCN_MEM_SHARED              0x10000000
#define IMAGE_SCN_MEM_EXECUTE             0x20000000
#define IMAGE_SCN_MEM_READ                0x40000000
#define IMAGE_SCN_MEM_WRITE               0x80000000

#define LINUX_ARM64_MAGIC 0x644d5241

struct __packed image_dos_header {
	uint16_t e_magic;    // 00: MZ Header signature
	uint16_t e_cblp;     // 02: Bytes on last page of file
	uint16_t e_cp;       // 04: Pages in file
	uint16_t e_crlc;     // 06: Relocations
	uint16_t e_cparhdr;  // 08: Size of header in paragraphs
	uint16_t e_minalloc; // 0a: Minimum extra paragraphs needed
	uint16_t e_maxalloc; // 0c: Maximum extra paragraphs needed
	uint16_t e_ss;       // 0e: Initial (relative) SS value
	uint16_t e_sp;       // 10: Initial SP value
	uint16_t e_csum;     // 12: Checksum
	uint16_t e_ip;       // 14: Initial IP value
	uint16_t e_cs;       // 16: Initial (relative) CS value
	uint16_t e_lfarlc;   // 18: File address of relocation table
	uint16_t e_ovno;     // 1a: Overlay number
	uint16_t e_res[4];   // 1c: Reserved words
	uint16_t e_oemid;    // 24: OEM identifier (for e_oeminfo)
	uint16_t e_oeminfo;  // 26: OEM information; e_oemid specific
	uint16_t e_res2[10]; // 28: Reserved words
	uint32_t e_lfanew;   // 3c: Offset to extended header
};

//TODO not used: remove
struct __packed image_file_header {
	uint16_t machine;
	uint16_t number_of_sections;
	uint32_t time_date_stamp;
	uint32_t pointer_to_symbol_table;
	uint32_t number_of_symbols;
	uint16_t size_of_optional_header;
	uint16_t characteristics;
};

struct __packed image_data_directory {
	uint32_t virtual_address;
	uint32_t size;
};

#define IMAGE_NUMBEROF_DIRECTORY_ENTRIES 16

struct __packed image_optional_header64 {
	uint16_t magic; // 0x20b
	uint8_t  major_linker_version;
	uint8_t  minor_linker_version;
	uint32_t size_of_code;
	uint32_t size_of_initialized_data;
	uint32_t size_of_uninitialized_data;
	uint32_t address_of_entry_point;
	uint32_t base_of_code;
	uint64_t image_base;
	uint32_t section_alignment;
	uint32_t file_alignment;
	uint16_t major_operating_system_version;
	uint16_t minor_operating_system_version;
	uint16_t major_image_version;
	uint16_t minor_image_version;
	uint16_t major_subsystem_version;
	uint16_t minor_subsystem_version;
	uint32_t win32Version_value;
	uint32_t size_of_image;
	uint32_t size_of_headers;
	uint32_t check_sum;
	uint16_t subsystem;
	uint16_t dll_characteristics;
	uint64_t size_of_stack_reserve;
	uint64_t size_of_stack_commit;
	uint64_t size_of_heap_reserve;
	uint64_t size_of_heap_commit;
	uint32_t loader_flags;
	uint32_t number_of_rva_and_sizes;
	struct image_data_directory data_directory[IMAGE_NUMBEROF_DIRECTORY_ENTRIES];
};

struct __packed image_nt_headers64 {
	uint32_t signature;
	struct image_file_header fileheader;
	struct image_optional_header64 optional_header;
};

struct __packed image_optional_header32 {

	// standard fields

	uint16_t magic; // 0x10b or 0x107
	uint8_t  major_linker_version;
	uint8_t  minor_linker_version;
	uint32_t size_of_code;
	uint32_t size_of_initialized_data;
	uint32_t size_of_uninitialized_data;
	uint32_t address_of_entry_point;
	uint32_t base_of_code;
	uint32_t base_of_data;

	// NT additional fields

	uint32_t image_base;
	uint32_t section_alignment;
	uint32_t file_alignment;
	uint16_t major_operating_system_version;
	uint16_t minor_operating_system_version;
	uint16_t major_image_version;
	uint16_t minor_image_version;
	uint16_t major_subsystem_version;
	uint16_t minor_subsystem_version;
	uint32_t win32Version_value;
	uint32_t size_of_image;
	uint32_t size_of_headers;
	uint32_t check_sum;
	uint16_t subsystem;
	uint16_t dll_characteristics;
	uint32_t size_of_stack_reserve;
	uint32_t size_of_stack_commit;
	uint32_t size_of_heap_reserve;
	uint32_t size_of_heap_commit;
	uint32_t loader_flags;
	uint32_t number_of_rva_and_sizes;
	struct image_data_directory data_directory[IMAGE_NUMBEROF_DIRECTORY_ENTRIES];
	// offset 0xE0
};

struct image_nt_headers32 {
	uint32_t signature; // "PE"\0\0
	struct image_file_header file_header;
	struct image_optional_header32 optional_header;
};

#define IMAGE_SIZEOF_SHORT_NAME 8

struct __packed image_section_header {
	uint8_t name[IMAGE_SIZEOF_SHORT_NAME];
	union {
		uint32_t physical_address;
		uint32_t virtual_size;
	} misc;
	uint32_t virtual_address;
	uint32_t size_of_raw_data;
	uint32_t pointer_to_raw_data;
	uint32_t pointer_to_relocations;
	uint32_t pointer_to_linenumbers;
	uint16_t number_of_relocations;
	uint16_t number_of_linenumbers;
	uint32_t characteristics;
};

// Indices for Optional Header Data Directories
#define IMAGE_DIRECTORY_ENTRY_SECURITY  4
#define IMAGE_DIRECTORY_ENTRY_BASERELOC 5

struct __packed image_base_relocation
{
	uint32_t virtual_address;
	uint32_t size_of_block;
	// WORD TypeOffset[1];
};

struct __packed image_relocation
{
	union {
		uint32_t virtual_address;
		uint32_t reloc_count;
	};
	uint32_t symbol_table_index;
	uint16_t type;
};

#define IMAGE_SIZEOF_RELOCATION 10

// generic relocation types
#define IMAGE_REL_BASED_ABSOLUTE       0
#define IMAGE_REL_BASED_HIGH           1
#define IMAGE_REL_BASED_LOW            2
#define IMAGE_REL_BASED_HIGHLOW        3
#define IMAGE_REL_BASED_HIGHADJ        4
#define IMAGE_REL_BASED_MIPS_JMPADDR   5
#define IMAGE_REL_BASED_ARM_MOV32A     5 // yes, 5 too
#define IMAGE_REL_BASED_ARM_MOV32      5 // yes, 5 too
#define IMAGE_REL_BASED_RISCV_HI20     5 // yes, 5 too
#define IMAGE_REL_BASED_SECTION        6
#define IMAGE_REL_BASED_REL            7
#define IMAGE_REL_BASED_ARM_MOV32T     7 // yes, 7 too
#define IMAGE_REL_BASED_THUMB_MOV32    7 // yes, 7 too
#define IMAGE_REL_BASED_RISCV_LOW12I   7 // yes, 7 too
#define IMAGE_REL_BASED_RISCV_LOW12S   8
#define IMAGE_REL_BASED_MIPS_JMPADDR16 9
#define IMAGE_REL_BASED_IA64_IMM64     9 // yes, 9 too
#define IMAGE_REL_BASED_DIR64          10
#define IMAGE_REL_BASED_HIGH3ADJ       11

// ARM relocation types
#define IMAGE_REL_ARM_ABSOLUTE  0x0000
#define IMAGE_REL_ARM_ADDR      0x0001
#define IMAGE_REL_ARM_ADDR32NB  0x0002
#define IMAGE_REL_ARM_BRANCH24  0x0003
#define IMAGE_REL_ARM_BRANCH11  0x0004
#define IMAGE_REL_ARM_TOKEN     0x0005
#define IMAGE_REL_ARM_GPREL12   0x0006
#define IMAGE_REL_ARM_GPREL7    0x0007
#define IMAGE_REL_ARM_BLX24     0x0008
#define IMAGE_REL_ARM_BLX11     0x0009
#define IMAGE_REL_ARM_SECTION   0x000E
#define IMAGE_REL_ARM_SECREL    0x000F
#define IMAGE_REL_ARM_MOV32A    0x0010
#define IMAGE_REL_ARM_MOV32T    0x0011
#define IMAGE_REL_ARM_BRANCH20T 0x0012
#define IMAGE_REL_ARM_BRANCH24T 0x0014
#define IMAGE_REL_ARM_BLX23T    0x0015

// ARM64 relocation types
#define IMAGE_REL_ARM64_ABSOLUTE       0x0000
#define IMAGE_REL_ARM64_ADDR32         0x0001
#define IMAGE_REL_ARM64_ADDR32NB       0x0002
#define IMAGE_REL_ARM64_BRANCH26       0x0003
#define IMAGE_REL_ARM64_PAGEBASE_REL21 0x0004
#define IMAGE_REL_ARM64_REL21          0x0005
#define IMAGE_REL_ARM64_PAGEOFFSET_12A 0x0006
#define IMAGE_REL_ARM64_PAGEOFFSET_12L 0x0007
#define IMAGE_REL_ARM64_SECREL         0x0008
#define IMAGE_REL_ARM64_SECREL_LOW12A  0x0009
#define IMAGE_REL_ARM64_SECREL_HIGH12A 0x000A
#define IMAGE_REL_ARM64_SECREL_LOW12L  0x000B
#define IMAGE_REL_ARM64_TOKEN          0x000C
#define IMAGE_REL_ARM64_SECTION        0x000D
#define IMAGE_REL_ARM64_ADDR64         0x000E

// AMD64 relocation types
#define IMAGE_REL_AMD64_ABSOLUTE 0x0000
#define IMAGE_REL_AMD64_ADDR64   0x0001
#define IMAGE_REL_AMD64_ADDR32   0x0002
#define IMAGE_REL_AMD64_ADDR32NB 0x0003
#define IMAGE_REL_AMD64_REL32    0x0004
#define IMAGE_REL_AMD64_REL32_1  0x0005
#define IMAGE_REL_AMD64_REL32_2  0x0006
#define IMAGE_REL_AMD64_REL32_3  0x0007
#define IMAGE_REL_AMD64_REL32_4  0x0008
#define IMAGE_REL_AMD64_REL32_5  0x0009
#define IMAGE_REL_AMD64_SECTION  0x000A
#define IMAGE_REL_AMD64_SECREL   0x000B
#define IMAGE_REL_AMD64_SECREL7  0x000C
#define IMAGE_REL_AMD64_TOKEN    0x000D
#define IMAGE_REL_AMD64_SREL32   0x000E
#define IMAGE_REL_AMD64_PAIR     0x000F
#define IMAGE_REL_AMD64_SSPAN32  0x0010

// certificate appended to PE image
struct __packed win_certificate {
	uint32_t dw_length;
	uint16_t w_revision;
	uint16_t w_certificate_type;
	uint8_t b_certificate[];
};

// Definitions for the contents of the certs data block
#define WIN_CERT_TYPE_PKCS_SIGNED_DATA 0x0002
#define WIN_CERT_TYPE_EFI_OKCS115      0x0EF0
#define WIN_CERT_TYPE_EFI_GUID         0x0EF1

#define WIN_CERT_REVISION_1_0 0x0100
#define WIN_CERT_REVISION_2_0 0x0200

#endif // _PE_H
