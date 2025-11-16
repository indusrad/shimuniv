// SPDX-License-Identifier: GPL-2.0+

#ifndef ELF_H
#define ELF_H

#if defined(__aarch64__)
	#define R_AARCH64_RELATIVE 1027
	#define R_RELATIVE         R_AARCH64_RELATIVE
	#define R_MASK             0xffffffffULL
	#define IS_RELA            1
#elif defined(__riscv)
	#define R_RISCV_RELATIVE   3
	#define R_RELATIVE         R_RISCV_RELATIVE
	#define R_MASK             0xffULL
	#define IS_RELA            1
#else
	#error Need to add relocation awareness
#endif

struct elf_rel {
	unsigned long *offset;
	unsigned long info;
};

struct elf_rela {
	unsigned long *offset;
	unsigned long info;
	long addend;
};

#endif
