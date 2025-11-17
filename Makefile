## SPDX-License-Identifier: GPL-2.0-only

obj := build

all: $(obj)/leanefi.elf

######################### Kconfig ###############################

KCONFIG_AUTOHEADER  = ../../../../build//config.h

include ../../../../.config

######################### xcompile ##############################

ARCH-$(CONFIG_ARCH_ARM64) := arm64
ARCH-$(CONFIG_ARCH_RISCV_RV64) := riscv

include libpayload/libpayload.xcompile

CC := $(CC_$(ARCH-y))
LD := $(LD_$(ARCH-y))
CPP := $(CPP_$(ARCH-y))
OBJCOPY := $(OBJCOPY_$(ARCH-y))

######################### libpayload ############################

LIBPAYLOAD_DIR ?= ../../../libpayload

LIBPAYLOAD_INCLUDE_FLAGS := -I libpayload/include -I libpayload/include/$(ARCH-y) -include libpayload/include/kconfig.h -include libpayload/include/commonlib/bsd/compiler.h

LP_LIB = libpayload/lib/libpayload.a

######################### leanefi ###############################

# this is only used for the pattern rules.
build-dirs = $(obj) $(obj)/arch $(obj)/arch/$(ARCH-y)

INCLUDE_FLAGS := $(LIBPAYLOAD_INCLUDE_FLAGS) -I src/arch/$(ARCH-y) -include $(KCONFIG_AUTOHEADER)

depfile = $(@:.o=.d)
CPPFLAGS := $(INCLUDE_FLAGS)
CFLAGS = -g -Wp,-MMD,$(depfile) -fno-builtin -Wall -Werror -Wextra -nostdlib -I $(ARCH-y) $(INCLUDE_FLAGS)
LD_SCRIPT := $(obj)/arch/$(ARCH-y)/leanefi.ld
LDFLAGS := -no-pie -nostdlib -T $(LD_SCRIPT)

ifeq ($(CONFIG_ARCH_RISCV_RV64), y)
CFLAGS += -mcmodel=medany
endif

OBJECTS-y = \
	crc.o  \
	efi_boot_services.o \
	efi_console.o \
	efi_image_loader.o \
	efi_memory.o \
	efi_object.o \
	efi_protocol.o \
	efi_rng.o \
	efi_root_node.o \
	efi_runtime.o \
	efi_runtime_services.o \
	efi_table.o \
	efi_charset.o \
	arch/$(ARCH-y)/setjmp.S.o \
	main.o
OBJECTS-$(CONFIG_LEANEFI_PAYLOAD) += payload.S.o
OBJECTS-$(CONFIG_LEANEFI_ECPT) += efi_conformance.o
OBJECTS-$(CONFIG_LEANEFI_FDT) += efi_fdt.o
OBJECTS-$(CONFIG_LEANEFI_FDT) += fdt.S.o
OBJS    = $(patsubst %,$(obj)/%,$(OBJECTS-y))

# -include will not complain if it cannot trigger a rule for the *.d files
#  otherwise we would compile our object files before creating our configuration
-include $(OBJS:.o=.d)

strip_quotes = $(strip $(subst ",,$(subst \",,$(1))))
CONFIG_LEANEFI_PAYLOAD_PATH := $(call strip_quotes, $(CONFIG_LEANEFI_PAYLOAD_PATH))

######################### rules ############################

#TODO We should always execute this rule, because we cannot know if libpayload code changed
$(LP_LIB) libpayload/libpayload.xcompile: src/arch/$(ARCH-y)/libpayload.defconfig
	cp $< $(LIBPAYLOAD_DIR)/.config
	$(MAKE) -C $(LIBPAYLOAD_DIR) olddefconfig
	$(MAKE) -C $(LIBPAYLOAD_DIR)
	$(MAKE) -C $(LIBPAYLOAD_DIR) DESTDIR=$(abspath $(CURDIR)) install

$(obj)/%.ld: src/%.ld $(KCONFIG_AUTOHEADER) | $(build-dirs)
	$(CPP) $(CPPFLAGS) -P $< -o $@

$(obj)/%.S.o: src/%.S $(KCONFIG_AUTOHEADER) $(CONFIG_LEANEFI_PAYLOAD_PATH) | $(build-dirs)
	$(CC) $(CFLAGS) -c -o $@ $<

$(obj)/%.o: src/%.c $(KCONFIG_AUTOHEADER) | $(build-dirs)
	$(CC) $(CFLAGS) -c -o $@ $<

$(obj)/leanefi.elf: $(OBJS) $(LP_LIB) $(LD_SCRIPT) | $(obj)
	$(LD) $(LDFLAGS) -o $@ $(OBJS) $(LP_LIB)

$(build-dirs):
	mkdir -p $@

distclean clean:
	rm -rf $(obj) libpayload .config

.PHONY: all clean distclean
