# mark section as allocatable 'a' so that objcopy doesn't throw this section out when
# converting leanEFI ELF to binary
.section .fdt, "a"

.incbin CONFIG_LEANEFI_FDT_PATH
