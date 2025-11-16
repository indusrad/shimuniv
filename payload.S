# mark section as allocatable 'a' so that objcopy doesn't throw this section out when
# converting leanEFI ELF to binary
.section .payload , "a"

.incbin CONFIG_LEANEFI_PAYLOAD_PATH
