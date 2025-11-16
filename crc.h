// SPDX-License-Identifier: GPL-2.0+

#ifndef EFI_CRC
#define EFI_CRC

#include <stdint.h>

uint32_t crc32(uint32_t crc, const unsigned char *p, unsigned int len);

#endif
