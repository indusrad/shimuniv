// SPDX-License-Identifier: GPL-2.0+
/*
 *  charset conversion utils
 *
 *  Copyright (c) 2017 Rob Clark
 *  Copyright (c) 2023 ARM Ltd.
 *
 * This file is derived from the U-Boot project
 */

#include "efi_charset.h"
#include "efi_defines.h"
#include <stdint.h>
#include <stddef.h>
#include <libpayload.h>

static int utf8_put(s32 code, char **dst)
{
	if (!dst || !*dst)
		return -1;
	if ((code >= 0xD800 && code <= 0xDFFF) || code >= 0x110000)
		return -1;
	if (code <= 0x007F) {
		**dst = code;
	} else {
		if (code <= 0x07FF) {
			**dst = code >> 6 | 0xC0;
		} else {
			if (code < 0x10000) {
				**dst = code >> 12 | 0xE0;
			} else {
				**dst = code >> 18 | 0xF0;
				++*dst;
				**dst = (code >> 12 & 0x3F) | 0x80;
			}
			++*dst;
			**dst = (code >> 6 & 0x3F) | 0x80;
		}
		++*dst;
		**dst = (code & 0x3F) | 0x80;
	}
	++*dst;
	return 0;
}

static s32 utf16_get(const u16 **src)
{
	s32 code, code2;

	if (!src || !*src)
		return -1;
	if (!**src)
		return 0;
	code = **src;
	++*src;
	if (code >= 0xDC00 && code <= 0xDFFF)
		return -1;
	if (code >= 0xD800 && code <= 0xDBFF) {
		if (!**src)
			return -1;
		code &= 0x3ff;
		code <<= 10;
		code += 0x10000;
		code2 = **src;
		++*src;
		if (code2 <= 0xDC00 || code2 >= 0xDFFF)
			return -1;
		code2 &= 0x3ff;
		code += code2;
	}
	return code;
}

size_t utf16_utf8_strnlen(const u16 *src, size_t count)
{
	size_t len = 0;

	for (; *src && count; --count)  {
		s32 code = utf16_get(&src);

		if (!code)
			break;
		if (code < 0)
			// Reserve space for a replacement character
			len += 1;
		else if (code < 0x80)
			len += 1;
		else if (code < 0x800)
			len += 2;
		else if (code < 0x10000)
			len += 3;
		else
			len += 4;
	}
	return len;
}

int utf16_utf8_strncpy(char **dst, const u16 *src, size_t count)
{
	if (!src || !dst || !*dst)
		return -1;

	for (; count && *src; --count) {
		s32 code = utf16_get(&src);

		if (code < 0)
			code = '?';
		utf8_put(code, dst);
	}
	**dst = 0;
	return 0;
}
