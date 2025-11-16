// SPDX-License-Identifier: GPL-2.0+
/*
 *  charset conversion utils
 *
 *  Copyright (c) 2017 Rob Clark
 */

#ifndef __CHARSET_H_
#define __CHARSET_H_

#include <stdint.h>
#include <stddef.h>

#define utf16_utf8_strlen(a) utf16_utf8_strnlen((a), SIZE_MAX)

/*
 * length of a truncated utf-16 string after conversion to utf-8
 *
 * @src:    utf-16 string
 * @count:  maximum number of code points to convert
 *
 * Return: length in bytes after conversion to utf-8 without the trailing \0. If an invalid
 *         UTF-16 sequence is hit one byte will be reserved for a replacement character.
 */
size_t utf16_utf8_strnlen(const u16 *src, size_t count);

#define utf16_utf8_strcpy(d, s) utf16_utf8_strncpy((d), (s), SIZE_MAX)

/*
 * copy utf-16 string to utf-8 string
 *
 * @dst:   destination buffer
 * @src:   source buffer
 * @count: maximum number of code points to copy
 *
 * Return: -1 if the input parameters are invalid
 */
int utf16_utf8_strncpy(char **dst, const u16 *src, size_t count);

#endif /* __CHARSET_H_ */
