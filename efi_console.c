// SPDX-License-Identifier: GPL-2.0+
/*
 *  EFI application console interface
 *
 *  Copyright (c) 2016 Alexander Graf
 *  Copyright (C) 2023 ARM Ltd.
 *
 * This file is derived from the U-Boot project
 */

#include "efi_console.h"
#include "efi_charset.h"
#include <libpayload.h>

/**
 * efi_cout_output_string() - write Unicode string to console
 *
 * This function implements the OutputString service of the simple text output
 * protocol. See the Unified Extensible Firmware Interface (UEFI) specification
 * for details.
 *
 * @this:	simple text output protocol
 * @string:	u16 string
 * Return:	status code
 */
efi_status_t EFIAPI efi_cout_output_string(
			struct efi_simple_text_output_protocol *this,
			const u16 *string)
{
	if (!this || !string)
		return EFI_INVALID_PARAMETER;

	int buf_size = utf16_utf8_strlen(string) + 1;
	char *buf = malloc(buf_size);
	if (!buf)
		return EFI_OUT_OF_RESOURCES;

	char *pos = buf;
	utf16_utf8_strncpy(&pos, string, buf_size);
	puts(buf);
	free(buf);

	return EFI_SUCCESS;
}
