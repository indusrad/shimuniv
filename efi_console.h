// SPDX-License-Identifier: GPL-2.0+

#ifndef EFI_CONSOLE
#define EFI_CONSOLE

#include "efi_defines.h"
#include <stdbool.h>

struct efi_simple_text_output_protocol {
	efi_status_t (EFIAPI *reset)(
		struct efi_simple_text_output_protocol *this,
		char extended_verification);
	efi_status_t (EFIAPI *output_string)(
		struct efi_simple_text_output_protocol *this,
		const u16 *str);
	efi_status_t (EFIAPI *test_string)(
		struct efi_simple_text_output_protocol *this,
		const u16 *str);
	efi_status_t(EFIAPI *query_mode)(
		struct efi_simple_text_output_protocol *this,
		unsigned long mode_number, unsigned long *columns,
		unsigned long *rows);
	efi_status_t(EFIAPI *set_mode)(
		struct efi_simple_text_output_protocol *this,
		unsigned long mode_number);
	efi_status_t(EFIAPI *set_attribute)(
		struct efi_simple_text_output_protocol *this,
		unsigned long attribute);
	efi_status_t(EFIAPI *clear_screen) (
		struct efi_simple_text_output_protocol *this);
	efi_status_t(EFIAPI *set_cursor_position) (
		struct efi_simple_text_output_protocol *this,
		unsigned long column, unsigned long row);
	efi_status_t(EFIAPI *enable_cursor)(
		struct efi_simple_text_output_protocol *this,
		bool enable);
	struct simple_text_output_mode *mode;
};

efi_status_t EFIAPI efi_cout_output_string(
	struct efi_simple_text_output_protocol *this,
	const u16 *string);

#endif
