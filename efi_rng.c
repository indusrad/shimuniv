// SPDX-License-Identifier: GPL-2.0+
/*
 * Copyright (c) 2019, Linaro Limited
 * Copyright (c) 2023 ARM Ltd.
 *
 * This file is derived from the U-Boot project
 */

#include "efi_rng.h"
#include "efi_defines.h"
#include "efi_protocol.h"
#include <stdlib.h>
#include <time.h>

const efi_guid_t efi_guid_rng_protocol = EFI_RNG_PROTOCOL_GUID;

struct efi_rng_protocol {
	efi_status_t (EFIAPI *get_info)(struct efi_rng_protocol *protocol,
					size_t *rng_algorithm_list_size,
					efi_guid_t *rng_algorithm_list);
	efi_status_t (EFIAPI *get_rng)(struct efi_rng_protocol *protocol,
				       efi_guid_t *rng_algorithm,
				       size_t rng_value_length, uint8_t *rng_value);
};

// EFI random number generation protocol related GUID definitions
#define EFI_RNG_ALGORITHM_RAW \
	EFI_GUID(0xe43176d7, 0xb6e8, 0x4827, 0xb7, 0x84, 0x7f, 0xfd, 0xc4, 0xb6, 0x85, 0x61)

/*
 * get information about random number generation
 * This function implement the GetInfo() service of the EFI random number generator protocol.
 * See the UEFI spec for details.
 *
 * @this:                    random number generator protocol instance
 * @rng_algorithm_list_size: number of random number generation algorithms
 * @rng_algorithm_list:      descriptions of random number generation algorithms
 *
 * Return: status code
 */
static efi_status_t EFIAPI rng_getinfo(struct efi_rng_protocol *this,
				       size_t *rng_algorithm_list_size,
				       efi_guid_t *rng_algorithm_list)
{
	efi_status_t ret = EFI_SUCCESS;
	efi_guid_t rng_algo_guid = EFI_RNG_ALGORITHM_RAW;

	if (!this || !rng_algorithm_list_size) {
		ret = EFI_INVALID_PARAMETER;
		goto back;
	}

	if (!rng_algorithm_list ||
	    *rng_algorithm_list_size < sizeof(*rng_algorithm_list)) {
		*rng_algorithm_list_size = sizeof(*rng_algorithm_list);
		ret = EFI_BUFFER_TOO_SMALL;
		goto back;
	}

	/*
	 * For now, use EFI_RNG_ALGORITHM_RAW as the default
	 * algorithm. If a new algorithm gets added in the
	 * future through a Kconfig, rng_algo_guid will be set
	 * based on that Kconfig option
	 */
	*rng_algorithm_list_size = sizeof(*rng_algorithm_list);
	guidcpy(rng_algorithm_list, &rng_algo_guid);

back:
	return ret;
}

/*
 * get random value
 * This function implement the GetRng() service of the EFI random number generator protocol.
 * See the UEFI spec for details.
 *
 * @this:             random number generator protocol instance
 * @rng_algorithm:    random number generation algorithm
 * @rng_value_length: number of random bytes to generate, buffer length
 * @rng_value:        buffer to receive random bytes
 *
 * Return: status code
 */
static efi_status_t EFIAPI getrng(struct efi_rng_protocol *this,
				  efi_guid_t *rng_algorithm,
				  size_t rng_value_length,
				  uint8_t *rng_value)
{
	const efi_guid_t rng_raw_guid = EFI_RNG_ALGORITHM_RAW;

	if (!this || !rng_value || !rng_value_length) {
		return EFI_INVALID_PARAMETER;
	}

	if (rng_algorithm) {
		printf("RNG algorithm %pUs\n", rng_algorithm);
		if (guidcmp(rng_algorithm, &rng_raw_guid)) {
			return EFI_UNSUPPORTED;
		}
	}

	int seed = time((time_t *)0);
	srand(seed);
	for (size_t i = 0; i < rng_value_length; i++) {
		rng_value[i] = (uint8_t)rand();
	}

	return EFI_SUCCESS;
}

static const struct efi_rng_protocol efi_rng_protocol = {
	.get_info = rng_getinfo,
	.get_rng = getrng,
};

/*
 * register EFI_RNG_PROTOCOL
 * If a RNG device is available, the Random Number Generator Protocol is registered.
 *
 * Return: An error status is only returned if adding the protocol fails.
 */
efi_status_t efi_rng_register(efi_handle_t efi_root)
{
	efi_status_t ret;

	ret = efi_add_protocol(efi_root, &efi_guid_rng_protocol, (void *)&efi_rng_protocol);
	if (ret != EFI_SUCCESS)
		printf("Cannot install EFI_RNG_PROTOCOL\n");

	return ret;
}
