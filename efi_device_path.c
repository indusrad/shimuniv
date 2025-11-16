// SPDX-License-Identifier: GPL-2.0+

/*
 *  EFI device path
 *
 *  Copyright (c) 2017 Rob Clark
 *  Copyright (C) 2023 ARM Ltd.
 *
 * This file is derived from the U-Boot project
 */

#include "efi_guid.h"
#include "efi_object.h"
#include "efi_device_path.h"
#include "efi_memory.h"
#include "efi_protocol.h"

#include <stdbool.h>
#include <stddef.h>
#include <libpayload.h>

// This list contains all the EFI objects our payload has access to
extern struct efi_object_list efi_obj_list;

// terminating node
const struct efi_device_path dp_end_node = {
	.type     = DEVICE_PATH_TYPE_END,
	.sub_type = DEVICE_PATH_SUB_TYPE_END,
	.length   = sizeof(dp_end_node),
};

// Construct a device-path for memory-mapped image
struct efi_device_path *efi_dp_from_mem(uint32_t memory_type,
					uint64_t start_address,
					uint64_t end_address)
{
	struct efi_device_path_memory *mdp;
	void *buf, *start;

	start = buf = efi_alloc(sizeof(*mdp) + sizeof(dp_end_node));
	if (!buf)
		return NULL;

	mdp = buf;
	mdp->dp.type = DEVICE_PATH_TYPE_HARDWARE_DEVICE;
	mdp->dp.sub_type = DEVICE_PATH_SUB_TYPE_MEMORY;
	mdp->dp.length = sizeof(*mdp);
	mdp->memory_type = memory_type;
	mdp->start_address = start_address;
	mdp->end_address = end_address;
	buf = &mdp[1];

	*((struct efi_device_path *)buf) = dp_end_node;

	return start;
}

// get size of multi-instance device path excluding end node
size_t efi_dp_size(const struct efi_device_path *dp)
{
	const struct efi_device_path *p = dp;

	if (!p)
		return 0;
	while (p->type != DEVICE_PATH_TYPE_END ||
	       p->sub_type != DEVICE_PATH_SUB_TYPE_END)
		p = (void *)p + p->length;

	return (void *)p - (void *)dp;
}

// copy multi-instance device path
struct efi_device_path *efi_dp_dup(const struct efi_device_path *dp)
{
	struct efi_device_path *ndp;
	size_t sz = efi_dp_size(dp) + sizeof(dp_end_node);

	if (!dp)
		return NULL;

	ndp = efi_alloc(sz);
	if (!ndp)
		return NULL;
	memcpy(ndp, dp, sz);

	return ndp;
}

// Iterate to next block in device-path, terminating (returning NULL) at /End* node.
struct efi_device_path *efi_dp_next(const struct efi_device_path *dp)
{
	if (dp == NULL)
		return NULL;
	if (dp->type == DEVICE_PATH_TYPE_END)
		return NULL;
	dp = ((void *)dp) + dp->length;
	if (dp->type == DEVICE_PATH_TYPE_END)
		return NULL;
	return (struct efi_device_path *)dp;
}

/**
 * efi_dp_split_file_path() - split of relative file path from device path
 *
 * Given a device path indicating a file on a device, separate the device
 * path in two: the device path of the actual device and the file path
 * relative to this device.
 *
 * @full_path:   device path including device and file path
 * @device_path: path of the device
 * @file_path:   relative path of the file or NULL if there is none
 * Return:       status code
 */
efi_status_t efi_dp_split_file_path(struct efi_device_path *full_path,
				    struct efi_device_path **device_path,
				    struct efi_device_path **file_path)
{
	struct efi_device_path *p, *dp, *fp = NULL;

	*device_path = NULL;
	*file_path = NULL;
	dp = efi_dp_dup(full_path);
	if (!dp)
		return EFI_OUT_OF_RESOURCES;
	p = dp;
	while (!EFI_DP_TYPE(p, MEDIA_DEVICE, FILE_PATH)) {
		p = efi_dp_next(p);
		if (!p)
			goto out;
	}
	fp = efi_dp_dup(p);
	if (!fp)
		return EFI_OUT_OF_RESOURCES;
	p->type = DEVICE_PATH_TYPE_END;
	p->sub_type = DEVICE_PATH_SUB_TYPE_END;
	p->length = sizeof(*p);

out:
	*device_path = dp;
	*file_path = fp;
	return EFI_SUCCESS;
}

// get size of the first device path instance excluding end node
size_t efi_dp_instance_size(const struct efi_device_path *dp)
{
	size_t sz = 0;

	if (!dp || dp->type == DEVICE_PATH_TYPE_END)
		return 0;
	while (dp) {
		sz += dp->length;
		dp = efi_dp_next(dp);
	}

	return sz;
}

/**
 * efi_dp_shorten() - shorten device-path
 *
 * When creating a short boot option we want to use a device-path that is
 * independent of the location where the block device is plugged in.
 *
 * UsbWwi() nodes contain a serial number, hard drive paths a partition
 * UUID. Both should be unique.
 *
 * See UEFI spec, section 3.1.2 for "short-form device path".
 *
 * @dp:     original device-path
 * @Return: shortened device-path or NULL
 */
struct efi_device_path *efi_dp_shorten(struct efi_device_path *dp)
{
	while (dp) {
		if (EFI_DP_TYPE(dp, MESSAGING_DEVICE, MSG_USB_WWI) ||
		    EFI_DP_TYPE(dp, MEDIA_DEVICE, HARD_DRIVE_PATH) ||
		    EFI_DP_TYPE(dp, MEDIA_DEVICE, FILE_PATH))
			return dp;

		dp = efi_dp_next(dp);
	}

	return dp;
}

/*
 * find_handle() - find handle by device path and installed protocol
 *
 * If @rem is provided, the handle with the longest partial match is returned.
 *
 * @dp:         device path to search
 * @guid:       GUID of protocol that must be installed on path or NULL
 * @short_path: use short form device path for matching
 * @rem:        pointer to receive remaining device path
 * Return:      matching handle
 */
efi_handle_t find_handle(struct efi_device_path *dp,
				const efi_guid_t *guid, bool short_path,
				struct efi_device_path **rem)
{
	efi_handle_t handle, best_handle = NULL;
	size_t len, best_len = 0;

	len = efi_dp_instance_size(dp);

	LIST_FOREACH(handle, &efi_obj_list, link) {
		struct efi_handler *handler;
		struct efi_device_path *dp_current;
		size_t len_current;
		efi_status_t ret;

		if (guid) {
			ret = efi_search_protocol(handle, guid, &handler);
			if (ret != EFI_SUCCESS)
				continue;
		}
		ret = efi_search_protocol(handle, &efi_guid_device_path,
					  &handler);
		if (ret != EFI_SUCCESS)
			continue;
		dp_current = handler->protocol_interface;
		if (short_path) {
			dp_current = efi_dp_shorten(dp_current);
			if (!dp_current)
				continue;
		}
		len_current = efi_dp_instance_size(dp_current);
		if (rem) {
			if (len_current > len)
				continue;
		} else {
			if (len_current != len)
				continue;
		}
		if (memcmp(dp_current, dp, len_current))
			continue;
		if (!rem)
			return handle;
		if (len_current > best_len) {
			best_len = len_current;
			best_handle = handle;
			*rem = (void *)((u8 *)dp + len_current);
		}
	}
	return best_handle;
}

/*
 * efi_dp_find_obj() - find handle by device path
 *
 * If @rem is provided, the handle with the longest partial match is returned.
 *
 * @dp:    device path to search
 * @guid:  GUID of protocol that must be installed on path or NULL
 * @rem:   pointer to receive remaining device path
 * Return: matching handle
 */
efi_handle_t efi_dp_find_obj(struct efi_device_path *dp,
			     const efi_guid_t *guid,
			     struct efi_device_path **rem)
{
	efi_handle_t handle;

	handle = find_handle(dp, guid, false, rem);
	if (!handle)
		/* Match short form device path */
		handle = find_handle(dp, guid, true, rem);

	return handle;
}

/*
 * Append or concatenate two device paths. Concatenated device path will be separated by a
 * sub-type 0xff end node
 *
 * @dp1:     First device path
 * @dp2:     Second device path
 * @concat:  If true the two device paths will be concatenated and separated
 *           by an end of entrire device path sub-type 0xff end node.
 *           If true the second device path will be appended to the first and
 *           terminated by an end node
 * Return:
 * concatenated device path or NULL. Caller must free the returned value
 */
struct efi_device_path *efi_dp_append_or_concatenate(const struct efi_device_path *dp1,
					      const struct efi_device_path *dp2,
					      bool concat)
{
	struct efi_device_path *ret;
	size_t end_size = sizeof(dp_end_node);

	if (concat)
		end_size = 2 * sizeof(dp_end_node);
	if (!dp1 && !dp2) {
		/* return an end node */
		ret = efi_dp_dup(&dp_end_node);
	} else if (!dp1) {
		ret = efi_dp_dup(dp2);
	} else if (!dp2) {
		ret = efi_dp_dup(dp1);
	} else {
		/* both dp1 and dp2 are non-null */
		unsigned int sz1 = efi_dp_size(dp1);
		unsigned int sz2 = efi_dp_size(dp2);
		void *p = efi_alloc(sz1 + sz2 + end_size);
		if (!p)
			return NULL;
		ret = p;
		memcpy(p, dp1, sz1);
		p += sz1;

		if (concat) {
			memcpy(p, &dp_end_node, sizeof(end_node));
			p += sizeof(dp_end_node);
		}

		/* the end node of the second device path has to be retained */
		memcpy(p, dp2, sz2);
		p += sz2;
		memcpy(p, &dp_end_node, sizeof(end_node));
	}

	return ret;
}

/*
 * efi_dp_append() - Append a device to an existing device path.
 *
 * @dp1: First device path
 * @dp2: Second device path
 *
 * Return:
 * concatenated device path or NULL. Caller must free the returned value
 */
struct efi_device_path *efi_dp_append(const struct efi_device_path *dp1,
				      const struct efi_device_path *dp2)
{
	return efi_dp_append_or_concatenate(dp1, dp2, false);
}
