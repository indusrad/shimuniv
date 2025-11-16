// SPDX-License-Identifier: GPL-2.0+

/*
 * Copyright (C) 1999 VA Linux Systems
 * Copyright (C) 1999 Walt Drummond <drummond@valinux.com>
 * Copyright (C) 1999, 2002-2003 Hewlett-Packard Co.
 * David Mosberger-Tang <davidm@hpl.hp.com>
 * Stephane Eranian <eranian@hpl.hp.com>
 * Copyright (c) 2023 ARM Ltd.
 */

#ifndef EFI_PROTOCOL_H
#define EFI_PROTOCOL_H

#include "efi_defines.h"
#include "efi_object.h"
#include "efi_guid.h"

#include <stdint.h>
#include <queue.h>

/*
 * handle for notified protocol
 * When a protocol interface is installed for which an event was registered with
 * the RegisterProtocolNotify() service this structure is used to hold the
 * handle on which the protocol interface was installed.
 *
 * @link:    link to list of all handles notified for this event
 * @handle:  handle on which the notified protocol interface was installed
 */
struct efi_protocol_notification {
	LIST_ENTRY(efi_protocol_notification) link;
	efi_handle_t handle;
};

struct efi_open_protocol_info_entry {
	efi_handle_t agent_handle;
	u32 attributes;
	u32 open_count;
};

/*
 * open protocol info item
 * When a protocol is opened a open protocol info entry is created.
 * These are maintained in a list.
 *
 * @link: link to the list of open protocol info entries of a protocol
 * @info: information about the opening of a protocol
 */
struct efi_open_protocol_info_item {
	LIST_ENTRY(efi_open_protocol_info_item) link;
	struct efi_open_protocol_info_entry info;
};

LIST_HEAD(efi_open_protocol_info_items, efi_open_protocol_info_item);

/*
 * single protocol interface of a handle
 * When the UEFI payload wants to open a protocol on an object to get its interface (usually
 * a struct with callback functions), this struct maps the protocol GUID to the respective
 * protocol interface
 *
 * @link:               link to the list of protocols of a handle
 * @guid:               GUID of the protocol
 * @protocol_interface: protocol interface
 * @open_infos:         link to the list of open protocol info items
 */
struct efi_handler {
	LIST_ENTRY(efi_handler) link;
	const efi_guid_t guid;
	void *protocol_interface;
	struct efi_open_protocol_info_items open_infos;
};

efi_status_t EFIAPI efi_install_protocol_interface(efi_handle_t *handle,
		const efi_guid_t *protocol,
		int protocol_interface_type,
		void *protocol_interface);
efi_status_t EFIAPI efi_install_multiple_protocol_interfaces(efi_handle_t *handle, ...);
efi_status_t EFIAPI efi_uninstall_protocol_interface(efi_handle_t handle,
		const efi_guid_t *protocol,
		void *protocol_interface);
efi_status_t EFIAPI efi_uninstall_multiple_protocol_interfaces(efi_handle_t handle, ...);
efi_status_t EFIAPI efi_reinstall_protocol_interface(efi_handle_t handle,
		const efi_guid_t *protocol,
		void *old_interface,
		void *new_interface);
efi_status_t EFIAPI efi_handle_protocol(efi_handle_t handle,
		const efi_guid_t *protocol,
		void **protocol_interface);
efi_status_t EFIAPI efi_register_protocol_notify(const efi_guid_t *protocol,
		void *event,
		void **registration);
efi_status_t EFIAPI efi_locate_handle_ext(enum efi_locate_search_type search_type,
		const efi_guid_t *protocol,
		void *search_key,
		size_t *buffer_size,
		efi_handle_t *buffer);
efi_status_t EFIAPI efi_close_protocol_ext(efi_handle_t handle, const efi_guid_t *protocol,
		efi_handle_t agent_handle,
		efi_handle_t controller_handle);
efi_status_t EFIAPI efi_open_protocol(efi_handle_t handle, const efi_guid_t *protocol,
		void **protocol_interface, efi_handle_t agent_handle,
		efi_handle_t controller_handle, uint32_t attributes);
efi_status_t EFIAPI efi_open_protocol_information(efi_handle_t handle,
		const efi_guid_t *protocol,
		struct efi_open_protocol_info_entry **entry_buffer,
		size_t *entry_count);
efi_status_t EFIAPI efi_protocols_per_handle(efi_handle_t handle,
		efi_guid_t ***protocol_buffer,
		size_t *protocol_buffer_count);
efi_status_t EFIAPI efi_locate_protocol(const efi_guid_t *protocol,
		void *registration,
		void **protocol_interface);
efi_status_t EFIAPI efi_locate_handle_buffer(enum efi_locate_search_type search_type,
		const efi_guid_t *protocol,
		void *search_key,
		size_t *no_handles,
		efi_handle_t **buffer);
efi_status_t EFIAPI efi_install_multiple_protocol_interfaces_ext(efi_handle_t *handle, ...);
efi_status_t EFIAPI efi_uninstall_multiple_protocol_interfaces_ext(efi_handle_t handle, ...);
efi_status_t efi_search_protocol(const efi_handle_t handle, const efi_guid_t *protocol_guid,
		struct efi_handler **handler);
efi_status_t efi_add_protocol(const efi_handle_t handle, const efi_guid_t *protocol,
		void *protocol_interface);
efi_status_t efi_uninstall_protocol(efi_handle_t handle, const efi_guid_t *protocol,
		void *protocol_interface);
efi_status_t efi_remove_protocol(const efi_handle_t handle, const efi_guid_t *protocol,
		void *protocol_interface);
efi_status_t efi_remove_all_protocols(const efi_handle_t handle);
efi_status_t efi_close_protocol(efi_handle_t handle, const efi_guid_t *protocol,
		efi_handle_t agent_handle,
		efi_handle_t controller_handle);
int efi_search(enum efi_locate_search_type search_type, const efi_guid_t *protocol,
		efi_handle_t handle);
void efi_signal_event(void *event);
void efi_add_handle(efi_handle_t handle);
efi_status_t efi_locate_handle_buffer_int(enum efi_locate_search_type search_type,
		const efi_guid_t *protocol,
		void *search_key,
		size_t *no_handles,
		efi_handle_t **buffer);
struct efi_open_protocol_info_entry *efi_create_open_info(struct efi_handler *handler);

#endif
