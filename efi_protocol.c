// SPDX-License-Identifier: GPL-2.0+

/*
 *  Copyright (c) 2016 Alexander Graf
 *  Copyright (c) 2023 ARM Ltd.
 *
 * This file is derived from the U-Boot project
 */

#include "efi_protocol.h"
#include "efi_defines.h"
#include "efi_memory.h"
#include <stdint.h>
#include <queue.h>
#include <libpayload.h>

// This list contains all the EFI objects our payload has access to
extern struct efi_object_list efi_obj_list;
extern efi_handle_t efi_root;

/*
 * remove an open protocol info entry from a protocol
 *
 * @item: open protocol info entry to delete
 *
 * Return: status code
 */
static efi_status_t efi_delete_open_info(struct efi_open_protocol_info_item *item)
{
	LIST_REMOVE(item, link);
	free(item);
	return EFI_SUCCESS;
}

/*
 * find a protocol on a handle.
 *
 * @handle:        handle
 * @protocol_guid: GUID of the protocol
 * @handler:       reference to the protocol
 *
 * Return: status code
 */
efi_status_t efi_search_protocol(const efi_handle_t handle,
				 const efi_guid_t *protocol_guid,
				 struct efi_handler **handler)
{
	struct efi_handler *lhandle;

	if (!handle || !protocol_guid)
		return EFI_INVALID_PARAMETER;

	if (!efi_obj_in_list(handle))
		return EFI_INVALID_PARAMETER;

	LIST_FOREACH(lhandle, &handle->protocols, link) {
		struct efi_handler *protocol;

		protocol = lhandle;
		if (!guidcmp(&protocol->guid, protocol_guid)) {
			if (handler)
				*handler = protocol;
			return EFI_SUCCESS;
		}
	}
	return EFI_NOT_FOUND;
}

/*
 * open protocol interface on a handle
 *
 * @handler:            handler of a protocol
 * @protocol_interface: interface implementing the protocol
 * @agent_handle:       handle of the driver
 * @controller_handle:  handle of the controller
 * @attributes:         attributes indicating how to open the protocol
 *
 * Return: status code
 */
static efi_status_t efi_protocol_open(
			struct efi_handler *handler,
			void **protocol_interface, void *agent_handle,
			void *controller_handle, uint32_t attributes)
{
	(void)controller_handle;
	struct efi_open_protocol_info_item *item;
	struct efi_open_protocol_info_entry *match = NULL;

	// If there is no agent, only return the interface
	if (!agent_handle)
		goto out;

	// For TEST_PROTOCOL ignore interface attribute
	if (attributes != EFI_OPEN_PROTOCOL_TEST_PROTOCOL)
		*protocol_interface = NULL;

	// Find existing entry
	LIST_FOREACH(item, &handler->open_infos, link) {
		if (item->info.agent_handle == agent_handle &&
		    item->info.attributes == attributes)
			match = &item->info;
	}
	// None found, create one
	if (!match) {
		match = efi_create_open_info(handler);
		if (!match)
			return EFI_OUT_OF_RESOURCES;
	}

	match->agent_handle = agent_handle;
	match->attributes = attributes;
	match->open_count++;

out:
	// For TEST_PROTOCOL ignore interface attribute.
	if (attributes != EFI_OPEN_PROTOCOL_TEST_PROTOCOL)
		*protocol_interface = handler->protocol_interface;

	return EFI_SUCCESS;
}

/**
 * install new protocol on a handle
 *
 * @handle:             handle on which the protocol shall be installed
 * @protocol:           GUID of the protocol to be installed
 * @protocol_interface: interface of the protocol implementation
 *
 * Return: status code
 */
efi_status_t efi_add_protocol(const efi_handle_t handle,
			      const efi_guid_t *protocol,
			      void *protocol_interface)
{
	struct efi_handler *handler;
	efi_status_t ret;

	if (!efi_obj_in_list(handle))
		return EFI_INVALID_PARAMETER;

	ret = efi_search_protocol(handle, protocol, NULL);
	if (ret != EFI_NOT_FOUND)
		return EFI_INVALID_PARAMETER;

	handler = calloc(1, sizeof(struct efi_handler));
	if (!handler)
		return EFI_OUT_OF_RESOURCES;

	memcpy((void *)&handler->guid, protocol, sizeof(efi_guid_t));
	handler->protocol_interface = protocol_interface;
	LIST_INIT(&handler->open_infos);
	LIST_INSERT_HEAD(&handle->protocols, handler, link);

	return EFI_SUCCESS;
}

/*
 * install protocol interface
 * This function implements the InstallProtocolInterface service.
 * See the Unified Extensible Firmware Interface (UEFI) specification for details.
 *
 * @handle:                  handle on which the protocol shall be installed
 * @protocol:                GUID of the protocol to be installed
 * @protocol_interface_type: type of the interface to be installed,
 *                           always EFI_NATIVE_INTERFACE
 * @protocol_interface:      interface of the protocol implementation
 *
 * Return: status code
 */
efi_status_t EFIAPI efi_install_protocol_interface(
			efi_handle_t *handle, const efi_guid_t *protocol,
			int protocol_interface_type, void *protocol_interface)
{
	efi_status_t r;

	if (!handle || !protocol ||
	    protocol_interface_type != EFI_NATIVE_INTERFACE) {
		r = EFI_INVALID_PARAMETER;
		goto out;
	}

	// Create new handle if requested.
	if (!*handle) {
		r = efi_create_handle(handle);
		if (r != EFI_SUCCESS)
			goto out;
		printf("new handle %p\n", *handle);
	} else {
		printf("handle %p\n", *handle);
	}
	// Add new protocol
	r = efi_add_protocol(*handle, protocol, protocol_interface);
out:
	return r;
}

/*
 * delete protocol from a handle
 *
 * @handle:             handle from which the protocol shall be deleted
 * @protocol:           GUID of the protocol to be deleted
 * @protocol_interface: interface of the protocol implementation
 *
 * Return: status code
 */
efi_status_t efi_remove_protocol(const efi_handle_t handle,
				 const efi_guid_t *protocol,
				 void *protocol_interface)
{
	struct efi_handler *handler;
	efi_status_t ret;

	ret = efi_search_protocol(handle, protocol, &handler);
	if (ret != EFI_SUCCESS)
		return ret;
	if (handler->protocol_interface != protocol_interface)
		return EFI_NOT_FOUND;
	LIST_REMOVE(handler, link);
	free(handler);
	return EFI_SUCCESS;
}

/*
 * delete all protocols from a handle
 *
 * @handle: handle from which the protocols shall be deleted
 *
 * Return: status code
 */
efi_status_t efi_remove_all_protocols(const efi_handle_t handle)
{
	struct efi_handler *protocol;

	if (!efi_obj_in_list(handle))
		return EFI_INVALID_PARAMETER;

	LIST_FOREACH(protocol, &handle->protocols, link) {
		efi_status_t ret;

		ret = efi_remove_protocol(handle, &protocol->guid,
					  protocol->protocol_interface);
		if (ret != EFI_SUCCESS)
			return ret;
	}
	return EFI_SUCCESS;
}

/*
 * uninstall protocol interface
 * This function DOES NOT delete a handle without installed protocol.
 *
 * @handle:             handle from which the protocol shall be removed
 * @protocol:           GUID of the protocol to be removed
 * @protocol_interface: interface to be removed
 *
 * Return: status code
 */
efi_status_t efi_uninstall_protocol(
	efi_handle_t handle,
	const efi_guid_t *protocol,
	void *protocol_interface)
{
	struct efi_handler *handler;
	struct efi_open_protocol_info_item *item;
	efi_status_t r;

	// Check handle
	if (!efi_obj_in_list(handle)) {
		r = EFI_INVALID_PARAMETER;
		goto out;
	}

	// Find the protocol on the handle
	r = efi_search_protocol(handle, protocol, &handler);
	if (r != EFI_SUCCESS)
		goto out;

	// Close protocol
	LIST_FOREACH(item, &handler->open_infos, link) {
		if (item->info.attributes == EFI_OPEN_PROTOCOL_BY_HANDLE_PROTOCOL ||
		    item->info.attributes == EFI_OPEN_PROTOCOL_GET_PROTOCOL ||
		    item->info.attributes == EFI_OPEN_PROTOCOL_TEST_PROTOCOL) {
			LIST_REMOVE(item, link);
		}
	}

	if (!LIST_EMPTY(&handler->open_infos)) {
		r =  EFI_ACCESS_DENIED;
		goto out;
	}
	r = efi_remove_protocol(handle, protocol, protocol_interface);
out:
	return r;
}

/*
 * uninstall protocol interface
 * This function implements the UninstallProtocolInterface service.
 * See the Unified Extensible Firmware Interface (UEFI) specification for details.
 *
 * @handle:             handle from which the protocol shall be removed
 * @protocol:           GUID of the protocol to be removed
 * @protocol_interface: interface to be removed
 *
 * Return: status code
 */
efi_status_t EFIAPI efi_uninstall_protocol_interface(
	efi_handle_t handle,
	const efi_guid_t *protocol,
	void *protocol_interface)
{
	efi_status_t ret;

	ret = efi_uninstall_protocol(handle, protocol, protocol_interface);
	if (ret != EFI_SUCCESS)
		goto out;

	// If the last protocol has been removed, delete the handle.
	if (LIST_EMPTY(&handle->protocols)) {
		LIST_REMOVE(handle, link);
		free(handle);
	}
out:
	return ret;
}

/*
 * Install multiple protocol interfaces
 * Core functionality of efi_install_multiple_protocol_interfaces Must not be called directly
 *
 * @handle: handle on which the protocol interfaces shall be installed
 * @argptr: va_list of args
 *
 * Return: status code
 */
static efi_status_t EFIAPI
efi_install_multiple_protocol_interfaces_int(efi_handle_t *handle, efi_va_list argptr)
{
	const efi_guid_t *protocol;
	void *protocol_interface;
	efi_status_t ret = EFI_SUCCESS;
	int i = 0;
	efi_va_list argptr_copy;

	if (!handle)
		return EFI_INVALID_PARAMETER;

	efi_va_copy(argptr_copy, argptr);
	for (;;) {
		protocol = efi_va_arg(argptr, efi_guid_t*);
		if (!protocol)
			break;
		protocol_interface = efi_va_arg(argptr, void*);
		ret = efi_install_protocol_interface(handle, protocol, EFI_NATIVE_INTERFACE, protocol_interface);
		if (ret != EFI_SUCCESS)
			break;
		i++;
	}
	if (ret == EFI_SUCCESS)
		goto out;

	// If an error occurred undo all changes.
	for (; i; --i) {
		protocol = efi_va_arg(argptr_copy, efi_guid_t*);
		protocol_interface = efi_va_arg(argptr_copy, void*);
		efi_uninstall_protocol_interface(*handle, protocol, protocol_interface);
	}

out:
	efi_va_end(argptr_copy);
	return ret;

}

/*
 * Install multiple protocol interfaces
 * This is the function for internal usage. For the API function
 * implementing the InstallMultipleProtocol service see
 * efi_install_multiple_protocol_interfaces_ext()
 *
 * @handle: handle on which the protocol interfaces shall be installed
 * @...:    NULL terminated argument list with pairs of protocol GUIDS and interfaces
 *
 * Return: status code
 */
efi_status_t EFIAPI
efi_install_multiple_protocol_interfaces(efi_handle_t *handle, ...)
{
	efi_status_t ret;
	efi_va_list argptr;

	efi_va_start(argptr, handle);
	ret = efi_install_multiple_protocol_interfaces_int(handle, argptr);
	efi_va_end(argptr);
	return ret;
}

/*
 * wrapper for uninstall multiple protocol interfaces
 * Core functionality of efi_uninstall_multiple_protocol_interfaces must not be called directly
 *
 * @handle: handle from which the protocol interfaces shall be removed
 * @argptr: va_list of args
 *
 * Return: status code
 */
static efi_status_t EFIAPI
efi_uninstall_multiple_protocol_interfaces_int(efi_handle_t handle,
					       efi_va_list argptr)
{
	const efi_guid_t *protocol;
	void *protocol_interface;
	efi_status_t ret = EFI_SUCCESS;
	size_t i = 0;
	efi_va_list argptr_copy;

	if (!handle)
		return EFI_INVALID_PARAMETER;

	efi_va_copy(argptr_copy, argptr);
	for (;;) {
		protocol = efi_va_arg(argptr, efi_guid_t*);
		if (!protocol)
			break;
		protocol_interface = efi_va_arg(argptr, void*);
		ret = efi_uninstall_protocol(handle, protocol,
					     protocol_interface);
		if (ret != EFI_SUCCESS)
			break;
		i++;
	}
	if (ret == EFI_SUCCESS) {
		// If the last protocol has been removed, delete the handle.
		if (LIST_EMPTY(&handle->protocols)) {
			LIST_REMOVE(handle, link);
			free(handle);
		}
		goto out;
	}

	// If an error occurred undo all changes.
	for (; i; --i) {
		protocol = efi_va_arg(argptr_copy, efi_guid_t*);
		protocol_interface = efi_va_arg(argptr_copy, void*);
		efi_install_protocol_interface(&handle, protocol,
							EFI_NATIVE_INTERFACE,
							protocol_interface);
	}
	/*
	 * If any errors are generated while the protocol interfaces are being
	 * uninstalled, then the protocols uninstalled prior to the error will
	 * be reinstalled using InstallProtocolInterface() and the status code
	 * EFI_INVALID_PARAMETER is returned.
	 */
	ret = EFI_INVALID_PARAMETER;

out:
	efi_va_end(argptr_copy);
	return ret;
}

/*
 * reinstall protocol interface
 * This function implements the ReinstallProtocolInterface service.
 * See the Unified Extensible Firmware Interface (UEFI) specification for details.
 * The old interface is uninstalled. The new interface is installed. Drivers are connected.
 *
 * @handle:        handle on which the protocol shall be reinstalled
 * @protocol:      GUID of the protocol to be installed
 * @old_interface: interface to be removed
 * @new_interface: interface to be installed
 *
 * Return: status code
 */
efi_status_t EFIAPI efi_reinstall_protocol_interface(
			efi_handle_t handle, const efi_guid_t *protocol,
			void *old_interface, void *new_interface)
{
	efi_status_t ret;

	// Uninstall protocol but do not delete handle
	ret = efi_uninstall_protocol(handle, protocol, old_interface);
	if (ret != EFI_SUCCESS)
		goto out;

	// Install the new protocol
	ret = efi_add_protocol(handle, protocol, new_interface);
	/*
	 * The UEFI spec does not specify what should happen to the handle
	 * if in case of an error no protocol interface remains on the handle.
	 * So let's do nothing here.
	 */
	if (ret != EFI_SUCCESS)
		goto out;
out:
	return ret;
}

/*
 * get interface of a protocol on a handle.
 * This function implements the HandleProtocol service.
 * See the Unified Extensible Firmware Interface (UEFI) specification for details.
 *
 * @handle:             handle on which the protocol shall be opened
 * @protocol:           GUID of the protocol
 * @protocol_interface: interface implementing the protocol
 *
 * Return: status code
 */
efi_status_t EFIAPI efi_handle_protocol(efi_handle_t handle,
					const efi_guid_t *protocol,
					void **protocol_interface)
{
	return efi_open_protocol(handle, protocol, protocol_interface, efi_root,
				 NULL, EFI_OPEN_PROTOCOL_BY_HANDLE_PROTOCOL);
}

/*
 * create open protocol info entry and add it to a protocol
 *
 * @handler: handler of a protocol
 *
 * Return: open protocol info entry
 */
struct efi_open_protocol_info_entry *efi_create_open_info(
			struct efi_handler *handler)
{
	struct efi_open_protocol_info_item *item;

	item = calloc(1, sizeof(struct efi_open_protocol_info_item));
	if (!item)
		return NULL;
	// Append the item to the open protocol info list.
	LIST_INSERT_HEAD(&handler->open_infos, item, link);

	return &item->info;
}


/*
 * determine if an EFI handle implements a protocol.
 * See the documentation of the LocateHandle service in the UEFI specification.
 *
 * @search_type: selection criterion
 * @protocol:    GUID of the protocol
 * @handle:      handle
 *
 * Return: 0 if the handle implements the protocol
 */
int efi_search(enum efi_locate_search_type search_type,
		      const efi_guid_t *protocol, efi_handle_t handle)
{
	efi_status_t ret;

	switch (search_type) {
	case ALL_HANDLES:
		return 0;
	case BY_PROTOCOL:
		ret = efi_search_protocol(handle, protocol, NULL);
		return (ret != EFI_SUCCESS);
	default:
		// Invalid search type
		return -1;
	}
}

/*
 * locate handles implementing a protocol
 * This function is meant for internal calls. For the API implementation
 * of the LocateHandle service see efi_locate_handle_ext.
 *
 * @search_type:	selection criterion
 * @protocol:		GUID of the protocol
 * @search_key:		registration key
 * @buffer_size:	size of the buffer to receive the handles in bytes
 * @buffer:		buffer to receive the relevant handles
 *
 * Return: status code
 */
static efi_status_t efi_locate_handle(
			enum efi_locate_search_type search_type,
			const efi_guid_t *protocol, void *search_key,
			size_t *buffer_size, efi_handle_t *buffer)
{
	(void)search_key;
	struct efi_object *efiobj;
	size_t size = 0;

	// Check parameters
	switch (search_type) {
	case ALL_HANDLES:
		break;
	case BY_REGISTER_NOTIFY:
		return EFI_UNSUPPORTED;
	case BY_PROTOCOL:
		if (!protocol)
			return EFI_INVALID_PARAMETER;
		break;
	default:
		return EFI_INVALID_PARAMETER;
	}

	// Count how much space we need
	LIST_FOREACH(efiobj, &efi_obj_list, link) {
		if (!efi_search(search_type, protocol, efiobj))
			size += sizeof(void *);
	}
	if (size == 0)
		return EFI_NOT_FOUND;

	if (!buffer_size)
		return EFI_INVALID_PARAMETER;

	if (*buffer_size < size) {
		*buffer_size = size;
		return EFI_BUFFER_TOO_SMALL;
	}

	*buffer_size = size;

	// The buffer size is sufficient but there is no buffer
	if (!buffer)
		return EFI_INVALID_PARAMETER;

	// Then fill the array
	LIST_FOREACH(efiobj, &efi_obj_list, link) {
		if (!efi_search(search_type, protocol, efiobj))
			*buffer++ = efiobj;
	}

	return EFI_SUCCESS;
}

/*
 * locate handles implementing a protocol.
 * This function implements the LocateHandle service.
 * See the Unified Extensible Firmware Interface (UEFI) specification for details.
 *
 * @search_type: selection criterion
 * @protocol:    GUID of the protocol
 * @search_key:  registration key
 * @buffer_size: size of the buffer to receive the handles in bytes
 * @buffer:      buffer to receive the relevant handles
 *
 * Return: 0 if the handle implements the protocol
 */
efi_status_t EFIAPI efi_locate_handle_ext(
			enum efi_locate_search_type search_type,
			const efi_guid_t *protocol, void *search_key,
			size_t *buffer_size, efi_handle_t *buffer)
{
	return efi_locate_handle(search_type, protocol, search_key,
			buffer_size, buffer);
}

/*
 * close a protocol
 * This is the function implementing the CloseProtocol service is for internal usage.
 * For API usage wrapper efi_close_protocol_ext() is provided.
 * See the Unified Extensible Firmware Interface (UEFI) specification for details.
 *
 * @handle:            handle on which the protocol shall be closed
 * @protocol:          GUID of the protocol to close
 * @agent_handle:      handle of the driver
 * @controller_handle: handle of the controller
 *
 * Return: status code
 */
efi_status_t efi_close_protocol(efi_handle_t handle, const efi_guid_t *protocol,
				efi_handle_t agent_handle,
				efi_handle_t controller_handle)
{
	(void)controller_handle;
	struct efi_handler *handler;
	struct efi_open_protocol_info_item *item;
	struct efi_open_protocol_info_item *pos;
	efi_status_t ret;

	if (!efi_obj_in_list(agent_handle))
		return EFI_INVALID_PARAMETER;

	ret = efi_search_protocol(handle, protocol, &handler);
	if (ret != EFI_SUCCESS)
		return ret;

	ret = EFI_NOT_FOUND;
	LIST_FOREACH_SAFE(item, &handler->open_infos, link, pos) {
		if (item->info.agent_handle == agent_handle) {
			efi_delete_open_info(item);
			ret = EFI_SUCCESS;
		}
	}

	return ret;
}

/*
 * close a protocol
 * This function implements the CloseProtocol service.
 * See the Unified Extensible Firmware Interface (UEFI) specification for details.
 *
 * @handle:            handle on which the protocol shall be closed
 * @protocol:          GUID of the protocol to close
 * @agent_handle:      handle of the driver
 * @controller_handle: handle of the controller
 *
 * Return: status code
 */
efi_status_t EFIAPI
efi_close_protocol_ext(efi_handle_t handle, const efi_guid_t *protocol,
		       efi_handle_t agent_handle,
		       efi_handle_t controller_handle)
{
	efi_status_t ret;

	ret = efi_close_protocol(handle, protocol, agent_handle, controller_handle);

	return ret;
}

/*
 * provide information about then open status of a protocol on a handle
 * This function implements the OpenProtocolInformation service.
 * See the Unified Extensible Firmware Interface (UEFI) specification for details.
 *
 * @handle:       handle for which the information shall be retrieved
 * @protocol:     GUID of the protocol
 * @entry_buffer: buffer to receive the open protocol information
 * @entry_count:  number of entries available in the buffer
 *
 * Return: status code
 */
efi_status_t EFIAPI efi_open_protocol_information(
			efi_handle_t handle, const efi_guid_t *protocol,
			struct efi_open_protocol_info_entry **entry_buffer,
			size_t *entry_count)
{
	unsigned long buffer_size;
	unsigned long count;
	struct efi_handler *handler;
	struct efi_open_protocol_info_item *item;
	efi_status_t r;

	// Check parameters
	if (!entry_buffer) {
		r = EFI_INVALID_PARAMETER;
		goto out;
	}
	r = efi_search_protocol(handle, protocol, &handler);
	if (r != EFI_SUCCESS)
		goto out;

	// Count entries
	count = 0;
	LIST_FOREACH(item, &handler->open_infos, link) {
		if (item->info.open_count)
			++count;
	}
	*entry_count = count;
	*entry_buffer = NULL;
	if (!count) {
		r = EFI_SUCCESS;
		goto out;
	}

	// Copy entries
	buffer_size = count * sizeof(struct efi_open_protocol_info_entry);
	r = efi_allocate_pool(EFI_BOOT_SERVICES_DATA, buffer_size,
			      (void **)entry_buffer);
	if (r != EFI_SUCCESS)
		goto out;
	int i = 0;
	LIST_FOREACH(item, &handler->open_infos, link) {
		if (item->info.open_count)
			(*entry_buffer)[i++] = item->info;
	}
out:
	return r;
}

/*
 * get protocols installed on a handle
 * This function implements the ProtocolsPerHandleService.
 * See the Unified Extensible Firmware Interface (UEFI) specification for details.
 *
 * @handle:                handle for which the information is retrieved
 * @protocol_buffer:       buffer with protocol GUIDs
 * @protocol_buffer_count: number of entries in the buffer
 *
 * Return: status code
 */
efi_status_t EFIAPI efi_protocols_per_handle(
			efi_handle_t handle, efi_guid_t ***protocol_buffer,
			size_t *protocol_buffer_count)
{
	unsigned long buffer_size;
	struct efi_handler *protocol_handle;
	efi_status_t r;

	if (!handle || !protocol_buffer || !protocol_buffer_count)
		return EFI_INVALID_PARAMETER;

	*protocol_buffer = NULL;
	*protocol_buffer_count = 0;

	if (!efi_obj_in_list(handle))
		return EFI_INVALID_PARAMETER;

	// Count protocols
	LIST_FOREACH(protocol_handle, &handle->protocols, link) {
		++*protocol_buffer_count;
	}

	// Copy GUIDs
	if (*protocol_buffer_count) {
		size_t j = 0;

		buffer_size = sizeof(efi_guid_t *) * *protocol_buffer_count;
		r = efi_allocate_pool(EFI_BOOT_SERVICES_DATA, buffer_size,
				      (void **)protocol_buffer);
		if (r != EFI_SUCCESS)
			return r;
		LIST_FOREACH(protocol_handle, &handle->protocols, link) {
			struct efi_handler *protocol;

			protocol = protocol_handle;

			(*protocol_buffer)[j] = (void *)&protocol->guid;
			++j;
		}
	}

	return EFI_SUCCESS;
}

efi_status_t efi_locate_handle_buffer_int(enum efi_locate_search_type search_type,
					  const efi_guid_t *protocol, void *search_key,
					  size_t *no_handles, efi_handle_t **buffer)
{
	efi_status_t r;
	size_t buffer_size = 0;

	if (!no_handles || !buffer) {
		r = EFI_INVALID_PARAMETER;
		goto out;
	}
	*no_handles = 0;
	*buffer = NULL;
	r = efi_locate_handle(search_type, protocol, search_key, &buffer_size,
			      *buffer);
	if (r != EFI_BUFFER_TOO_SMALL)
		goto out;
	r = efi_allocate_pool(EFI_BOOT_SERVICES_DATA, buffer_size,
			      (void **)buffer);
	if (r != EFI_SUCCESS)
		goto out;
	r = efi_locate_handle(search_type, protocol, search_key, &buffer_size,
			      *buffer);
	if (r == EFI_SUCCESS)
		*no_handles = buffer_size / sizeof(efi_handle_t);
out:
	return r;
}

/*
 * locate handles implementing a protocol
 * This function implements the LocateHandleBuffer service.
 * See the Unified Extensible Firmware Interface (UEFI) specification for details.
 *
 * @search_type: selection criterion
 * @protocol:    GUID of the protocol
 * @search_key:  registration key
 * @no_handles:  number of returned handles
 * @buffer:      buffer with the returned handles
 *
 * Return: status code
 */
efi_status_t EFIAPI efi_locate_handle_buffer(
	enum efi_locate_search_type search_type,
	const efi_guid_t *protocol,
	void *search_key,
	size_t *no_handles,
	efi_handle_t **buffer)
{
	return efi_locate_handle_buffer_int(
		search_type,
		protocol,
		search_key,
		no_handles,
		buffer);
}

/*
 * find an interface implementing a protocol
 * This function implements the LocateProtocol service.
 * See the Unified Extensible Firmware Interface (UEFI) specification for details.
 *
 * @protocol:           GUID of the protocol
 * @registration:       registration key passed to the notification function
 * @protocol_interface: interface implementing the protocol
 *
 * Return: status code
 */
efi_status_t EFIAPI efi_locate_protocol(const efi_guid_t *protocol,
					       void *registration,
					       void **protocol_interface)
{
	struct efi_handler *handler;
	efi_status_t ret;
	struct efi_object *efiobj;

	/*
	 * The UEFI spec explicitly requires a protocol even if a registration
	 * key is provided. This differs from the logic in LocateHandle().
	 */
	if (!protocol || !protocol_interface)
		return EFI_INVALID_PARAMETER;

	if (!registration) {
		LIST_FOREACH(efiobj, &efi_obj_list, link) {
			ret = efi_search_protocol(efiobj, protocol, &handler);
			if (ret == EFI_SUCCESS) {
				*protocol_interface = handler->protocol_interface;
				return EFI_SUCCESS;
			}
		}
	} else {
		// leanEFI does not support efi events and therefore they can not be used to locate a protocol.
		*protocol_interface = NULL;
		return EFI_UNSUPPORTED;
	}
	*protocol_interface = NULL;
	return EFI_NOT_FOUND;
}

/*
 * Install multiple protocol interfaces
 * This function implements the MultipleProtocolInterfaces service.
 * See the Unified Extensible Firmware Interface (UEFI) specification for details.
 *
 * @handle: handle on which the protocol interfaces shall be installed
 * @...:    NULL terminated argument list with pairs of protocol GUIDS and
 *          interfaces
 *
 * Return: status code
 */
efi_status_t EFIAPI
efi_install_multiple_protocol_interfaces_ext(efi_handle_t *handle, ...)
{
	efi_status_t ret;
	efi_va_list argptr;

	efi_va_start(argptr, handle);
	ret = efi_install_multiple_protocol_interfaces_int(handle, argptr);
	efi_va_end(argptr);
	return ret;
}

/*
 * uninstall multiple protocol interfaces
 * This function implements the UninstallMultipleProtocolInterfaces service.
 * This is the function for internal usage. For the API function
 * implementing the UninstallMultipleProtocolInterfaces service see
 * efi_uninstall_multiple_protocol_interfaces_ext()
 *
 * @handle: handle from which the protocol interfaces shall be removed
 * @...:    NULL terminated argument list with pairs of protocol GUIDS and
 *          interfaces
 *
 * Return: status code
 */
efi_status_t EFIAPI
efi_uninstall_multiple_protocol_interfaces(efi_handle_t handle, ...)
{
	efi_status_t ret;
	efi_va_list argptr;

	efi_va_start(argptr, handle);
	ret = efi_uninstall_multiple_protocol_interfaces_int(handle, argptr);
	efi_va_end(argptr);
	return ret;
}

/*
 * uninstall multiple protocol interfaces
 * This function implements the UninstallMultipleProtocolInterfaces service.
 * See the Unified Extensible Firmware Interface (UEFI) specification for details.
 *
 * @handle: handle from which the protocol interfaces shall be removed
 * @...:    NULL terminated argument list with pairs of protocol GUIDS and
 *          interfaces
 *
 * Return: status code
 */
efi_status_t EFIAPI
efi_uninstall_multiple_protocol_interfaces_ext(efi_handle_t handle, ...)
{
	efi_status_t ret;
	efi_va_list argptr;

	efi_va_start(argptr, handle);
	ret = efi_uninstall_multiple_protocol_interfaces_int(handle, argptr);
	efi_va_end(argptr);
	return ret;
}

/*
 * open protocol interface on a handle
 * This function implements the OpenProtocol interface.
 * See the Unified Extensible Firmware Interface (UEFI) specification for details.
 *
 * @handle:             handle on which the protocol shall be opened
 * @protocol:           GUID of the protocol
 * @protocol_interface: interface implementing the protocol
 * @agent_handle:       handle of the driver
 * @controller_handle:  handle of the controller
 * @attributes:         attributes indicating how to open the protocol
 *
 * Return: status code
 */
efi_status_t EFIAPI efi_open_protocol(
	efi_handle_t handle,
	const efi_guid_t *protocol,
	void **protocol_interface,
	efi_handle_t agent_handle,
	efi_handle_t controller_handle,
	uint32_t attributes)
{
	struct efi_handler *handler;
	efi_status_t r = EFI_INVALID_PARAMETER;

	if (!handle || !protocol || (!protocol_interface &&
		attributes != EFI_OPEN_PROTOCOL_TEST_PROTOCOL)) {
		goto out;
	}

	switch (attributes) {
	case EFI_OPEN_PROTOCOL_BY_HANDLE_PROTOCOL:
	case EFI_OPEN_PROTOCOL_GET_PROTOCOL:
	case EFI_OPEN_PROTOCOL_TEST_PROTOCOL:
		break;
	case EFI_OPEN_PROTOCOL_EXCLUSIVE:
		// Check that the agent handle is valid
		if (!efi_obj_in_list(agent_handle))
			goto out;
		break;
	default:
		goto out;
	}

	r = efi_search_protocol(handle, protocol, &handler);
	switch (r) {
	case EFI_SUCCESS:
		break;
	case EFI_NOT_FOUND:
		r = EFI_UNSUPPORTED;
		goto out;
	default:
		goto out;
	}

	r = efi_protocol_open(handler, protocol_interface, agent_handle,
			      controller_handle, attributes);
out:
	return r;
}
