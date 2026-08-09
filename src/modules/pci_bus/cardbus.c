/* SPDX-License-Identifier: GPL-2.0-only */
#include <cdk2/pci_bus_model.h>

int cdk2_pci_cardbus_insert(struct cdk2_pci_cardbus_socket *socket)
{
	uint64_t generation;
	if (socket == NULL || socket->set_power == NULL || socket->reset == NULL ||
	    socket->notify == NULL || socket->present)
		return -1;
	if (socket->set_power(socket->context, 1) != 0)
		return -1;
	socket->powered = 1;
	if (socket->reset(socket->context) != 0) {
		(void)socket->set_power(socket->context, 0);
		socket->powered = 0;
		return -1;
	}
	generation = socket->generation + 1U;
	if (generation == 0U || socket->notify(socket->context, 1, generation) != 0) {
		(void)socket->set_power(socket->context, 0);
		socket->powered = 0;
		return -1;
	}
	if (socket->bind_child != NULL &&
	    socket->bind_child(socket->context, &socket->child_handle) != 0) {
		(void)socket->notify(socket->context, 0, generation);
		(void)socket->set_power(socket->context, 0);
		socket->child_handle = NULL;
		socket->powered = 0;
		return -1;
	}
	socket->generation = generation;
	socket->present = 1;
	return 0;
}

int cdk2_pci_cardbus_remove(struct cdk2_pci_cardbus_socket *socket)
{
	uint64_t generation;
	if (socket == NULL || socket->set_power == NULL || socket->notify == NULL ||
	    !socket->present)
		return -1;
	generation = socket->generation + 1U;
	if (generation == 0U || socket->notify(socket->context, 0, generation) != 0)
		return -1;
	if (socket->set_power(socket->context, 0) != 0) {
		/* Compensate the delivered removal before returning residency. */
		(void)socket->notify(socket->context, 1, socket->generation);
		return -1;
	}
	if (socket->child_handle != NULL && socket->unbind_child != NULL)
		socket->unbind_child(socket->context, socket->child_handle);
	socket->child_handle = NULL;
	socket->generation = generation;
	socket->present = 0;
	socket->powered = 0;
	return 0;
}

int cdk2_pci_cardbus_queue_event(struct cdk2_pci_cardbus_socket *socket,
	int inserted, uint64_t tick)
{
	uint8_t tail;
	if (socket == NULL || socket->event_count == 8U ||
	    tick < socket->last_event_tick)
		return -1;
	if (socket->event_count != 0U &&
	    tick - socket->last_event_tick < socket->debounce_ticks) {
		tail = (uint8_t)((socket->event_head + socket->event_count - 1U) % 8U);
		socket->events[tail].inserted = inserted != 0;
		socket->events[tail].tick = tick;
		socket->last_event_tick = tick;
		return 0;
	}
	tail = (uint8_t)((socket->event_head + socket->event_count) % 8U);
	socket->events[tail].inserted = inserted != 0;
	socket->events[tail].tick = tick;
	socket->event_count++;
	socket->last_event_tick = tick;
	return 0;
}

int cdk2_pci_cardbus_process_event(struct cdk2_pci_cardbus_socket *socket)
{
	int status;
	if (socket == NULL || socket->event_count == 0U)
		return -1;
	status = socket->events[socket->event_head].inserted ?
		cdk2_pci_cardbus_insert(socket) : cdk2_pci_cardbus_remove(socket);
	if (status != 0)
		return -1;
	socket->event_head = (uint8_t)((socket->event_head + 1U) % 8U);
	socket->event_count--;
	return 0;
}
