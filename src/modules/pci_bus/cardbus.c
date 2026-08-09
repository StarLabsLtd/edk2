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
	socket->generation = generation;
	socket->present = 0;
	socket->powered = 0;
	return 0;
}
