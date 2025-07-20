#pragma once
#include <stdint.h>
uint16_t compute_ip_checksum(uint16_t *header, int header_len) {
	uint32_t sum = 0;

	while (header_len > 1) {
		sum += *header++;
		header_len -= 2;
	}

	if (header_len > 0) 
		sum += *header & 0xFF00;

	while (sum >> 16)
		sum = (sum & 0xFFFF) + (sum >> 16);

	return (uint16_t)(~sum);
}

