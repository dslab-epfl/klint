#include "net/packet.h"
#include "os/memory.h"

#include <stdbool.h>
#include <stdint.h>

enum Command_type { REMOVE = 0, ADD = 1 };

struct net_dns_record {
	char host[64];
	uint32_t ip_address;
	uint32_t ttl;
};

struct command {
	struct net_dns_record record;
	enum Command_type cmd_type;
};

/**
 * @struct net_dns_header
 * @brief dns packet header
 *
 *
 */
struct net_dns_header {
	uint16_t identifiaction;
	uint16_t options;
	uint16_t question_count;
	uint16_t answer_count;
	uint16_t ns_count;
	uint16_t ar_count;
	uint8_t* data;
} __attribute__((__packed__));

struct net_dns_answer_entry {
	char qname[64];
	uint16_t qtype;
	uint16_t qclass;
} __attribute__((__packed__));

// TODO we are not checking the 64 byte limit yet (maybe we will never do it)
inline size_t net_get_dns_question_entry(uint8_t* dns_entry_data, struct net_dns_answer_entry* out_net_dns_question_entry)
{
	size_t entry_index = 0;
	while (dns_entry_data[entry_index] != 0) {
		for (uint8_t read = dns_entry_data[entry_index]; read > 0; read--) {
			out_net_dns_question_entry->qname[entry_index] = (char) dns_entry_data[entry_index];
			entry_index++;
		}
		out_net_dns_question_entry->qname[entry_index] = '.';
		entry_index++;
	}

	size_t entry_index_clone = entry_index;
	while (entry_index_clone < 64) {
		out_net_dns_question_entry->qname[entry_index_clone] = '\0';
		entry_index_clone++;
	}

	// need to do it to also include the 0 of the prefix qname in out calcs
	entry_index++;

	out_net_dns_question_entry->qtype = (uint16_t) dns_entry_data[entry_index];
	entry_index += 2;
	out_net_dns_question_entry->qclass = (uint16_t) dns_entry_data[entry_index];
	entry_index += 2;

	return entry_index;
}

// TODO we are not checking for overflowing the total size of the dns packet
static void prepare_dns_response(size_t entry_index, struct net_dns_record* in_net_dns_record, struct net_dns_header* in_net_dns_header)
{
	// update the dns request header
	in_net_dns_header->options = in_net_dns_header->options | 0x8000;
	in_net_dns_header->answer_count = 1;

	// copy the first 3 fields from the question to response entry
	os_memory_copy(in_net_dns_header->data, &in_net_dns_header->data[entry_index], entry_index);
	entry_index += entry_index;

	// store the first option from DNS record
	os_memory_copy(&in_net_dns_record->ttl, &in_net_dns_header->data[entry_index], 4);
	entry_index += 4;

	// assign the RDLength
	uint16_t rdatalen = 4;
	os_memory_copy(&rdatalen, &in_net_dns_header->data[entry_index], 2);
	entry_index += 2;

	// copy chars of record
	os_memory_copy(&in_net_dns_record->ip_address, &in_net_dns_header->data[entry_index], 4);
	entry_index += 4;
}

static inline bool net_get_dns_header(struct net_ipv4_header* ipv4_header, struct net_dns_header** out_dns_header)
{
	struct net_tcpudp_header* udp_header;
	if (ipv4_header->next_proto_id != IP_PROTOCOL_UDP || !net_get_tcpudp_header(ipv4_header, &udp_header)) {
		return false;
	}
	if (udp_header->dst_port != 53) {
		return false;
	}
	*out_dns_header = (struct net_dns_header*) (udp_header + 2);
	return ((*out_dns_header)->options & 0x80) == 0x80;
}