#include "net/packet.h"

#include <stdint.h>

/**
 * @struct net_dhcp_header
 *
 * @brief This represent a DHCP header without the option field whose size is not predfined
 *
 * @var net_dhcp_header::op
 *  message op code set to 1 if it is a DHCP request message set to 2 if it is a DHCP reply
 *  message
 * @var net_dhcp_header::htype
 *  define the type of hardware used for the local network set to 1 for EtherNet
 * @var net_dhcp_header::hlen
 *  define the length of hardware addresses in this message based on the htype, usually the value is 6
 * @var net_dhcp_header::hops
 *  Set to 0 by client and incremented by relay agents on the message paths
 * @var net_dhcp_header:: xid
 *  transaction ID, a random number chosen by client to associate message response between
 *  client and server
 * @var net_dhcp_header::secs
 *  second elapse between the start of the client request
 * @var net_dhcp_header::ciaddr
 *  clients IP address if it already has one, otherwise set to 0
 * @var net_dhcp_header::yaddr
 *  IP address the server is assigning to the client
 * @var net_dhcp_header::siaddr
 *  IP address of the server that the client should use for the next step of the protocol
 * @var net_dhcp_header::giaddr
 *  IP address of the gateway to be used by the client
 * @var net_dhcp_header::chaddr
 *  client hardware address (MAC address)
 * @var net_dhcp_header::sname
 *  server domain name if available
 * @var net_dhcp_header::file
 *  boot file name optionally requested by the client
 * @var net_dhcp_header::magic_cookie
 *  Special entry that is set to 63825363 for DHCP (telling protocols that the option field following is of type DHCP)
 * @var net_dhcp_header::options
 *  Filed that holds all the DHCP option fields that changes based on the type of DHCP message sent.
 */
struct net_dhcp_header {
	uint8_t op;
	uint8_t htype;
	uint8_t hlen;
	uint8_t hops;
	uint32_t xid;
	uint16_t secs;
	uint16_t flags;
	uint32_t ciaddr;
	uint32_t yaddr;
	uint32_t siaddr;
	uint32_t giaddr;
	uint8_t chaddr[16];
	char sname[64];
	char file[128];
	uint32_t magic_cookie;
	uint8_t* options;
} __attribute__((__packed__));

/**
 * @struct net_dhcp_response_option
 * @brief represents the option section of any dhcp response packet sent from the server to client
 *
 * @see net_dhcp_discover_option for more information on the option fields structure
 *
 */
struct net_dhcp_response_option {
	uint8_t dhcp_message_type_option_code;
	uint8_t dhcp_message_type_size;
	uint8_t dhcp_message_type_value;
	uint8_t dhcp_server_identifier_option_code;
	uint8_t dhcp_server_identifier_size;
	uint32_t dhcp_server_identifier_value;
	uint8_t subnet_mask_option_code;
	uint8_t subnet_mask_size;
	uint32_t subnet_mask_value;
	uint8_t ip_address_lease_time_option_code;
	uint8_t ip_address_lease_time_size;
	uint32_t ip_address_lease_time_value;
	uint8_t gateway_ip_option_code;
	uint8_t gateway_ip_size;
	uint32_t gateway_ip_value;
	uint8_t dns_server_ip_option_code;
	uint8_t dns_server_ip_size;
	uint32_t dns_server_ip_value;
	uint8_t end_option_code;
} __attribute__((__packed__));

/**
 * @struct net_dhcp_discover_option
 *
 * @brief defines the fields the option field of DHCPDISCOVER packets sent from the client to the DHCP server
 *
 * The option section of all DHCP messages follow the same entry patter
 *  1. type_option_code defines the type of entry will be read next for the values used for DHCP can be found in RF 1533
 *  2. type_size located directly after the option_code defines how many bytes of data to read
 *  3. type_value located directly after ther type_size is the value to be read for that specific option code
 *
 * @pre the option fields define must be of the order present in the struct (this is not always the case in DHCP option as the option_type is what
 * should be used in order to determine what will be read next)
 *
 * @see net_dhcp_discover_option for more information on the option fields structure
 *
 */
struct net_dhcp_discover_option {
	uint8_t dhcp_message_type_option_code;
	uint8_t dhcp_message_type_size;
	uint8_t dhcp_message_type_value;
	uint8_t client_identifier_option_code;
	uint8_t client_identifier_size;
	uint8_t client_identifier_hardware_value;
	uint8_t client_identifier_value[6];
	uint8_t requested_ip_address_option_code;
	uint8_t requested_ip_address_option_size;
	uint32_t requested_ip_address_option_value;
	uint8_t end_option_code;
} __attribute__((__packed__));

/**
 * @struct net_dhcp_request_option
 * @brief defines the fields of the option field of DHCPREQUEST packets sent from client to the DHCP server
 *
 * @pre the option fields define must be of the order present in the struct (this is not always the case in DHCP option as the option_type is what
 * should be used in order to determine what will be read next)
 */
struct net_dhcp_request_option {
	uint8_t dhcp_message_type_option_code;
	uint8_t dhcp_message_type_size;
	uint8_t dhcp_message_type_value;
	uint8_t client_identifier_option_code;
	uint8_t client_identifier_size;
	uint8_t client_identifier_hardware_value;
	uint8_t client_identifier_value[6];
	uint8_t requested_ip_address_option_code;
	uint8_t requested_ip_address_size;
	uint32_t requested_ip_address_value;
	uint8_t end_option_code;
} __attribute__((__packed__));

struct net_dhcp_nack_option {
	uint8_t dhcp_message_type_option_code;
	uint8_t dhcp_message_type_size;
	uint8_t dhcp_message_type_value;
	uint8_t end_option_code;
} __attribute__((__packed__));

/**
 * @brief value of the MAGIC_COOKIE informing that the options filed comming after it are to be read as DHCP options.
 *
 */
static const uint32_t DHCP_MAGIC_COOKIE = 0x63825363;

/**
 * @enum DHCP_message_type
 * @brief dhcp message type option values defining the type of DHCP packet
 *
 */
enum DHCP_message_type { DHCPDISCOVER = 1, DHCPOFFER = 2, DHCPREQUEST = 3, DHCPDECLINE = 4, DHCPACK = 5, DHCPNAK = 6, DHCPRELEASE = 7 };

/**
 * @enum DHCP_header_type
 * @brief defines from where a DHCP message originated from
 *
 */
enum DHCP_header_type { BOOTREQUEST = 1, BOOTREPLY = 2 };

/**
 * @brief Option type code that are used to identify option fields in DHCP packet option section
 *
 */
enum Option_code {
	DHCP_MESSAGE_TYPE = 53,
	REQUESTED_IP_ADDRESS = 50,
	DHCP_SERVER_IDENTIFIER = 54,
	DNS_NAME_SERVER = 6,
	ROUTER = 3,
	END_OPTION = 255,
	IP_ADDRESS_LEASE_TIME = 51,
	SUBNET_MASK = 1,
	CLIENT_IDENTIFIER = 61,
};

/**
 * @brief retrieves the DHCP header
 *
 * @param ipv4_header
 * @param out_net_dhcp_header
 * @return true if ipv4_header is next protocol is UDP, UDP dst port is 67 and UDP src port is 68 and the MAGIC_COOKIE value is valid
 * @return false
 */
static inline bool net_get_dhcp_header(struct net_ipv4_header* ipv4_header, struct net_dhcp_header** out_net_dhcp_header)
{
	if (ipv4_header->next_proto_id != IP_PROTOCOL_UDP) {
		return false;
	}
	struct net_tcpudp_header* tmp;
	if (!net_get_tcpudp_header(ipv4_header, &tmp)) {
		return false;
	}
	// Moving by 2 since net_tcpudp_header is 4 bytes and UDP header size is 8 bytes
	*out_net_dhcp_header = (struct net_dhcp_header*) (tmp + 2);
	return tmp->dst_port == 67 && tmp->src_port == 68 && (*out_net_dhcp_header)->magic_cookie == DHCP_MAGIC_COOKIE;
}

/**
 * @brief checks if the dhcp packet received is of type DHCPDISCOVER message
 *
 * @param dhcp_header
 * @return true
 * @return false
 */
static inline bool is_dhcp_discover_message(struct net_dhcp_header* dhcp_header)
{
	struct net_dhcp_discover_option* o = (struct net_dhcp_discover_option*) dhcp_header->options;
	return o->dhcp_message_type_value == DHCPDISCOVER && dhcp_header->op == BOOTREQUEST;
}

/**
 * @brief checks if the dhcp packet received is of type DHCPREQUEST message
 *
 * @param dhcp_header
 * @return true
 * @return false
 */
static inline bool is_dhcp_request_message(struct net_dhcp_header* dhcp_header)
{
	struct net_dhcp_request_option* o = (struct net_dhcp_request_option*) dhcp_header->options;
	return o->dhcp_message_type_value == DHCPREQUEST && dhcp_header->op == BOOTREQUEST;
}
/**
 * @brief Set the dhcp offer option object
 *
 * @param option
 */
static inline void set_dhcp_offer_option(struct net_dhcp_response_option* option)
{
	option->dhcp_message_type_value = DHCPOFFER;
	option->dhcp_server_identifier_option_code = DHCP_SERVER_IDENTIFIER;
	option->dhcp_server_identifier_size = 4;
	option->dns_server_ip_option_code = DNS_NAME_SERVER;
	option->dns_server_ip_size = 4;
	option->gateway_ip_option_code = ROUTER;
	option->gateway_ip_size = 4;
	option->ip_address_lease_time_option_code = IP_ADDRESS_LEASE_TIME;
	option->ip_address_lease_time_size = 4;
	option->subnet_mask_option_code = SUBNET_MASK;
	option->subnet_mask_size = 4;
	option->end_option_code = END_OPTION;
}

/**
 * @brief Set the dhcp ack option object
 *
 * @param option
 */
static inline void set_dhcp_ack_option(struct net_dhcp_response_option* option)
{
	option->dhcp_message_type_value = DHCPACK;
	option->dhcp_server_identifier_option_code = DHCP_SERVER_IDENTIFIER;
	option->dhcp_server_identifier_size = 4;
	option->dns_server_ip_option_code = DNS_NAME_SERVER;
	option->dns_server_ip_size = 4;
	option->gateway_ip_option_code = ROUTER;
	option->gateway_ip_size = 4;
	option->ip_address_lease_time_option_code = IP_ADDRESS_LEASE_TIME;
	option->ip_address_lease_time_size = 4;
	option->subnet_mask_option_code = SUBNET_MASK;
	option->subnet_mask_size = 4;
	option->end_option_code = END_OPTION;
}

static inline void set_dhcp_nack_option(struct net_dhcp_nack_option* option)
{
	option->dhcp_message_type_value = DHCPNAK;
	option->end_option_code = END_OPTION;
}