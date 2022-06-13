STATUS: Not verified

# Description
The goal of this nf is to act as a DNS resolver holding A records at the beginning.

These A records will be static and define by the config file.

## Discrepancy from the RFC
The expect the input packet passed to the NF padded with 0s in order to be able to fill in the requested answer sections (Ressource records) in the original packet memory region and return it to sender.

## DNS header format
We will use the DNS header defined in the [RFC 1035](https://datatracker.ietf.org/doc/html/rfc1035) except the DNSSEC flag which got extended in [RFC 2065](https://datatracker.ietf.org/doc/html/rfc2065).

| field name | size in bits | purpose                                                                                                           |
| ---------- | ------------ | ----------------------------------------------------------------------------------------------------------------- |
| ID         | 16           | This identifier is copied the corresponding reply and used to match up replies to outstanding queries.            |
| QR         | 1            | specifies whether this message is a query (0), or a response (1)                                                  | <!-- TODO at packet processing: set to 1 -->       |
| Opcode     | 4            | kind of query in this message (set by requester and just copied into response)                                    |
| AA         | 1            | specifies that the responding name server is an authority for the domain name in question section                 | <!-- TODO at packet processing: maybe set to 1 --> |
| TC         | 1            | specifies that this message was truncated due to length greater than that permitted on the transmission channel   | <!-- TODO at packet processing: set to 0 -->       |
| RD         | 1            | this bit may be set in a query and is copied into the response (Recursive query support is optional)              |
| RA         | 1            | this bit is set or cleared in a response, and denotes whether recursive query support is available in name server | <!-- TODO at packet processing: maybe set to 1 --> |
| Z          | 1            | reserved for future use, must be zero                                                                             | <!-- TODO at packet processing: set to 0 -->       |
| AD         | 1            | DNSSEC Stuff: return only Authenticated or Insecure data with the AD bit set in the response                      |
| CD         | 1            | DNSSEC Stuff: security aware resolver willing to do cryptography SHOULD assert the CD bit on all queries          |
| RCODE      | 4            | response code (0: no error condition, 1: Format error, 4: Not Implemented)                                        |
| QDCOUNT    | 16           | number of entries in the question section                                                                         |
| ANCOUNT    | 16           | number of resource records in the answer section                                                                  |
| NSCOUNT    | 16           | number of name server resource records in the authority records section                                           |
| ARCOUNT    | 16           | number of resource records in the additional records section                                                      |

All of the fields smaller then one byte were in our implementation concatinated to one Options field of size 16 bits.

## Question section format
This follows closely the https://datatracker.ietf.org/doc/html/rfc1035.

| field name | size in bits | purpose                                                                             |
| ---------- | ------------ | ----------------------------------------------------------------------------------- |
| QNAME      | *            | length-prefixed: follows the following format: www.example.com -> 3www7example3com0 |
| QTYPE      | 16           | type of the query (e.g. 0: A records)                                               | <!-- TODO at packet processing: check if Opcode!=1, set here to NotImplemented --> |
| QCLASS     | 16           | class of the query, most often 1=IN for Internet                                    |

## Resource record format
This follows closely the https://datatracker.ietf.org/doc/html/rfc1035.

| field name | size in bits | purpose                                                     |
| ---------- | ------------ | ----------------------------------------------------------- |
| NAME       | *            | domain name to which this resource record pertains          | <!-- TODO at packet processing: copy from question section --> |
| TYPE       | 16           | type of the query (e.g. 0: A records)                       | <!-- TODO at packet processing: copy from question section --> |
| CLASS      | 16           | class of the query, most often 1=IN for Internet            | <!-- TODO at packet processing: copy from question section --> |
| TTL        | 32           | resource record may be cached before it should be discarded | <!-- TODO at packet processing: set value from config.txt -->  |
| RDLENGTH   | 16           | length in octets of the RDATA field                         | <!-- TODO at packet processing: set value to 32 -->            |
| RDATA      | *            | describes the resource                                      | <!-- TODO at packet processing: set ip from config.txt -->     |

## Specifications
1. if an DNS reponse object was recieved
   1. If not, check for error packet (RCODE set to 1)
2. else if question sections have multiple entries or the one is none a-records type
   1. If not, check for error packet (RCODE set to 4)
3. else if requested NAME is not in dns-entries map
   1. If not, check for error packet (RCODE set to 3)
4. else, scan response
   1. if attributes of response and queries do not match
   2. if values of config.txt do not match