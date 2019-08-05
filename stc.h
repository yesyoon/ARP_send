#ifndef STC_H
#define STC_H

#endif // STC_H

#include <stdint.h>
#include <pcap.h>


struct _Ethernet_header
{
    uint8_t edst_mac[6];
    uint8_t esrc_mac[6];
    uint16_t e_type;

};

struct _request_arp_packet
{
      uint16_t hardware_type;
      uint16_t protocol_type;
      uint8_t	hardware_len;
      uint8_t	protocol_len;
      uint16_t opcode;
      uint8_t	sender_mac[6];
      uint8_t	sender_ip[4];
      uint8_t	target_mac[6];
      uint8_t	target_ip[4];

};

struct _reply_arp_packet
{
      uint16_t hardware_type;
      uint16_t protocol_type;
      uint8_t	hardware_len;
      uint8_t	protocol_len;
      uint16_t opcode;
      uint8_t	sender_mac[6];
      uint8_t	sender_ip[4];
      uint8_t	target_mac[6];
      uint8_t	target_ip[4];

};

