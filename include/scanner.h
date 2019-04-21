#ifndef _H_SCANNER
#define _H_SCANNER

// Scanner constants
#define BUF_SIZE 1024
#define PACKET_LEN 8192
#define TRUE 1
#define FALSE 0
#define SRC_PORT 40528

// IPV4 default values
#define IPV4_HL 5
#define IPV4_V 4
#define IPV4_SERVICE 0
#define IPV4_OFFSET 0
#define ICMP_PROTO 1
#define TCP_PROTO 6

// Timeout for packet capture
#define UDP_TIMEOUT 50
#define ETHER_SIZE 16
#define SEQ_NUM 2531

// Uchar
#define U_CHAR_T 0x01
#define U_CHAR_F 0x02

// Port states
#define FILTERED 2
#define OPEN 1
#define CLOSED 0

#include <stdlib.h>
#include <arpa/inet.h> // inet_ntop
#include <string.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/if_ether.h>
#include <netinet/ip_icmp.h>
#include <netinet/tcp.h>
#include <netdb.h> // addrinfo
#include <pcap/pcap.h>
#include <ifaddrs.h>// ifaddrs
#include <net/if.h>
#include <unistd.h>
#include <sys/socket.h>
#include <signal.h>

struct addrinfo *get_addr(char *, int *);
int get_ip(struct addrinfo *,char *,int *);
int get_our_ip(char *,char *,int);
int find_capture_device(char *,char *);

pcap_t* set_capture_device(char *, char *,int,int);
int capture_icmp_packet(pcap_t *handle, int,int);
int capture_tcp_packet(pcap_t *handle,int);

uint16_t checksum (uint16_t *addr, int len);
#endif
