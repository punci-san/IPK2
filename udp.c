#include "include/udp.h"

#include <sys/ioctl.h>
#include <net/if.h>
#include <linux/if_packet.h>

// Global variables for callback functions
int port_state_udp = -1;
int port_udp = 0;
pcap_t *handle_udp = NULL;

/*******************************************************************************************************
* Title: UDP ipv6 checksum calculation function
* Author: P. David Buchan
* Email pdbuchan@yahoo.com
* Date: March 6,2015
* Code version: 1.0
* Availability: http://www.pdbuchan.com/rawsock/rawsock.html?fbclid=IwAR2wUpdaHEzMfMwFQ6uC-3dlZZ7LDDY6YMkG8dEY-9NqrudMO9K7YTFEZnk
* Description: Function for calculating IPV6 UDP checksum
*******************************************************************************************************/
uint16_t udp6_checksum (struct ip6_hdr iphdr, struct udphdr udphdr, uint8_t *payload, int payloadlen)
{
  char buf[IP_MAXPACKET];
  char *ptr;
  int chksumlen = 0;
  int i;

  ptr = &buf[0];  // ptr points to beginning of buffer buf

  // Copy source IP address into buf (128 bits)
  memcpy (ptr, &iphdr.ip6_src.s6_addr, sizeof (iphdr.ip6_src.s6_addr));
  ptr += sizeof (iphdr.ip6_src.s6_addr);
  chksumlen += sizeof (iphdr.ip6_src.s6_addr);

  // Copy destination IP address into buf (128 bits)
  memcpy (ptr, &iphdr.ip6_dst.s6_addr, sizeof (iphdr.ip6_dst.s6_addr));
  ptr += sizeof (iphdr.ip6_dst.s6_addr);
  chksumlen += sizeof (iphdr.ip6_dst.s6_addr);

  // Copy UDP length into buf (32 bits)
  memcpy (ptr, &udphdr.len, sizeof (udphdr.len));
  ptr += sizeof (udphdr.len);
  chksumlen += sizeof (udphdr.len);

  // Copy zero field to buf (24 bits)
  *ptr = 0; ptr++;
  *ptr = 0; ptr++;
  *ptr = 0; ptr++;
  chksumlen += 3;

  // Copy next header field to buf (8 bits)
  memcpy (ptr, &iphdr.ip6_nxt, sizeof (iphdr.ip6_nxt));
  ptr += sizeof (iphdr.ip6_nxt);
  chksumlen += sizeof (iphdr.ip6_nxt);

  // Copy UDP source port to buf (16 bits)
  memcpy (ptr, &udphdr.source, sizeof (udphdr.source));
  ptr += sizeof (udphdr.source);
  chksumlen += sizeof (udphdr.source);

  // Copy UDP destination port to buf (16 bits)
  memcpy (ptr, &udphdr.dest, sizeof (udphdr.dest));
  ptr += sizeof (udphdr.dest);
  chksumlen += sizeof (udphdr.dest);

  // Copy UDP length again to buf (16 bits)
  memcpy (ptr, &udphdr.len, sizeof (udphdr.len));
  ptr += sizeof (udphdr.len);
  chksumlen += sizeof (udphdr.len);

  // Copy UDP checksum to buf (16 bits)
  // Zero, since we don't know it yet
  *ptr = 0; ptr++;
  *ptr = 0; ptr++;
  chksumlen += 2;

  // Copy payload to buf
  memcpy (ptr, payload, payloadlen * sizeof (uint8_t));
  ptr += payloadlen;
  chksumlen += payloadlen;

  // Pad to the next 16-bit boundary
  for (i=0; i<payloadlen%2; i++, ptr++) {
    *ptr = 0;
    ptr++;
    chksumlen++;
  }

  return checksum ((uint16_t *) buf, chksumlen);
}

/*******************************************************************************************************
* Title: UDP ipv4 checksum calculation function
* Author: P. David Buchan
* Email pdbuchan@yahoo.com
* Date: March 6,2015
* Code version: 1.0
* Availability: http://www.pdbuchan.com/rawsock/rawsock.html?fbclid=IwAR2wUpdaHEzMfMwFQ6uC-3dlZZ7LDDY6YMkG8dEY-9NqrudMO9K7YTFEZnk
* Description: Function for calculating IPV4 UDP checksum
*******************************************************************************************************/
uint16_t udp4_checksum (struct ip iphdr, struct udphdr udphdr, uint8_t *payload, int payloadlen)
{
  char buf[IP_MAXPACKET];
  char *ptr;
  int chksumlen = 0;
  int i;

  ptr = &buf[0];  // ptr points to beginning of buffer buf

  // Copy source IP address into buf (32 bits)
  memcpy (ptr, &iphdr.ip_src.s_addr, sizeof (iphdr.ip_src.s_addr));
  ptr += sizeof (iphdr.ip_src.s_addr);
  chksumlen += sizeof (iphdr.ip_src.s_addr);

  // Copy destination IP address into buf (32 bits)
  memcpy (ptr, &iphdr.ip_dst.s_addr, sizeof (iphdr.ip_dst.s_addr));
  ptr += sizeof (iphdr.ip_dst.s_addr);
  chksumlen += sizeof (iphdr.ip_dst.s_addr);

  // Copy zero field to buf (8 bits)
  *ptr = 0; ptr++;
  chksumlen += 1;

  // Copy transport layer protocol to buf (8 bits)
  memcpy (ptr, &iphdr.ip_p, sizeof (iphdr.ip_p));
  ptr += sizeof (iphdr.ip_p);
  chksumlen += sizeof (iphdr.ip_p);

  // Copy UDP length to buf (16 bits)
  memcpy (ptr, &udphdr.len, sizeof (udphdr.len));
  ptr += sizeof (udphdr.len);
  chksumlen += sizeof (udphdr.len);

  // Copy UDP source port to buf (16 bits)
  memcpy (ptr, &udphdr.source, sizeof (udphdr.source));
  ptr += sizeof (udphdr.source);
  chksumlen += sizeof (udphdr.source);

  // Copy UDP destination port to buf (16 bits)
  memcpy (ptr, &udphdr.dest, sizeof (udphdr.dest));
  ptr += sizeof (udphdr.dest);
  chksumlen += sizeof (udphdr.dest);

  // Copy UDP length again to buf (16 bits)
  memcpy (ptr, &udphdr.len, sizeof (udphdr.len));
  ptr += sizeof (udphdr.len);
  chksumlen += sizeof (udphdr.len);

  // Copy UDP checksum to buf (16 bits)
  // Zero, since we don't know it yet
  *ptr = 0; ptr++;
  *ptr = 0; ptr++;
  chksumlen += 2;

  // Copy payload to buf
  memcpy (ptr, payload, payloadlen);
  ptr += payloadlen;
  chksumlen += payloadlen;

  // Pad to the next 16-bit boundary
  for (i=0; i<payloadlen%2; i++, ptr++) {
    *ptr = 0;
    ptr++;
    chksumlen++;
  }

  return checksum ((uint16_t *) buf, chksumlen);
}

/*********************************************************************************************************************************
* Function handling signal SIGALRM
* Source of information:
* https://www.tcpdump.org/manpages/pcap_loop.3pcap.html
*********************************************************************************************************************************/
void timeout_HANDLE_UDP()
{
  printf("%d/udp\topen\n",port_udp);

  // Break pcap_loop() if handle is defined
  if(handle_udp != NULL);
    pcap_breakloop(handle_udp);
}

/*********************************************************************************************************************************
* Based on filter we know that we received ICMP packet so we know the port is closed
* Sources of information:
* https://www.tcpdump.org/manpages/pcap_loop.3pcap.html
* Packet analyzation from wireshark
*********************************************************************************************************************************/
void handler_ICMP(u_char *args,const struct pcap_pkthdr * header,const u_char *packet)
{
  // Print the port is closed
  printf("%d/udp\tclosed\n",port_udp);
  
  // Break pcap_loop()
  if(handle_udp != NULL);
    pcap_breakloop(handle_udp);
    
}

/*********************************************************************************************************************************
* Create socket and generate IPV6 UDP packet to be sent to the dst_addr and start listening for incoming packets
* Sources of information:
* http://man7.org/linux/man-pages/man2/socket.2.html
* http://man7.org/linux/man-pages/man3/setsockopt.3p.html
* https://en.wikipedia.org/wiki/IPv4
* https://en.wikipedia.org/wiki/User_Datagram_Protocol
* https://www.tcpdump.org/pcap.html
*********************************************************************************************************************************/
int scan_IPV6_UDP(char *dst_addr,char *src_addr,char *device,int port)
{
  // Variables
  int udp_socket = 0;
  int res = 0;

  // Packet
  char buffer[IP_MAXPACKET];
  struct ip6_hdr  *ip6 = (struct ip6_hdr *)&buffer;
  struct udphdr *udp = (struct udphdr *)(buffer + sizeof(struct ip6_hdr));

  // Settings
  struct sockaddr_in6 sin, din;
  int one = 1;
  const int *val = &one;

  // Clear string
  memset(&buffer,0,IP_MAXPACKET);
  memset(&sin,0,sizeof(sin));
  memset(&din,0,sizeof(din));

  // Set global port for callback functions
  port_udp = port;

  // Create socket ipv6
  udp_socket = socket(AF_INET6, SOCK_RAW, IPPROTO_UDP);

  // Is socket ok ?
  if (udp_socket < 0)
  {
    perror("soccket() error");
    return -1;
  }

  // Tell os to not modify this socket
	if(setsockopt(udp_socket, IPPROTO_IPV6, IPV6_HDRINCL, val, sizeof(one)) < 0)
	{
		perror("setsockopt() error");
		return -1;
	}

  // Set IPV6
  sin.sin6_family = AF_INET6;
  din.sin6_family = AF_INET6;

  // Set ports
  sin.sin6_port = htons(SRC_PORT);
  din.sin6_port = htons(0);
  
  // Set address
  inet_pton(AF_INET6,src_addr,&(sin.sin6_addr));
  inet_pton(AF_INET6,dst_addr,&(din.sin6_addr));

  inet_pton(AF_INET6,src_addr,&(ip6->ip6_src));     /* Source address */
  inet_pton(AF_INET6,dst_addr,&(ip6->ip6_dst));     /* Destination address */

  // Set Internet protocol IPV6
  ip6->ip6_flow = htonl(0b01100000000000000000000000000000);                    /* 20 bits of flow-ID */
  ip6->ip6_plen = htons(sizeof(struct udphdr));	 /* payload length */
  ip6->ip6_nxt = (IPPROTO_UDP);       /* Next header */
  ip6->ip6_hlim = (MAXTTL);	          /* hop limit */

  // Set UDP protocol
  udp->uh_sport = htons(SRC_PORT);
  udp->uh_dport = htons(port);
  udp->uh_ulen = htons(sizeof(struct udphdr));
  udp->uh_sum = (udp6_checksum(*ip6,*udp,NULL,0));

  // Set capture device FALSE = IPV6,FALSE = UDP
  if ((handle_udp = set_capture_device(device,dst_addr,FALSE,FALSE)) == NULL)
  {
    return -1;
  }

  // Send packet
  if (sendto(udp_socket,buffer,sizeof(struct udphdr) + sizeof(struct ip6_hdr),0,(struct sockaddr *)&din,sizeof(din)) < 0)
  {
    perror("sendto() failed");
    return -1;
  }

  // Start timeout for checking if port is OPEN
  ualarm(500000,0);

  // Signal for handling timeout
  signal(SIGALRM,timeout_HANDLE_UDP);

  // Start loop for receiving ICMP packets
  pcap_loop(handle_udp,-1,handler_ICMP,NULL);

  // Close socket and handler and return port state
  pcap_close(handle_udp);
  close(udp_socket);
  return TRUE;
}

/*********************************************************************************************************************************
* Create socket and generate IPV4 UDP packet to be sent to the dst_addr and start listening for incoming packets
* Sources of information:
* http://man7.org/linux/man-pages/man2/socket.2.html
* http://man7.org/linux/man-pages/man3/setsockopt.3p.html
* https://en.wikipedia.org/wiki/IPv4
* https://en.wikipedia.org/wiki/User_Datagram_Protocol
* https://www.tcpdump.org/pcap.html
*********************************************************************************************************************************/
int scan_IPV4_UDP(char *dst_addr,char *src_addr,char *device,int port)
{
  // Variables
  int udp_socket = 0;
  u_char arg = U_CHAR_T;

  // Packet
  char buffer[PACKET_LEN];
  struct ip *ip = (struct ip *)buffer;
  struct udphdr *udp = (struct udphdr *)(buffer + sizeof(struct ip));

  //pcap_t *handle = NULL;

  // Settings
  struct sockaddr_in sin, din;
  int one = 1;
  const int *val = &one;

  // Set global port
  port_udp = port;

  // Clear string
  memset(&buffer,0,PACKET_LEN);
  memset(&sin,0,sizeof(sin));
  memset(&din,0,sizeof(din));

  // Create socket
  udp_socket = socket(PF_INET, SOCK_RAW, IPPROTO_UDP);

  // Is socket ok ?
  if (udp_socket < 0)
  {
    perror("soccket() error");
    return -1;
  }

  // Tell os to not modify this socket
	if(setsockopt(udp_socket, IPPROTO_IP, IP_HDRINCL, val, sizeof(one)) < 0)
	{
		perror("setsockopt() error");
		return -1;
	}

  // Set IPV4
  sin.sin_family = AF_INET;
  din.sin_family = AF_INET;

  // Set ports
  sin.sin_port = htons(SRC_PORT);
  din.sin_port = htons(port);

  // Set address
  inet_pton(AF_INET,src_addr,&(sin.sin_addr));
  inet_pton(AF_INET,dst_addr,&(din.sin_addr));

  // Set Internet protocol IPV4
  ip->ip_hl = IPV4_HL;          /* Header length */
  ip->ip_v = IPV4_V;           /* Version */

  ip->ip_tos = IPV4_SERVICE;         /* Type of service */
  ip->ip_len = sizeof(struct ip) + sizeof(struct udphdr);         /* Total length */
  ip->ip_id = htons(1254);          /* Identification */
  ip->ip_off = IPV4_OFFSET;         /* Fragment offset field */

  ip->ip_ttl = MAXTTL;         /* Time to live */
  ip->ip_p = IPPROTO_UDP;           /* Protocol */
  ip->ip_sum = 0;               /* Checksum */
  ip->ip_src = sin.sin_addr;         /* Source address */
  ip->ip_dst = din.sin_addr;         /* Destination address */

  // Set UDP protocol
  udp->uh_sport = htons(SRC_PORT);
  udp->uh_dport = htons(port);
  udp->uh_ulen = htons(sizeof(struct udphdr));
	udp->uh_sum = udp4_checksum(*ip,*udp,NULL,0);

  // Set capture device TRUE = IPV4,FALSE = UDP
  if ((handle_udp = set_capture_device(device,dst_addr,TRUE,FALSE)) == NULL)
  {
    return -1;
  }

  // Send packet
  if (sendto(udp_socket,buffer,ip->ip_len,0,(struct sockaddr *)&din,sizeof(din)) < 0)
  {
    perror("sendto() failed");
    return -1;
  }

  // Start timeout
  ualarm(500000,0);

  // Signal
  signal(SIGALRM,timeout_HANDLE_UDP);

  // Start loop
  int test = pcap_loop(handle_udp,-1,handler_ICMP,NULL);

  // Close socket and handler and return port state
  pcap_close(handle_udp);
  close(udp_socket);
  return TRUE;
}

/*********************************************************************************************************************************
* Function to help with the UDP scanning of one port in IPV4 or IPV6 mode 
*********************************************************************************************************************************/
int scan_port_UDP(struct addrinfo *dest,char *interface,int port,int *ipv4_only)
{
  // Result of scan
  int res = 0;
  char dst_buff[BUF_SIZE];
  char src_buff[BUF_SIZE];

  // Reset buffer and get IP
  memset(&src_buff,0,BUF_SIZE);
  memset(&dst_buff,0,BUF_SIZE);

  // Destination IP
  if (get_ip(dest,dst_buff,ipv4_only))
  {
    return -1;
  }

  // Source IP
  if (get_our_ip(src_buff,interface,*ipv4_only) < 0)
  {
    return -1;
  }

  // Loop if IPV6 fail we switch to IPV4
  while(TRUE)
  {
    // Scan using IPV4
    if (*ipv4_only)
    {
      // If port 
      for (int i = 0; i <UDP_PORT_LOOP; i++)
      {
        // Scan for port
        res = scan_IPV4_UDP(dst_buff,src_buff,interface,port);

        // Scan failed
        if (res < 0)
        {
          // Scan failed
          return EXIT_FAILURE;
        }

        // We need to check few more times if it is really open
        if (port_state_udp == OPEN)
        {
          continue;
        }
        // Port is closed break and tell
        break;
      }

      // End
      break;
    }
    // IPV6 scan
    else
    {
      // Scan for port
      res = scan_IPV6_UDP(dst_buff,src_buff,interface,port);

      // Scan failed
      if (res < 0)
      {
        // Change to IPV4 and try again
        *ipv4_only = TRUE;

        // Reset buffer and get IP
        memset(&src_buff,0,BUF_SIZE);
        memset(&dst_buff,0,BUF_SIZE);

        // Destination IP
        if (get_ip(dest,dst_buff,ipv4_only))
        {
          return -1;
        }

        // Source IP
        if (get_our_ip(src_buff,interface,*ipv4_only))
        {
          return -1;
        }
        continue;
      }

      // Scan OK
      break;
    }
  }

  // Return success
  return EXIT_SUCCESS;
}
