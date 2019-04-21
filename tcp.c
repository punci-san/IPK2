#include "include/tcp.h"

// Global variables that will work with callback functions
int port_state = 0;
pcap_t *handle_tcp = NULL;

/*********************************************************************************************************************************
* Title: Build IPv4 TCP pseudo-header and call checksum function (Section 8.1 of RFC 2460).
* Author: P. David Buchan
* Email pdbuchan@yahoo.com
* Date: March 6,2015
* Code version: 1.0
* Availability: http://www.pdbuchan.com/rawsock/rawsock.html?fbclid=IwAR2wUpdaHEzMfMwFQ6uC-3dlZZ7LDDY6YMkG8dEY-9NqrudMO9K7YTFEZnk
* Description: Build IPv4 TCP pseudo-header and call checksum function.
*********************************************************************************************************************************/
uint16_t tcp4_checksum (struct ip iphdr, struct tcphdr tcphdr)
{
  uint16_t svalue;
  char buf[IP_MAXPACKET], cvalue;
  char *ptr;
  int chksumlen = 0;

  // ptr points to beginning of buffer buf
  ptr = &buf[0];

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

  // Copy TCP length to buf (16 bits)
  svalue = htons (sizeof (tcphdr));
  memcpy (ptr, &svalue, sizeof (svalue));
  ptr += sizeof (svalue);
  chksumlen += sizeof (svalue);

  // Copy TCP source port to buf (16 bits)
  memcpy (ptr, &tcphdr.th_sport, sizeof (tcphdr.th_sport));
  ptr += sizeof (tcphdr.th_sport);
  chksumlen += sizeof (tcphdr.th_sport);

  // Copy TCP destination port to buf (16 bits)
  memcpy (ptr, &tcphdr.th_dport, sizeof (tcphdr.th_dport));
  ptr += sizeof (tcphdr.th_dport);
  chksumlen += sizeof (tcphdr.th_dport);

  // Copy sequence number to buf (32 bits)
  memcpy (ptr, &tcphdr.th_seq, sizeof (tcphdr.th_seq));
  ptr += sizeof (tcphdr.th_seq);
  chksumlen += sizeof (tcphdr.th_seq);

  // Copy acknowledgement number to buf (32 bits)
  memcpy (ptr, &tcphdr.th_ack, sizeof (tcphdr.th_ack));
  ptr += sizeof (tcphdr.th_ack);
  chksumlen += sizeof (tcphdr.th_ack);

  // Copy data offset to buf (4 bits) and
  // copy reserved bits to buf (4 bits)
  cvalue = (tcphdr.th_off << 4) + tcphdr.th_x2;
  memcpy (ptr, &cvalue, sizeof (cvalue));
  ptr += sizeof (cvalue);
  chksumlen += sizeof (cvalue);

  // Copy TCP flags to buf (8 bits)
  memcpy (ptr, &tcphdr.th_flags, sizeof (tcphdr.th_flags));
  ptr += sizeof (tcphdr.th_flags);
  chksumlen += sizeof (tcphdr.th_flags);

  // Copy TCP window size to buf (16 bits)
  memcpy (ptr, &tcphdr.th_win, sizeof (tcphdr.th_win));
  ptr += sizeof (tcphdr.th_win);
  chksumlen += sizeof (tcphdr.th_win);

  // Copy TCP checksum to buf (16 bits)
  // Zero, since we don't know it yet
  *ptr = 0; ptr++;
  *ptr = 0; ptr++;
  chksumlen += 2;

  // Copy urgent pointer to buf (16 bits)
  memcpy (ptr, &tcphdr.th_urp, sizeof (tcphdr.th_urp));
  ptr += sizeof (tcphdr.th_urp);
  chksumlen += sizeof (tcphdr.th_urp);

  return checksum ((uint16_t *) buf, chksumlen);
}

/*********************************************************************************************************************************
* Title: Build IPv6 TCP pseudo-header and call checksum function (Section 8.1 of RFC 2460).
* Author: P. David Buchan
* Email pdbuchan@yahoo.com
* Date: March 6,2015
* Code version: 1.0
* Availability: http://www.pdbuchan.com/rawsock/rawsock.html?fbclid=IwAR2wUpdaHEzMfMwFQ6uC-3dlZZ7LDDY6YMkG8dEY-9NqrudMO9K7YTFEZnk
* Description: Build IPv6 TCP pseudo-header and call checksum function.
*********************************************************************************************************************************/
uint16_t
tcp6_checksum (struct ip6_hdr iphdr, struct tcphdr tcphdr)
{
  uint32_t lvalue;
  char buf[IP_MAXPACKET], cvalue;
  char *ptr;
  int chksumlen = 0;

  ptr = &buf[0];  // ptr points to beginning of buffer buf

  // Copy source IP address into buf (128 bits)
  memcpy (ptr, &iphdr.ip6_src, sizeof (iphdr.ip6_src));
  ptr += sizeof (iphdr.ip6_src);
  chksumlen += sizeof (iphdr.ip6_src);

  // Copy destination IP address into buf (128 bits)
  memcpy (ptr, &iphdr.ip6_dst, sizeof (iphdr.ip6_dst));
  ptr += sizeof (iphdr.ip6_dst);
  chksumlen += sizeof (iphdr.ip6_dst);

  // Copy TCP length to buf (32 bits)
  lvalue = htonl (sizeof (tcphdr));
  memcpy (ptr, &lvalue, sizeof (lvalue));
  ptr += sizeof (lvalue);
  chksumlen += sizeof (lvalue);

  // Copy zero field to buf (24 bits)
  *ptr = 0; ptr++;
  *ptr = 0; ptr++;
  *ptr = 0; ptr++;
  chksumlen += 3;

  // Copy next header field to buf (8 bits)
  memcpy (ptr, &iphdr.ip6_nxt, sizeof (iphdr.ip6_nxt));
  ptr += sizeof (iphdr.ip6_nxt);
  chksumlen += sizeof (iphdr.ip6_nxt);

  // Copy TCP source port to buf (16 bits)
  memcpy (ptr, &tcphdr.th_sport, sizeof (tcphdr.th_sport));
  ptr += sizeof (tcphdr.th_sport);
  chksumlen += sizeof (tcphdr.th_sport);

  // Copy TCP destination port to buf (16 bits)
  memcpy (ptr, &tcphdr.th_dport, sizeof (tcphdr.th_dport));
  ptr += sizeof (tcphdr.th_dport);
  chksumlen += sizeof (tcphdr.th_dport);

  // Copy sequence number to buf (32 bits)
  memcpy (ptr, &tcphdr.th_seq, sizeof (tcphdr.th_seq));
  ptr += sizeof (tcphdr.th_seq);
  chksumlen += sizeof (tcphdr.th_seq);

  // Copy acknowledgement number to buf (32 bits)
  memcpy (ptr, &tcphdr.th_ack, sizeof (tcphdr.th_ack));
  ptr += sizeof (tcphdr.th_ack);
  chksumlen += sizeof (tcphdr.th_ack);

  // Copy data offset to buf (4 bits) and
  // copy reserved bits to buf (4 bits)
  cvalue = (tcphdr.th_off << 4) + tcphdr.th_x2;
  memcpy (ptr, &cvalue, sizeof (cvalue));
  ptr += sizeof (cvalue);
  chksumlen += sizeof (cvalue);

  // Copy TCP flags to buf (8 bits)
  memcpy (ptr, &tcphdr.th_flags, sizeof (tcphdr.th_flags));
  ptr += sizeof (tcphdr.th_flags);
  chksumlen += sizeof (tcphdr.th_flags);

  // Copy TCP window size to buf (16 bits)
  memcpy (ptr, &tcphdr.th_win, sizeof (tcphdr.th_win));
  ptr += sizeof (tcphdr.th_win);
  chksumlen += sizeof (tcphdr.th_win);

  // Copy TCP checksum to buf (16 bits)
  // Zero, since we don't know it yet
  *ptr = 0; ptr++;
  *ptr = 0; ptr++;
  chksumlen += 2;

  // Copy urgent pointer to buf (16 bits)
  memcpy (ptr, &tcphdr.th_urp, sizeof (tcphdr.th_urp));
  ptr += sizeof (tcphdr.th_urp);
  chksumlen += sizeof (tcphdr.th_urp);

  return checksum ((uint16_t *) buf, chksumlen);
}

/*********************************************************************************************************************************
* Function handling signal SIGALRM
* Source of information:
* https://www.tcpdump.org/manpages/pcap_loop.3pcap.html
*********************************************************************************************************************************/
void timeout_HANDLE_TCP()
{
  // Set port state into filtered so we know we need to check again
  port_state = FILTERED;
  
  // Break loop only when handle exist
  if(handle_tcp != NULL);
    pcap_breakloop(handle_tcp);
}

/*********************************************************************************************************************************
* Will check what type of packet we received and if it is TCP SYN/ACK or ACK/RST will set variables accordingly, works in IPV4
* Sources of information:
* https://www.tcpdump.org/manpages/pcap_loop.3pcap.html
* Packet analyzation from wireshark
*********************************************************************************************************************************/
void handler_TCP_IPV4(u_char *args,const struct pcap_pkthdr * header,const u_char *packet)
{
  // 48 and 49 byte of packet are bytes for flags in TCP header
  
  // 96 and 18 represent flags SYN and ACK
  if (packet[48] == 96 && packet[49] == 18)
  {
    // Set global variable to state OPEN
    port_state = OPEN;
  }
  // 80 and 20 represent flags SYN and RST 
  else if (packet[48] == 80 && packet[49] == 20)
  {
    // Set global variable to state CLOSED
    port_state = CLOSED;
  }
  // Packet that does not contain the correct values
  else
  {
    // Skip
    return;
  }
  
  // Right packet was found end loop if handle exist
  if(handle_tcp != NULL);
    pcap_breakloop(handle_tcp);
}

/*********************************************************************************************************************************
* Will check what type of packet we received and if it is TCP SYN/ACK or ACK/RST will set variables accordingly, works in IPV6
* Sources of information:
* https://www.tcpdump.org/manpages/pcap_loop.3pcap.html
* Packet analyzation from wireshark
*********************************************************************************************************************************/
void handler_TCP_IPV6(u_char *args,const struct pcap_pkthdr * header,const u_char *packet)
{
  // 68 and 69 byte of packet are bytes for flags in TCP header
  // 96 and 18 represent flags SYN and ACK
  if (packet[68] == 96 && packet[69] == 18)
  {
    // Set global variable to state OPEN
    port_state = OPEN;
  }
  // 80 and 20 represent flags SYN and RST 
  else if (packet[68] == 80 && packet[69] == 20)
  {
    // Set global variable to state CLOSED
    port_state = CLOSED;
  }
  // Packet that does not contain the correct values
  else
  {
    // Skip
    return;
  }
  
  // Right packet was found end loop if handle exist
  if(handle_tcp != NULL);
    pcap_breakloop(handle_tcp);
}

/*********************************************************************************************************************************
* Create socket and generate IPV6 TCP packet to be sent to the dst_addr and start listening for incoming packets
* Sources of information:
* http://man7.org/linux/man-pages/man2/socket.2.html
* http://man7.org/linux/man-pages/man3/setsockopt.3p.html
* https://en.wikipedia.org/wiki/IPv6
* https://en.wikipedia.org/wiki/Transmission_Control_Protocol
* https://www.tcpdump.org/pcap.html
*********************************************************************************************************************************/
int scan_IPV6_TCP(char *dst_addr,char *src_addr,char *device,int port)
{
  // Variables
  int tcp_socket = 0;
  int res = 0;

  // Packet
  char buffer[IP_MAXPACKET];
  struct ip6_hdr  *ip6 = (struct ip6_hdr *)&buffer;
  struct tcphdr *tcp = (struct tcphdr *)(buffer + sizeof(struct ip6_hdr));

  // Settings
  struct sockaddr_in6 sin, din;
  int one = 1;
  const int *val = &one;

  // Clear buffer
  memset(&buffer,0,IP_MAXPACKET);
  memset(&sin,0,sizeof(sin));
  memset(&din,0,sizeof(din));

  // Create socket ipv6
  tcp_socket = socket(AF_INET6, SOCK_RAW, IPPROTO_TCP);

  // Is socket ok ?
  if (tcp_socket < 0)
  {
    perror("soccket() error");
    return -1;
  }

  // Tell os to not modify this socket
	if(setsockopt(tcp_socket, IPPROTO_IPV6, IPV6_HDRINCL, val, sizeof(one)) < 0)
	{
		perror("setsockopt() error");
		return -1;
	}

  // Set IPV6 family
  sin.sin6_family = AF_INET6;
  din.sin6_family = AF_INET6;

  // Set ports
  sin.sin6_port = htons(SRC_PORT);
  din.sin6_port = htons(0);
  
  // Set addresses
  inet_pton(AF_INET6,src_addr,&(sin.sin6_addr));
  inet_pton(AF_INET6,dst_addr,&(din.sin6_addr));

  // Set Internet protocol IPV6

  // Set addresses
  inet_pton(AF_INET6,src_addr,&(ip6->ip6_src));     /* Source address */
  inet_pton(AF_INET6,dst_addr,&(ip6->ip6_dst));     /* Destination address */
  ip6->ip6_flow = htonl(0b01100000000000000000000000000000);                    /* 20 bits of flow-ID */
  ip6->ip6_plen = htons(sizeof(struct tcphdr));	 /* payload length */
  ip6->ip6_nxt = (IPPROTO_TCP);       /* Next header */
  ip6->ip6_hlim = (MAXTTL);	          /* hop limit */

  // Set TCP protocol 
  tcp->th_sport = htons(SRC_PORT);    /* Source port */
  tcp->th_dport = htons(port);        /* Destination port */
  tcp->th_seq = SEQ_NUM;              /* Sequence number */
  tcp->th_ack = htonl(0);             /* Acknowledgment number */
  tcp->th_x2 = htonl(0);              /* Unused */
  tcp->th_off = IPV4_HL;              /* Data offset (header size) */
  // Set SYN flag that is used for in first  chapter of 3 way handshake
  tcp->th_flags = TH_SYN;             /* Flags */
  tcp->th_win = htons(32767);         /* Window size */
  tcp->th_sum = tcp6_checksum(*ip6,*tcp); /* Checksum */
  tcp->th_urp = 0;                    /* Urgent pointer */

  // Set capture device FALSE = IPV6,TRUE = TCP
  if ((handle_tcp = set_capture_device(device,dst_addr,FALSE,TRUE)) == NULL)
  {
    return -1;
  }

  // Send packet
  if (sendto(tcp_socket,buffer,sizeof(struct tcphdr) + sizeof(struct ip6_hdr),0,(struct sockaddr *)&din,sizeof(din)) < 0)
  {
    perror("sendto() failed");
    return -1;
  }

  // Start timeout for checking if TCP port is filtered
  ualarm(500000,0);

  // Signal to handle timeout
  signal(SIGALRM,timeout_HANDLE_TCP);

  // Start loop for scanning of packets
  pcap_loop(handle_tcp,-1,handler_TCP_IPV6,NULL);

  // Close socket and handler and return port state
  pcap_close(handle_tcp);
  close(tcp_socket);
  return TRUE;
}

/*********************************************************************************************************************************
* Create socket and generate IPV4 TCP packet to be sent to the dst_addr and start listening for incoming packets
* Sources of information:
* http://man7.org/linux/man-pages/man2/socket.2.html
* http://man7.org/linux/man-pages/man3/setsockopt.3p.html
* https://en.wikipedia.org/wiki/IPv4
* https://en.wikipedia.org/wiki/Transmission_Control_Protocol
* https://www.tcpdump.org/pcap.html
*********************************************************************************************************************************/
int scan_IPV4_TCP(char *dst_addr,char *src_addr,char *device,int port)
{
  // Variables
  int tcp_socket = 0;
  int res = 0;

  // Packet
  char buffer[PACKET_LEN];
  struct ip *ip = (struct ip *)buffer;
  struct tcphdr *tcp = (struct tcphdr  *)(buffer + sizeof(struct ip));

  // Settings
  struct sockaddr_in sin, din;
  int one = 1;
  const int *val = &one;

  // Clear string
  memset(&buffer,0,PACKET_LEN);
  memset(&sin,0,sizeof(sin));
  memset(&din,0,sizeof(din));

  // Create socket IPV4 tcp socket
  tcp_socket = socket(PF_INET, SOCK_RAW, IPPROTO_TCP);

  // Is socket ok ?
  if (tcp_socket < 0)
  {
    // No error
    perror("soccket() error");
    return -1;
  }

  // Tell os to not modify this socket
	if(setsockopt(tcp_socket, IPPROTO_IP, IP_HDRINCL, val, sizeof(one)) < 0)
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

  // Set ipv4 address
  inet_pton(AF_INET,src_addr,&(sin.sin_addr));
  inet_pton(AF_INET,dst_addr,&(din.sin_addr));

  // Set IP packet version 4 IPV4
  ip->ip_hl = IPV4_HL;          /* Header length */
  ip->ip_v = IPV4_V;           /* Version */
  ip->ip_tos = IPV4_SERVICE;         /* Type of service */
  ip->ip_len = sizeof(struct ip) + sizeof(struct tcphdr);         /* Total length */
  ip->ip_id = htons(1254);          /* Identification */
  ip->ip_off = IPV4_OFFSET;         /* Fragment offset field */
  ip->ip_ttl = MAXTTL;         /* Time to live */
  ip->ip_p = IPPROTO_TCP;           /* Protocol */
  ip->ip_sum = 0;               /* Checksum */
  ip->ip_src = sin.sin_addr;         /* Source address */
  ip->ip_dst = din.sin_addr;         /* Destination address */

  // Set TCP protocol 
  tcp->th_sport = htons(SRC_PORT);    /* Source port */
  tcp->th_dport = htons(port);        /* Destination port */
  tcp->th_seq = SEQ_NUM;       /* Sequence number */
  tcp->th_ack = htonl(0);             /* Acknowledgment number */
  tcp->th_x2 = htonl(0);              /* Unused */
  tcp->th_off = IPV4_HL;              /* Data offset (header size) */
  // Set SYN flag that is used for in first  chapter of 3 way handshake
  tcp->th_flags = TH_SYN;             /* Flags */
  tcp->th_win = htons(32767);         /* Window size */
  tcp->th_sum = tcp4_checksum(*ip,*tcp);
  tcp->th_urp = 0;                    /* Urgent pointer */

  // Set capture device for TCP IPV4 
  if ((handle_tcp = set_capture_device(device,dst_addr,TRUE,TRUE)) == NULL)// 1. TRUE = TCP, 2. TRUE = IPV4
  {
    return -1;
  }

  // Send generated packet to the dst_address
  if (sendto(tcp_socket,buffer,ip->ip_len,0,(struct sockaddr *)&din,sizeof(din)) < 0)
  {
    perror("sendto() failed");
    return -1;
  }

  // Start timeout for checking if port is filtered
  ualarm(500000,0);

  // Signal to handle timeout
  signal(SIGALRM,timeout_HANDLE_TCP);

  // Start loop where we receive packets
  pcap_loop(handle_tcp,-1,handler_TCP_IPV4,NULL);

  // Close socket and handler and return success
  pcap_close(handle_tcp);
  close(tcp_socket);
  return TRUE;
}

/*********************************************************************************************************************************
* Function to help with the UDP scanning of one port in IPV4 or IPV6 mode 
*********************************************************************************************************************************/
int scan_port_TCP(struct addrinfo *dest,char *interface,int port,int *ipv4_only)
{
  // variables
  int res = 0;
  char dst_buff[BUF_SIZE];
  char src_buff[BUF_SIZE];

  // Reset buffer
  memset(&src_buff,0,BUF_SIZE);
  memset(&dst_buff,0,BUF_SIZE);

  // Get destination IP
  if (get_ip(dest,dst_buff,ipv4_only))
  {
    return -1;
  }

  // Get source IP
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
      // TCP when first packet did not arrive we check second time if it is really filtered that port
      for(int i = 0;i < 2;i++)
      {
        // Set port state into something that is not port type
        port_state = -1;

        // Scan for port in IPV4 mode
        res = scan_IPV4_TCP(dst_buff,src_buff,interface,port);

        // Scan failed 
        if (res < 0)
        {
          // Scan failed
          return EXIT_FAILURE;
        }

        // Check again if it is really filtered
        if (port_state == FILTERED)
        {
          continue;
        }
        // End from for loop
        break;
      }
      // End from while loop
      break;
    }
    // IPV6 scan
    else
    {
      // TCP when first packet did not arrive we check second time if it is really filtered that port
      for (int i = 0; i < 2; i++)
      {
        // Scan for port
        res = scan_IPV6_TCP(dst_buff,src_buff,interface,port);

        // Scan failed
        if (res < 0)
        {
          // Change to IPV4 and try again
          *ipv4_only = TRUE;

          // Reset buffer and get IP
          memset(&src_buff,0,BUF_SIZE);
          memset(&dst_buff,0,BUF_SIZE);

          // Get destination IP
          if (get_ip(dest,dst_buff,ipv4_only))
          {
            return -1;
          }

          // Get source IP
          if (get_our_ip(src_buff,interface,*ipv4_only))
          {
            return -1;
          }
        }
        
        // We need to check again if it is really filtered
        if (port_state == FILTERED)
        {
          continue;
        }

        // Scan OK end from for loop
        break;
      }

      // IF IPV4 is set try scan with IPV4 method
      if (*ipv4_only == TRUE)
      {
        continue;
      }

      // Break from while loop
      break;
    }
  }
  // Print result of scan
  printf("%d/tcp\t%s\n", port,(port_state == OPEN) ? "OPEN" : (port_state == FILTERED) ? "FILTERED" : "CLOSED");

  // Return OK
  return 0;
}
