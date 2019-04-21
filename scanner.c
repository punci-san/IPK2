#include "include/scanner.h"

/*******************************************************************************************************
* Title: Internet checksum computation (RFC 1071)
* Author: P. David Buchan
* Email pdbuchan@yahoo.com
* Date: March 6,2015
* Code version: 1.0
* Availability: http://www.pdbuchan.com/rawsock/rawsock.html?fbclid=IwAR2wUpdaHEzMfMwFQ6uC-3dlZZ7LDDY6YMkG8dEY-9NqrudMO9K7YTFEZnk
* Description: Function for computing the internet checksum (RFC 1071)
*******************************************************************************************************/
uint16_t checksum (uint16_t *addr, int len)
{
  int count = len;
  register uint32_t sum = 0;
  uint16_t answer = 0;

  // Sum up 2-byte values until none or only one byte left.
  while (count > 1) 
  {
    sum += *(addr++);
    count -= 2;
  }

  // Add left-over byte, if any.
  if (count > 0) {
    sum += *(uint8_t *) addr;
  }

  // Fold 32-bit sum into 16 bits; we lose information by doing this,
  // increasing the chances of a collision.
  // sum = (lower 16 bits) + (upper 16 bits shifted right 16 bits)
  while (sum >> 16) {
    sum = (sum & 0xffff) + (sum >> 16);
  }

  // Checksum is one's compliment of sum.
  answer = ~sum;

  return (answer);
}

/*********************************************************************************************************************************
* Will return first IPV6 or IPV4 address
* Source of information:
* http://man7.org/linux/man-pages/man3/getaddrinfo.3.html
*********************************************************************************************************************************/
struct addrinfo *get_addr(char* domain,int *ipv4_only)
{
  // Variables
  struct addrinfo hints;
  struct addrinfo *result = NULL;
  int s = 0;

  // Null hints
  memset(&hints,0,sizeof(hints));

  // Set hints
  hints.ai_family = PF_UNSPEC;
  hints.ai_socktype = SOCK_STREAM;

  // Get information about domain
  s = getaddrinfo(domain,NULL,&hints,&result);

  // Did it fail ?
  if (s)
  {
    // Print error and end
    fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(s));
    return NULL;
  }

  // Look for given IP
  while (result)
  {
    // IPV6
    if (result->ai_family== AF_INET6 && !(*ipv4_only))
    {
      return result;
    }
    // IPV4
    else if (result->ai_family == AF_INET)
    {
      // We are working in IPV4 domain
      *ipv4_only = TRUE;
      return result;
    }
    // Get next IP
    result = result->ai_next;
  }

  // Return first found IP address
  return result;
}

/*********************************************************************************************************************************
* Title: Convert addrinfo into human readable IP
* Author: Jiri Hnidek
* Date: February 7,2019
* Availability: https://gist.github.com/jirihnidek/bf7a2363e480491da72301b228b35d5d
* Description: Convert addrinfo into humand readable form
*********************************************************************************************************************************/
int get_ip(struct addrinfo *addr,char *buf,int *ipv4_only)
{
  // No address was given
  if (!addr)
  {
    // Return error
    return EXIT_FAILURE;
  }

  inet_ntop(addr->ai_family, addr->ai_addr->sa_data, buf, INET_ADDRSTRLEN);

  // Is it IPV6 ?
  if (addr->ai_family == AF_INET6 && !(*ipv4_only))
  {
    inet_ntop(addr->ai_family, &((struct sockaddr_in6 *) addr->ai_addr)->sin6_addr, buf, BUF_SIZE);
  }
  // Is it IPV4 ?
  else if (addr->ai_family == AF_INET)
  {
    inet_ntop(addr->ai_family, &((struct sockaddr_in *) addr->ai_addr)->sin_addr, buf, BUF_SIZE);
  }
  // Something else error
  else
  {
    return EXIT_FAILURE;
  }

  // Return success
  return EXIT_SUCCESS;
}

/*********************************************************************************************************************************
* Will return source IP based on given interface, if none was given it will select the first interface after loopback
* Source of information:
* http://man7.org/linux/man-pages/man3/getifaddrs.3.html
*********************************************************************************************************************************/
int get_our_ip(char *result,char *interface,int ipv4)
{
  // Variables
  struct ifaddrs *ifaddr = NULL, *ifa = NULL;
  int family = 0, s = 0,n = 0;

  // Will return structure containing all the interfaces
  if (getifaddrs(&ifaddr) == -1)
  {
      perror("getifaddrs()");
      return -1;
  }

  // Loop through all interfaces
  for (ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next, n++)
  {
    // If empty interface skip
    if (ifa->ifa_addr == NULL)
      continue;

    // No interface specified
    if (interface == NULL)
    {
      // Skip loopback
      if (strcmp(ifa->ifa_name,"lo") == 0)
      {
        continue;
      }

      // Only IPV4 ?
      if (ipv4)
      {
        // Check if interface is IPV4
        if (ifa->ifa_addr->sa_family == AF_INET)
        {
          // Get interface IP
          s = getnameinfo(ifa->ifa_addr,sizeof(struct sockaddr_in),result,BUF_SIZE,NULL,0,NI_NUMERICHOST);

          // Free resources
          freeifaddrs(ifaddr);

          // Did the getnameinfo failed ?
          if (s != 0)
          {
            fprintf(stderr,"getnameinfo() failed%s\n", gai_strerror(s));
            return -1;
          }

          // Return with ip index of interface
          return if_nametoindex(ifa->ifa_name);
        }
      }
      // IPV6
      else
      {
        // Is interface IPV6 ?
        if (ifa->ifa_addr->sa_family == AF_INET6)
        {
          // Get IPV6 address
          s = getnameinfo(ifa->ifa_addr,sizeof(struct sockaddr_in6),result,BUF_SIZE,NULL,0,NI_NUMERICHOST);

          // Free addr
          freeifaddrs(ifaddr);

          // Did getnameinfo faile ?
          if (s != 0)
          {
            fprintf(stderr,"getnameinfo() failed%s\n", gai_strerror(s));
            return -1;
          }

          // Return with ip index of interface
          return if_nametoindex(ifa->ifa_name);
        }
      }
    }
    // Interface specified
    else
    {
      // Check if we found the given interface
      if (strcmp(ifa->ifa_name,interface) == 0)
      {
        // We require IPV4 versin of interface
        if (ipv4)
        {
          // Is the given address IPV4 ?
          if (ifa->ifa_addr->sa_family == AF_INET)
          {
            // Get IPV4 address
            s = getnameinfo(ifa->ifa_addr,sizeof(struct sockaddr_in),result,BUF_SIZE,NULL,0,NI_NUMERICHOST);

            // Free addr
            freeifaddrs(ifaddr);

            // Check if command returned ok
            if (s != 0)
            {
              printf("getnameinfo() failed: %s\n", gai_strerror(s));
          		return -1;
            }

            // Return with ip index of interface
            return if_nametoindex(ifa->ifa_name);
          }

        }
        // IPV6
        else
        {
          // Is found interface IPV6 ?
          if (ifa->ifa_addr->sa_family == AF_INET6)
          {
            // Get IP
            s = getnameinfo(ifa->ifa_addr,sizeof(struct sockaddr_in6),result,BUF_SIZE,NULL,0,NI_NUMERICHOST);

            // Free addr
            freeifaddrs(ifaddr);

            // Check if command returned ok
            if (s != 0)
            {
              printf("getnameinfo() failed: %s\n", gai_strerror(s));
              freeifaddrs(ifaddr);
              return -1;
            }

            // Return with ip index of interface
            return if_nametoindex(ifa->ifa_name);
          }
        }
      }
    }
  }

  // Nothing found free and return error
  freeifaddrs(ifaddr);
  return -1;
}

/*********************************************************************************************************************************
* Will check if given interface exist and return the name of interface if everything is okay
* Source of information:
* https://www.tcpdump.org/manpages/pcap_loop.3pcap.html
*********************************************************************************************************************************/
int find_capture_device(char *result,char *interface)
{
  char error_buffer[PCAP_ERRBUF_SIZE];
  pcap_if_t *all_devices = NULL;
  pcap_if_t *dev = NULL;

  // Find all devices
  if (pcap_findalldevs(&all_devices,error_buffer) != 0)
  {
    fprintf(stderr, "pcap_findalldevs() failed: %s\n", error_buffer);
    return 1;
  }

  // Loop through all device
  for(dev = all_devices; dev != NULL; dev = dev->next)
  {
    // Interface is set so check if it exist
    if (interface)
    {
      // Check if we found interface
      if (strcmp(interface,dev->name) == 0)
      {
        // Return interface name
        strcpy(result,dev->name);
        pcap_freealldevs(all_devices);
        return 0;
      }
      // Jump up
      continue;
    }

    // Skip loopback
    if (dev->flags & PCAP_IF_LOOPBACK)
    {
      continue;
    }

    // Return first found
    strcpy(result,dev->name);
    pcap_freealldevs(all_devices);
    return 0;
  }

  // No interface was found
  pcap_freealldevs(all_devices);
  return 1;
}

/*********************************************************************************************************************************
* Will set the interface into promisc mode and set filters if the scanning type is UDP and return pointer to the handler
* Source of information:
* https://www.tcpdump.org/manpages/pcap_loop.3pcap.html
*********************************************************************************************************************************/
pcap_t * set_capture_device(char *device,char *src_ip,int ipv4,int tcp)
{
  struct bpf_program filter;
  char filter_exp[BUF_SIZE];
  pcap_t *handle = NULL;
  char error_buffer[PCAP_ERRBUF_SIZE];
  bpf_u_int32 subnet_mask, ip;

  // Reset filter
  memset(&filter_exp,0,BUF_SIZE);

  // UDP IPV4 filter
  if (ipv4)
  {
    sprintf(filter_exp,"icmp and icmp[icmptype] == icmp-unreach");
  }
  // UDP IPV6 filter
  else
  {
    sprintf(filter_exp,"icmp6");
  }

  // Loop up device
  if (pcap_lookupnet(device,&ip,&subnet_mask,error_buffer) == -1)
  {
    printf("Could not get information for device: %s\n", device);
    ip = 0;
    subnet_mask = 0;
  }

  // Start listening on the device
  if ((handle = pcap_open_live(device,65536,1,0,error_buffer)) == NULL)
  {
    fprintf(stderr, "Could not open %s - %s\n", device,error_buffer);
    return NULL;
  }

  // Use filter only for UDP
  if (tcp == FALSE)
  {
    // Compile filter
    if(pcap_compile(handle,&filter,filter_exp,0,ip) == -1)
    {
      printf("Bad filter - %s\n",pcap_geterr(handle));
      return NULL;
    }

    // Add filter to the handler
    if(pcap_setfilter(handle,&filter) == -1)
    {
      printf("Error setting filter - %s\n",pcap_geterr(handle));
      return NULL;
    }
  }

  // Return handler
  return handle;
}
