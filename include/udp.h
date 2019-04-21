#ifndef _H_UDP
#define _H_UDP

// Number of tries, if the port is really OPEN
#define UDP_PORT_LOOP 3

// C Headers
#include <stdlib.h>
#include <stdio.h>
#include <netdb.h> // addrinfo

// My headers
#include "scanner.h"
#include <netinet/udp.h>

// Public functions
int scan_port_UDP(struct addrinfo *,char *,int,int *);

#endif
