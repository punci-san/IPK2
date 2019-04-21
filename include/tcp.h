#ifndef _H_TCP
#define _H_TCP

// C headers
#include <stdio.h>
#include <netdb.h> // addrinfo
#include <netinet/tcp.h>

// My headers
#include "scanner.h"

// Public functions
int scan_port_TCP(struct addrinfo *,char *,int,int *);

#endif
