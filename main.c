#include <ctype.h> // isdigit()
#include <getopt.h> // GETOPT

#include "include/udp.h"
#include "include/tcp.h"

// Macro for checking if given string is in port range
#define PORT_RANGE(a) (atoi(a) >= 0 && atoi(a) <= 65535)

// Long options for function getopt 
static struct option long_options[] =
{
    {"pt",  required_argument, 0,  't' }, // TCP ports
    {"pu",  required_argument, 0,  'u' }, // UDP ports
    {0,     0,           0,   0  }  
};

/*********************************************************************************************************************************
* We check if given string is number, if not we return TRUE 
*********************************************************************************************************************************/
int not_number(char *str)
{
  // Loop through the whole string
  for (size_t i = 0; i < strlen(str); i++)
  {
    // Check if char is not digit
    if (!isdigit(str[i]))
      return TRUE;
  }
  // Str is number
  return FALSE;
}

/*********************************************************************************************************************************
* We generate array of ports to scan from given string
*********************************************************************************************************************************/
int split_ports(int **port_array,int *port_num,char *optarg)
{
  // Variables
  char optarg_tmp[BUF_SIZE];  // Copy optarg because strtok will destroy string
  char *ports = NULL;
  char *from = NULL;
  char *to = NULL;

  // Clear string and copy optarg
  memset(&optarg_tmp,0,BUF_SIZE);
  strcpy(optarg_tmp,optarg);


  // How is the port given
  // 2-5
  if (strstr(optarg_tmp,"-"))
  {
    // Variables
    int from_int = 0;
    int to_int = 0;

    // Get from and to
    from = strtok(optarg,"-");
    to = strtok(NULL,"-");

    // If nothing was returned it is error
    if (!from || !to)
    {
      return EXIT_FAILURE;
    }

    // There cant be any other string
    if (strtok(NULL,"-"))
    {
      return EXIT_FAILURE;
    }

    // If one of them is not number
    if (not_number(from) || not_number(to))
    {
      // Error
      return EXIT_FAILURE;
    }

    // If one of them is not in port range
    if (!PORT_RANGE(from) || !PORT_RANGE(to))
    {
      return EXIT_FAILURE;
    }

    // Convert
    from_int = atoi(from);
    to_int = atoi(to);

    // From must be lower or equal than to
    if (from_int > to_int)
    {
      return EXIT_FAILURE;
    }

    // Size of integer array 
    (*port_num) = (to_int - from_int) + 1;

    // Create array of integers to fill all the ports
    (*port_array) = malloc(sizeof(int) * (*port_num));

    // Malloc ok ?
    if (!port_array)
    {
      return EXIT_FAILURE;
    }

    // Index of int array
    int index = 0;

    // Loop in the given range
    for (int i = from_int; i <= to_int; i++)
    {
      // Save given int into array
      (*port_array)[index++] = i;
    }
  }
  // 2,3,4,5
  else if (strstr(optarg_tmp,","))
  {
    // Last char is ,
    if (optarg_tmp[strlen(optarg_tmp) - 1] == ',')
    {
      // Error
      return EXIT_FAILURE;
    }

    // Get the first port
    ports = strtok(optarg_tmp,",");

    // Get all the other ports
    while (ports)
    {
      // Check if given port number is correct
      if (not_number(ports))
      {
        return EXIT_FAILURE;
      }

      // Check if given port is in range
      if (!PORT_RANGE(ports))
      {
        return EXIT_FAILURE;
      }

      // Increment for every port so we know how many elements to allocate
      (*port_num)++;

      // Get next port
      ports = strtok(NULL,",");
    }

    // Create array of integers to fill all the ports
    (*port_array) = malloc(sizeof(int) * (*port_num));

    // Malloc ok ?
    if (!port_array)
    {
      return EXIT_FAILURE;
    }

    // Index
    int i = 0;

    // Get the first port
    ports = strtok(optarg,",");

    // Null the array
    memset((*port_array),0,sizeof(int) * (*port_num));

    // Get all the other ports
    while (ports)
    {
      // Convert the port from string to int and save in given index
      (*port_array)[i] = atoi(ports);

      // Get next port
      ports = strtok(NULL,",");

      // Increment index
      i++;
    }
  }
  // 2
  else
  {
    // Check if given number contains only integers
    if (not_number(optarg))
    {
      return EXIT_FAILURE;
    }

    // Check if port is in range
    if (!PORT_RANGE(optarg))
    {
      return EXIT_FAILURE;
    }

    // Set port_num
    (*port_num) = 1;

    // Create arry of 1 element 
    (*port_array) = malloc(sizeof(int) * (*port_num));

    // Malloc ok ?
    if (!port_array)
    {
      return EXIT_FAILURE;
    }

    // Null the array
    memset((*port_array),0,sizeof(int) * (*port_num));

    // Insert into array the given number
    (*port_array)[0] = atoi(optarg);
  }

 return EXIT_SUCCESS;
}

/*********************************************************************************************************************************
* Itterate through all arguments and check them with getopt()
*********************************************************************************************************************************/
struct addrinfo* parse_arguments(char **interface, int ** tcp_ports,int *tcp_amount,int ** udp_ports,int *udp_amount,int argc,char **argv,int * ipv4_only)
{
  // Variables
  int c = 0;
  int option_index = 0;
  struct addrinfo* result = NULL;
  char ip[BUF_SIZE];

  // Set getopt to not output help messages
  opterr = 0;

  // Clear ip
  memset(&ip,0,BUF_SIZE);

  // Loop through all elements
  while (TRUE)
  {
    // Get next element
    c = getopt_long_only(argc,argv,"i:",long_options,&option_index);

    // Is there no more arguments left ?
    if (c < 0)
    {
      // Then end
      break;
    }

    // Check what type of argument we are dealing with
    switch (c)
    {
      // TCP ports
      case 't':
        // Split ports based on how they were written
        if (split_ports(&(*tcp_ports),tcp_amount,optarg))
        {
          // If some error occured
          return NULL;
        }
        break;

      // UDP ports
      case 'u':
        // Split ports based on how they were written
        if (split_ports(&(*udp_ports),udp_amount,optarg))
        {
          // If some error occured
          return NULL;
        }
        break;

      // Interface
      case 'i':
        // Copy string into interface
        *interface = optarg;
        break;

      // Wrong argument
      case '?':
      default:
        // Print help message
        printf("Wrong arguments.\n");
        printf("Usage:\n");
        printf("\t%s -i <interface> -pt [<1,2,3>|<1-5>|<1>] -pu [<1,2,3>|<1-5>|<1>] [<ip address>|<domain name>]\n",argv[0]);
        return NULL;
        break;
    } // Switch end
  } // While end

  // There should be only 1 argument
  int must_be_one = argc - optind;

  // There is no or more than 1 arguments
  if (must_be_one != 1)
  {
    // Error
    return NULL;
  }

  // Only 1 argument was given, convert IP/DOMAIN into struct addrinfo
  if((result = get_addr(argv[optind],ipv4_only)) == NULL)
  {
    return NULL;
  }

  // Check if we got some ports or we got address
  if ((*tcp_amount || *udp_amount))
  {
    // Nothing was returned by function
    if(get_ip(result,ip,ipv4_only))
      return NULL;

    // Print what we are doing
    printf("\nInteresting ports on %s (%s):\n", argv[optind],ip);
    printf("PORT\tSTATE\n");
  }
  // No address or no ports
  else
  {
    printf("No ports were specified.\n");
  }

  // Return result
  return result;
}

/*********************************************************************************************************************************
* Set variables, and start every function from here
*********************************************************************************************************************************/
int main(int argc, char *argv[])
{
  // Return error num
  int ret_code = EXIT_SUCCESS;

  // IPV6 prefered
  int ipv4_only = FALSE;
  char scan_device[BUF_SIZE];

  // IP address of domain
  struct addrinfo *dest_ip = NULL;
  char *interface = NULL;

  // Will contain array of TCP and UDP ports
  int *tcp_ports = NULL;
  int *udp_ports = NULL;

  // Number of tcp and upd ports to scan
  int amount_of_tcp_ports = 0;
  int amount_of_udp_ports = 0;

  // Get everything needed from arguments
  if ((dest_ip = parse_arguments(&interface,&tcp_ports,&amount_of_tcp_ports,&udp_ports,&amount_of_udp_ports,argc,argv,&ipv4_only)) == NULL)
  {
    // Set exit code
    ret_code = EXIT_FAILURE;
  }

  // If some ports were specified we check them
  if ((amount_of_tcp_ports || amount_of_udp_ports) && !ret_code)
  {
    // Clear buffer
    memset(&scan_device,0,BUF_SIZE);
   
    // If no device was found throw error
    if (find_capture_device(scan_device,interface))
    {
      fprintf(stderr, "No device for scanning was found.\n");
      ret_code = EXIT_FAILURE;
    }

    // Scan TCP ports
    for (int i = 0; i < amount_of_tcp_ports && ret_code != EXIT_FAILURE; i++)
    {
      // Did scan fail ?
      if (scan_port_TCP(dest_ip,scan_device,tcp_ports[i],&ipv4_only))
      {
        ret_code = EXIT_FAILURE;
        break;
      }
    }

    // Scan UDP ports
    for (int i = 0; i < amount_of_udp_ports && ret_code != EXIT_FAILURE; i++)
    {
      // Did scan fail ?
      if (scan_port_UDP(dest_ip,scan_device,udp_ports[i],&ipv4_only))
      {
        ret_code = EXIT_FAILURE;
        break;
      }
    }
  }

  // Free allocated resources
  if (dest_ip)
    freeaddrinfo(dest_ip);

  if (tcp_ports)
    free(tcp_ports);

  if (udp_ports)
    free(udp_ports);

  // Exit program
  return ret_code;
}
