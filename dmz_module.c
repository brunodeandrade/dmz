#include <stdio.h>
#include <stdlib.h>


struct baseline{
	int tpc_baseline;
	int udp_baseline;
	int icmp_baseline;
};

void print_info(char * ip_name, int bytes, char * protocol){

	printf("Upper ip: %s bytes: %i protocol: %s \n\n", ip_name, bytes, protocol);

}


