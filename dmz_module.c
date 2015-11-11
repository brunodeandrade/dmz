#include <stdio.h>
#include <stdlib.h>
#include <string.h>


typedef struct ip_node{
	char * ip_name;//primary key
	int tcp_baseline;
	int udp_baseline;
	int icmp_baseline;
	struct baseline *next_IP;
} ip_node;

ip_node * first_one = NULL;


void print_info(char * ip_name, int bytes, char * protocol){

	printf("Upper ip: %s bytes: %i protocol: %s \n\n", ip_name, bytes, protocol);

}

/*
*Creates a new ip_node
*
*/
ip_node * create_ip_node(char * ip_name, int bytes,char * protocol){
	ip_node * node = (ip_node *) malloc (sizeof(ip_node));	
	node->ip_name = ip_name;

	if(strcmp(protocol,"TCP") == 0){
		first_one->tcp_baseline = bytes;
		first_one->udp_baseline = 0;
	}else if(strcmp(protocol,"UDP") == 0){
		first_one->udp_baseline = bytes;
		first_one->tcp_baseline = 0;
	}
	return node;

}

/*
*Creates the list with all the ip's 
*
*/
void save_data(char * ip_name, int bytes, char * protocol){
	
	if(first_one == NULL){		
		first_one = create_ip_node(ip_name,bytes,protocol);	
	}



}




