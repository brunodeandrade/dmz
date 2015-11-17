#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "uthash.h"


typedef struct port_node{
	char * port_name;
	u_int64_t bytes;
	UT_hash_handle hh;
}port_node;

typedef struct ip_node{
	char * ip_name;//primary key
	port_node * tcp_ports;
	port_node * udp_ports;
	port_node * icmp_ports;
	int icmp_baseline;
	UT_hash_handle hh;
} ip_node;

typedef int bool;
enum { TCP, UDP, ICMP };

ip_node * hash_list = NULL;


void print_info(char * ip_name, int bytes, char * protocol, int lower_port){

	printf("Upper ip: %s bytes: %i protocol: %s port: %i \n\n", ip_name, bytes, protocol,lower_port);

}

/*
*Creates a new ip_node
*
*/
ip_node * create_ip_node(char * ip_name){
	printf("Criei o ip\n");
	ip_node * node = (ip_node *) malloc (sizeof(ip_node));	
	node->ip_name = ip_name;
	node->tcp_ports = NULL;
	node->udp_ports = NULL;
	node->icmp_ports = NULL;
	return node;

}

port_node * create_port_node(char * port_name, u_int64_t bytes){
	printf("Criei a porta\n");
	port_node * node = (port_node *) malloc (sizeof(port_node));	
	node->port_name = port_name;

	node->bytes = bytes;

	return node;
}


void insert_port_in_hash (ip_node * ip_node, char * port_name, int bytes, bool protocol_type) {

	port_node *node = create_port_node(port_name,bytes);

	switch(protocol_type){
		case TCP:
			HASH_ADD_STR(ip_node->tcp_ports, port_name, node);
		case UDP:
			HASH_ADD_STR(ip_node->udp_ports, port_name, node);
		case ICMP:
			HASH_ADD_STR(ip_node->icmp_ports, port_name, node);
		default: 
			printf("not known protocol");
	}

}

void find_port_and_increment (ip_node * ip_node, char *port_name, int bytes, bool protocol_type) {

	port_node * findable_port = NULL;

	switch(protocol_type){
		case TCP:
			HASH_FIND_STR(ip_node->tcp_ports, port_name, findable_port);
		case UDP:
			HASH_FIND_STR(ip_node->udp_ports, port_name, findable_port);
		case ICMP:
			HASH_FIND_STR(ip_node->icmp_ports, port_name, findable_port);
		default: 
			printf("not known protocol");
	}

	if(findable_port) {
		findable_port->bytes += bytes;
	}

	else {
		insert_port_in_hash(ip_node,port_name,bytes, protocol_type);
	}
}

/*
* Adds an IP node to the hash list
*
*/
void add_to_hash(char * ip_name, int bytes, char * protocol, int port_name){
	ip_node * findable = NULL;
	bool protocol_type;

	char port_str[6];
	sprintf(port_str,"%d",port_name);
	printf(" %d %s \n", port_name, port_str);

	if(strcmp(protocol,"TCP") == 0){
		protocol_type = TCP;
	}
	else if(strcmp(protocol,"UDP") == 0){
		protocol_type = UDP;
	}
	else if(strcmp(protocol,"ICMP") == 0){
		protocol_type = ICMP;
	}

	HASH_FIND_STR(hash_list,ip_name,findable);

	if(findable){
		find_port_and_increment(findable,port_str,bytes,protocol_type);
			
	}else{
		ip_node * node = create_ip_node(ip_name);
		insert_port_in_hash(node,port_str,bytes,protocol_type);
		HASH_ADD_STR(hash_list, ip_name, node);
	}
}


/*
* Free Hash List
*/
void free_hash_list(){
	ip_node * itr,* next;
	port_node * itr_port, *next_port;
	int i = 0;
	
	for(itr = hash_list; itr!= NULL;itr=next){


		for(itr_port = itr->tcp_ports; itr_port != NULL; itr_port = next_port) {
			next_port = itr_port->hh.next;
			free(itr_port);
		}
		for(itr_port = itr->udp_ports; itr_port != NULL; itr_port = next_port) {
			next_port = itr_port->hh.next;
			free(itr_port);
		}
		next = itr->hh.next;
		free(itr);
	}

	free(hash_list);
}



/*
* Print Hash
*/
void print_hash(){
	ip_node * itr;
	port_node *irt_port;
	int i = 0;

	printf("\n\tHash:\n");
	for(itr = hash_list; itr!= NULL;itr= itr->hh.next){
		printf("\t%d - IP: %s\n",i++,itr->ip_name);
		for(irt_port = itr->tcp_ports; irt_port != NULL; irt_port = irt_port->hh.next)
			printf("           Port: %s, Bytes: %d\n",irt_port->port_name,irt_port->bytes);
	}
	free_hash_list();
}

