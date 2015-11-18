#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "uthash.h"

typedef int ptype;
enum { TCP, UDP, ICMP };

typedef int bool;
enum {true, false};


typedef struct port_node{
	char * port_name;
	u_int64_t bytes;
	UT_hash_handle hh;
	int current_packets;
	bool learnt;
	long threshold; // in seconds, defined by poisson or other method
}port_node;

typedef struct ip_node{
	char * ip_name;//primary key
	port_node * tcp_ports;
	port_node * udp_ports;
	port_node * icmp_ports;
	int icmp_baseline;
	UT_hash_handle hh;
} ip_node;

ip_node * hash_list = NULL;
int wait_alert; //wait time until the throw of an alert, defined by the user
int learning_time; //learning time of the algorithm, defined by the user

int load_file(){
	FILE * config_file = fopen("config.txt","r");
	if(!config_file){
		printf("ERROR: Could not open file!\n\n\n");
		return -1;
	}

	fscanf(config_file,"%d %d",&wait_alert,&learning_time);	
	fclose(config_file);
	return 0;
}


void print_info(char * ip_name, int bytes, char * protocol, int lower_port, int packets){

	printf("Upper ip: %s bytes: %i protocol: %s port: %i  packets: %d \n\n", ip_name, bytes, protocol,lower_port,packets);

}

/*
*Creates a new ip_node
*
*/
ip_node * create_ip_node(char * ip_name){
	ip_node * node = (ip_node *) malloc (sizeof(ip_node));	
	node->ip_name = ip_name;
	node->tcp_ports = NULL;
	node->udp_ports = NULL;
	node->icmp_ports = NULL;
	return node;
}

/*
*Creates a port node
*
*/
port_node * create_port_node(char * port_name, u_int64_t bytes, int current_packets){
	port_node * node = (port_node *) malloc (sizeof(port_node));	
	node->port_name = malloc(sizeof(char) * strlen(port_name));
	strcpy(node->port_name,port_name);
	node->bytes = bytes;
	node->current_packets = current_packets;
	node->learnt = false;

	return node;
}


/*
*Inserts a new port in the hash of the node
*
*/
void insert_port_in_hash (ip_node * ip_node, ptype protocol_type, port_node *port) {

	char *port_name = port->port_name;

	switch(protocol_type){
		case TCP:
			HASH_ADD_STR(ip_node->tcp_ports, port_name, port);
			break;
		case UDP:
			HASH_ADD_STR(ip_node->udp_ports, port_name, port);
			break;
		case ICMP:
			HASH_ADD_STR(ip_node->icmp_ports, port_name, port);
			break;
		default: 
			printf("not known protocol\n");
			break;
	}

}

/*
*Adds the bytes to a port in the hash of the node
*
*/
void find_port_and_increment (ip_node * ip_node, ptype protocol_type, port_node * port) {

	port_node * findable_port = NULL;
	switch(protocol_type){
		case TCP:
			HASH_FIND_STR(ip_node->tcp_ports, port->port_name, findable_port);
			break;
		case UDP:
			HASH_FIND_STR(ip_node->udp_ports, port->port_name, findable_port);
			break;
		case ICMP:
			HASH_FIND_STR(ip_node->icmp_ports, port->port_name, findable_port);
			break;
		default: 
			printf("not known protocol\n");
			break;
	}

	if(findable_port) {
		findable_port->bytes += port->bytes;
		findable_port->current_packets = port->current_packets;
	}

	else {
		insert_port_in_hash(ip_node, protocol_type, port);
	}
}

/*
* Adds an IP node to the hash list
*
*/
void add_to_hash(char * ip_name, int bytes, char * protocol, int port_name , int current_packets){

	ip_node * findable = NULL;
	ptype protocol_type;

	char port_str[10];
	sprintf(port_str,"%d",port_name);
	//printf(" %d %s \n", port_name, port_str);

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

	port_node * port = create_port_node(port_str,bytes, current_packets);

	if(findable){
		find_port_and_increment(findable,protocol_type,port);
			
	}else{
		ip_node * ip = create_ip_node(ip_name);
		insert_port_in_hash(ip,protocol_type,port);
		HASH_ADD_STR(hash_list, ip_name, ip);
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
		for(itr_port = itr->icmp_ports; itr_port != NULL; itr_port = next_port) {
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
		printf("         TCP\n");
		for(irt_port = itr->tcp_ports; irt_port != NULL; irt_port = irt_port->hh.next)
			printf("           Port: %s, Bytes: %ld  Current Packets: %d\n",irt_port->port_name,irt_port->bytes,irt_port->current_packets);
		printf("         UDP\n");
		for(irt_port = itr->udp_ports; irt_port != NULL; irt_port = irt_port->hh.next)
			printf("           Port: %s, Bytes: %ld Current Packets: %d\n",irt_port->port_name,irt_port->bytes,irt_port->current_packets);
		printf("         ICMP\n");
		for(irt_port = itr->icmp_ports; irt_port != NULL; irt_port = irt_port->hh.next)
			printf("           Port: %s, Bytes: %ld Current Packets: %d\n",irt_port->port_name,irt_port->bytes,irt_port->current_packets);
	}

	printf("Wait alert is %d and the learning time is %d \n\n\n", wait_alert, learning_time);
	free_hash_list();
}



