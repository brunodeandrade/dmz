#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "uthash.h"
#include <sys/socket.h>
#include <sys/time.h>

typedef int ptype;
enum { TCP, UDP, ICMP };

typedef int bool;
enum {true, false};


typedef struct port_node{
	int port_name;
	UT_hash_handle hh;
	int current_packets;
	bool learnt;
	float threshold; // in seconds, defined by poisson or other method
	int wait_alert; //wait time until the throw of an alert
	int learning_time; //learning time of the algorithm
	int baseline;//The result of the learning
	struct timeval time_of_detection; 
}port_node;

typedef struct ip_node{
	int upper_ip;//primary key
	char * ip_name;
	port_node * tcp_ports;
	port_node * udp_ports;
	port_node * icmp_ports;
	UT_hash_handle hh;
} ip_node;

ip_node * hash_list = NULL;
int wait_alert_sys; //wait time until the throw of an alert, defined by the user for the whole system
int learning_time_sys; //learning time of the algorithm, defined by the user for the whole system
int static_baseline;
float global_threshold;

int load_file(){
	FILE * config_file = fopen("config.txt","r");
	if(!config_file){
		printf("ERROR: Could not open file!\n\n\n");
		return -1;
	}

	fscanf(config_file,"%d %d %d %f",&wait_alert_sys,&learning_time_sys,&static_baseline,&global_threshold);	
	fclose(config_file);
	return 0;
}


void print_info(long ip_number, char *ip_name, u_short protocol, int lower_port, int packets){

	printf("Upper number: %ld, Upper name: %s  protocol: %d port: %i  packets: %d \n\n", ip_number, ip_name, protocol,lower_port,packets);

}

/*
*Creates a new ip_node
*
*/
ip_node * create_ip_node(char * ip_name, int upper_ip){
	ip_node * node = (ip_node *) malloc (sizeof(ip_node));
	if(!node){
		printf("ip_node was not allocated correctly.\n\n\n");
		exit(0);
	}	
	node->ip_name = ip_name;
	node->upper_ip = upper_ip;
	node->tcp_ports = NULL;
	node->udp_ports = NULL;
	node->icmp_ports = NULL;
	return node;
}

/*
*Creates a port node
*
*/
port_node * create_port_node(int port_name, int current_packets){
	port_node * node = (port_node *) malloc (sizeof(port_node));

	if(!node){
		printf("port_node was not allocated correctly.\n\n\n");
		exit(0);
	}	
	
	node->port_name = port_name;
	node->current_packets = current_packets;
	node->learnt = false;
	gettimeofday(&node->time_of_detection,NULL);

	return node;
}


/*
*Inserts a new port in the hash of the node
*
*/
void insert_port_in_hash (ip_node * ip_node, u_short protocol_id, port_node *port) {

	int port_name = port->port_name;

	switch(protocol_id){
		case IPPROTO_TCP:
			HASH_ADD_INT(ip_node->tcp_ports, port_name, port);
			break;
		case IPPROTO_UDP:
			HASH_ADD_INT(ip_node->udp_ports, port_name, port);
			break;
		case IPPROTO_ICMP:
			HASH_ADD_INT(ip_node->icmp_ports, port_name, port);
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
void find_port_and_increment (ip_node * ip_node, u_short protocol_id, port_node * port) {

	port_node * findable_port = NULL;
	switch(protocol_id){
		case IPPROTO_TCP:
			HASH_FIND_INT(ip_node->tcp_ports, &(port->port_name), findable_port);
			break;
		case IPPROTO_UDP:
			HASH_FIND_INT(ip_node->udp_ports, &(port->port_name), findable_port);
			break;
		case IPPROTO_ICMP:
			HASH_FIND_INT(ip_node->icmp_ports, &(port->port_name), findable_port);
			break;
		default: 
			printf("not known protocol\n");
			break;
	}

	if(findable_port) {
		findable_port->current_packets += port->current_packets;
	}

	else {
		insert_port_in_hash(ip_node, protocol_id, port);
	}
}

/*
* Adds an IP node to the hash list
*
*/
void add_to_hash(int upper_ip, char * ip_name, u_short protocol_id, int port_name , int current_packets){

	ip_node * findable = NULL;

	HASH_FIND_INT(hash_list,&upper_ip,findable);

	port_node * port = create_port_node(port_name, current_packets);

	if(findable){		
		find_port_and_increment(findable,protocol_id,port);			
	}else{
		ip_node * ip = create_ip_node(ip_name,upper_ip);
		insert_port_in_hash(ip,protocol_id,port);
		HASH_ADD_INT(hash_list, upper_ip, ip);
	}
}


/*
* Free Hash List
*/
void free_hash_list(){
	ip_node * itr = NULL,* next = NULL;
	port_node * itr_port = NULL, *next_port = NULL;
	int i = 0;
	
	for(itr = hash_list; itr!= NULL;itr=next){

		for(itr_port = itr->tcp_ports; itr_port != NULL; itr_port = next_port) {
			next_port = itr_port->hh.next;
			HASH_DEL(itr->tcp_ports,itr_port);
			free(itr_port);
		}

		for(itr_port = itr->udp_ports; itr_port != NULL; itr_port = next_port) {
			next_port = itr_port->hh.next;
			HASH_DEL(itr->udp_ports,itr_port);
			free(itr_port);
		}
		for(itr_port = itr->icmp_ports; itr_port != NULL; itr_port = next_port) {
			next_port = itr_port->hh.next;
			HASH_DEL(itr->icmp_ports,itr_port);
			free(itr_port);
		}
		

		next = itr->hh.next;
		HASH_DEL(hash_list,itr);
		free(itr);		
	}
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
			printf("           Port: %d, Current Packets: %d, \t Detected Time: %d\n",irt_port->port_name,irt_port->current_packets,irt_port->time_of_detection);
		printf("         UDP\n");
		for(irt_port = itr->udp_ports; irt_port != NULL; irt_port = irt_port->hh.next)
			printf("           Port: %d, Current Packets: %d\n",irt_port->port_name,irt_port->current_packets);
		printf("         ICMP\n");
		for(irt_port = itr->icmp_ports; irt_port != NULL; irt_port = irt_port->hh.next)
			printf("           Port: %d, Current Packets: %d\n",irt_port->port_name,irt_port->current_packets);
	}

	printf("Wait alert is %d, the learning time is %d, the static baseline is %d and the global threshold is %f \n\n\n", wait_alert_sys, learning_time_sys,static_baseline,global_threshold);
	free_hash_list();
}



