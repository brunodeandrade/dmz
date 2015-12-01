#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "uthash.h"
#include <sys/socket.h>
#include <sys/time.h>

#define POLL_TIME 10

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
	int learning_time; //learning time of the algorithm, in polls not seconds
	int new_baseline;//The result of the learning
	int old_baseline;
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

ip_node * to_learn_list = NULL;
ip_node * learnt_list = NULL;

int wait_alert_sys; //wait time until the throw of an alert, defined by the user for the whole system
int learning_time_sys; //learning time of the algorithm, defined by the user for the whole system
int static_baseline;
float global_threshold;
float R0_BASELINE;
float R1_BASELINE;


int load_file(){
	FILE * config_file = fopen("config.txt","r");
	if(!config_file){
		printf("ERROR: Could not open file!\n\n\n");
		return -1;
	}

	fscanf(config_file,"%d %d %d %f %f %f",&wait_alert_sys,&learning_time_sys,&static_baseline,&global_threshold,&R0_BASELINE,&R1_BASELINE);

	if ((R0_BASELINE + R1_BASELINE) >= 1.0){
		printf("ERROR! These parameters are not set up correctly. Please check if the R0 and R1 parameters < 1.\n");
		exit (-1);
	}

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
* Remove port from list
*/
void remove_port(ip_node * ip, port_node * port, u_short protocol_id){

	int port_name = port->port_name;

	switch(protocol_id){
		case IPPROTO_TCP:
			HASH_DEL(ip->tcp_ports, port);
			break;
		case IPPROTO_UDP:
			HASH_DEL(ip->udp_ports, port);
			break;
		case IPPROTO_ICMP:
			HASH_DEL(ip->icmp_ports, port);
			break;
		default: 
			printf("not known protocol\n");
			break;
	}
	
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

	HASH_FIND_INT(to_learn_list,&upper_ip,findable);

	port_node * port = create_port_node(port_name, current_packets);

	if(findable){		
		find_port_and_increment(findable,protocol_id,port);			
	}else{
		ip_node * ip = create_ip_node(ip_name,upper_ip);
		insert_port_in_hash(ip,protocol_id,port);
		HASH_ADD_INT(to_learn_list, upper_ip, ip);
	}
}


/*
* Free Hash List
*/
void free_hash_list(ip_node * hash_list){
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
	for(itr = to_learn_list; itr!= NULL;itr= itr->hh.next){
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
	free_hash_list(to_learn_list);
	free_hash_list(learnt_list);
}

bool still_has_to_learn(struct timeval time_of_detection, int learning_time){
	struct timeval now;
	gettimeofday(&now,NULL);

	time_t time_of_detection_sec = (time_t) time_of_detection.tv_sec;
	time_t now_sec = (time_t)now.tv_sec;

	if((now_sec - time_of_detection_sec) > (learning_time*POLL_TIME))
		return false;
	else
		return true;	

}


/*
* Learning 
* Params - The port to have the baseline learning step done
*/


/*
* Learnt Control 
* Remove from the to_learn_list and add to the learnt_list
*/
void learnt_control(ip_node * ip, port_node * port, u_short protocol_id){
	ip_node * found = NULL;

	HASH_FIND_INT(learnt_list, &ip->upper_ip, found);
	if(found){
		insert_port_in_hash(found,protocol_id,port);
	}else{
		found = (ip_node *) malloc(sizeof(ip_node));
		memcpy(found,ip,sizeof(ip));
		found->tcp_ports = NULL;
		found->udp_ports = NULL;
		found->icmp_ports = NULL;
		insert_port_in_hash(found,protocol_id,port);
		int upper_ip = ip->upper_ip;
		HASH_ADD_INT(learnt_list,upper_ip,found);
	}
	remove_port(ip, port, protocol_id);
	if(ip->tcp_ports == NULL && ip->udp_ports == NULL && ip->icmp_ports == NULL){
		HASH_DEL(to_learn_list,ip);
	}

}


/*
* Learning Control - Poll Iteration
*/
void continuous_learning(){
	ip_node * itr = NULL,* next = NULL;
	port_node * itr_port = NULL, *next_port = NULL;
	
	for(itr = to_learn_list; itr!= NULL;itr=next){
		for(itr_port = itr->tcp_ports; itr_port != NULL; itr_port = next_port) {
			if(still_has_to_learn(itr_port->time_of_detection,itr_port->learning_time)){
				//TODO Learning step for this baseline goes here 
			}else{
				learnt_control(itr,itr_port,IPPROTO_TCP);
			}
			next_port = itr_port->hh.next;			
		}
		for(itr_port = itr->udp_ports; itr_port != NULL; itr_port = next_port) {
			if(still_has_to_learn(itr_port->time_of_detection,itr_port->learning_time)){
				//TODO Learning step for this baseline goes here 
			}else{
				learnt_control(itr,itr_port,IPPROTO_UDP);
			}
			next_port = itr_port->hh.next;			
		}
		for(itr_port = itr->icmp_ports; itr_port != NULL; itr_port = next_port) {
			if(still_has_to_learn(itr_port->time_of_detection,itr_port->learning_time)){
				//TODO Learning step for this baseline goes here 
			}else{
				learnt_control(itr,itr_port,IPPROTO_ICMP);
			}
			next_port = itr_port->hh.next;			
		}
	}
}



