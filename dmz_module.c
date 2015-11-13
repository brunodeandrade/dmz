#include <stdio.h>
#include <stdlib.h>
#include <string.h>


typedef struct port_node{
	u_int16_t port_name;
	u_int64_t bytes;
	struct port_node *next_port;
}port_node;

typedef struct ip_node{
	char * ip_name;//primary key
	int tcp_baseline;
	int udp_baseline;
	int icmp_baseline;
	struct ip_node *next_IP;
} ip_node;



ip_node * first_one = NULL;
port_node *first_port = NULL;


void print_info(char * ip_name, int bytes, char * protocol, int lower_port){

	printf("Upper ip: %s bytes: %i protocol: %s port: %i \n\n", ip_name, bytes, protocol,lower_port);

}

/*
*Creates a new ip_node
*
*/
ip_node * create_ip_node(char * ip_name, int bytes,char * protocol){
	ip_node * node = (ip_node *) malloc (sizeof(ip_node));	
	node->ip_name = ip_name;
	node->next_IP = NULL;

	if(strcmp(protocol,"TCP") == 0){
		node->tcp_baseline = bytes;
		node->udp_baseline = 0;
	}else if(strcmp(protocol,"UDP") == 0){
		node->udp_baseline = bytes;
		node->tcp_baseline = 0;
	}
	return node;

}

/*
*Creates the list with all the ip's 
*
*/
void save_data(char * ip_name, int bytes, char * protocol){
	ip_node * current_node, * next;
	
	if(first_one == NULL){	
		first_one = create_ip_node(ip_name,bytes,protocol);
		return;
	}

	current_node = first_one;

	/*
	*Run through all the nodes in the list to add data or create a new one
	*/
	do{
		if(strcmp(current_node->ip_name,ip_name) == 0){
			if(strcmp(protocol,"TCP") == 0){
				current_node->tcp_baseline += bytes;
				return;		
			}else if(strcmp(protocol,"UDP") == 0){
				current_node->udp_baseline += bytes;
				return;
			}
		}

		next = current_node->next_IP;
		if(next)
			current_node = current_node->next_IP;

	} while(next);

	//Creation of the new node, beacause he was not found in the list
	current_node->next_IP = create_ip_node(ip_name,bytes,protocol);

}

/*
*Free all the nodes
*/
void free_nodes(){
	ip_node * current_node = first_one;
	ip_node * next;
	int i = 1;
	
	do{
		next =  current_node->next_IP;
		free(current_node);
		current_node = next;
	} while(next);

}


/*
*Method to print the ip_list
*/
void print_ip_list(){
	ip_node * current_node = first_one;
	ip_node * next;

	int i = 1;

	printf("\n\tList:\n");
	do{
		printf("\t%d - IP: %s TCP Bytes: %d\n",i++,current_node->ip_name,current_node->tcp_baseline);
		next = current_node->next_IP;
		if(next)
			current_node = current_node->next_IP;

	} while(next);
	free_nodes();
}




port_node * create_port_node(u_int16_t port_name, u_int64_t bytes){
	port_node * node = (port_node *) malloc (sizeof(port_node));	
	node->port_name = port_name;
	node->next_port = NULL;

	node->bytes = bytes;

	return node;
}


/*
*Creates the list with all the ports 
*
*/
void save_port_data(u_int16_t port_name, u_int64_t bytes){
	port_node * current_node, * next;
	
	if(first_port == NULL){	
		first_port = create_port_node(port_name,bytes);
		return;
	}

	current_node = first_port;

	/*
	*Run through all the nodes in the list to add data or create a new one
	*/
	do{
		if(current_node->port_name == port_name){
				current_node->bytes += bytes;
				return;		
		}

		next = current_node->next_port;
		if(next)
			current_node = current_node->next_port;

	} while(next);

	//Creation of the new node, beacause he was not found in the list
	current_node->next_port = create_port_node(port_name,bytes);

}

/*
*Free all the nodes
*/
void free_ports(){
	port_node * current_node = first_port;
	port_node * next;
	int i = 1;
	
	do{
		next =  current_node->next_port;
		free(current_node);
		current_node = next;
	} while(next);

}

/*
*Method to print the port_list
*/
void print_port_list(){
	port_node * current_node = first_port;
	port_node * next;

	int i = 1;

	printf("\n\tPorts List:\n");
	do{
		printf("\t%d - Port: %u Bytes: %u\n",i++,current_node->port_name,current_node->bytes);
		next = current_node->next_port;
		if(next)
			current_node = current_node->next_port;

	} while(next);
	free_ports();
}
