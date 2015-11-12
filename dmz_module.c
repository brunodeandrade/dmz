#include <stdio.h>
#include <stdlib.h>
#include <string.h>


typedef struct ip_node{
	char * ip_name;//primary key
	int tcp_baseline;
	int udp_baseline;
	int icmp_baseline;
	struct ip_node *next_IP;
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
void print_list(){
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






