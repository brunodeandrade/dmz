#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "uthash.h"
#include <sys/socket.h>
#include <sys/time.h>
#include <math.h>
#include <tgmath.h>

#define POLL_TIME 10
#define MAX_CACHE 1000000
#define NUMBER_TOP_SENDERS 10

long double cache_log[MAX_CACHE];
long double cache_sum[MAX_CACHE];

typedef int ptype;
enum { TCP, UDP, ICMP };

typedef int bool;
enum {false, true};

typedef struct ip_alert{
	int upper_ip;
	char * ip_name;
	int packets;
	UT_hash_handle hh;
} ip_alert;

typedef struct port_node{
	int port_name;
	int current_packets;
	bool learnt;
	long double poisson_result; //defined by poisson
	int wait_alert; //wait time until the throw of an alert
	int learning_time; //learning time of the algorithm, in polls not seconds
	float new_baseline;//The result of the learning
	float old_baseline;
	struct timeval time_of_detection;
	ip_alert *alert_node;
	UT_hash_handle hh;
}port_node;

typedef struct ip_node{	
	int lower_ip;//primary key
	char * ip_name;
	port_node * tcp_ports;
	port_node * udp_ports;
	port_node * icmp_ports;// It's a code not a port
	UT_hash_handle hh;
} ip_node;


ip_node * ip_list = NULL;
//ip_node * to_learn_list = NULL;
//ip_node * learnt_list = NULL;

int wait_alert_sys; //wait time until the throw of an alert, defined by the user for the whole system
int learning_time_sys; //learning time of the algorithm, defined by the user for the whole system
int static_baseline;
float global_threshold;
float R0_BASELINE;
float R1_BASELINE;

int init_cache()        {
        int i=1;

        for(; i<MAX_CACHE; i++)
                cache_log[i] = logl((long double)i);

        memset(cache_sum, 0x0, MAX_CACHE);

}

long double poisson(int k, int lam)     {

        int c = 1;
        long double pvalue = 0;
        long double sum = 0;

        if ( cache_sum[k] )
                sum = cache_sum[k];
        else {
                while(c <= k)   {
                        sum += cache_log[c];
                        c++;
                }
                cache_sum[k] = sum;
        }

        pvalue = cache_log[2] + k*cache_log[lam] - sum - lam;

        return pvalue;
}


int load_file(){
	FILE * config_file = fopen("config.txt","r");
	if(!config_file){
		printf("ERROR: Could not open file!\n\n\n");
		return -1;
	}

	fscanf(config_file,"%d %d %d %f %f %f %f",&wait_alert_sys,&learning_time_sys,&static_baseline,&global_threshold,
		&R0_BASELINE,&R1_BASELINE);

	if ((R0_BASELINE + R1_BASELINE) >= 1.0){
		printf("ERROR! These parameters are not set up correctly. Please check if the R0 and R1 parameters < 1.\n");
		exit (-1);
	}

	fclose(config_file);
	init_cache();
	return 0;
}


void print_info(long ip_number, char *ip_name, u_short protocol, int lower_port, int packets){

	printf("Upper number: %ld, Upper name: %s  protocol: %d port: %i  packets: %d \n\n", ip_number, ip_name, protocol,lower_port,packets);

}

/*
*Creates a new ip_node
*
*/
ip_node * create_ip_node(char * ip_name, int lower_ip){
	ip_node * node = (ip_node *) calloc (1,sizeof(ip_node));
	if(!node){
		printf("ip_node was not allocated correctly.\n\n\n");		
		return NULL;
	}	
	node->ip_name = ip_name;
	node->lower_ip = lower_ip;
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
	port_node * node = (port_node *) calloc (1,sizeof(port_node));

	if(!node){
		printf("port_node was not allocated correctly.\n\n\n");
		return NULL;
	}	
	
	node->new_baseline = 0;
	node->old_baseline = 0;
	node->wait_alert = 0;
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
* Search port in a hash.
*/

port_node * find_port(ip_node * ip_node, u_short protocol_id, int port_name){

	port_node * findable_port = NULL;

	switch(protocol_id){
	case IPPROTO_TCP:
		HASH_FIND_INT(ip_node->tcp_ports, &(port_name), findable_port);
		break;
	case IPPROTO_UDP:
		HASH_FIND_INT(ip_node->udp_ports, &(port_name), findable_port);
		break;
	case IPPROTO_ICMP:
		HASH_FIND_INT(ip_node->icmp_ports, &(port_name), findable_port);
		break;
	default: 
		printf("not known protocol\n");
		break;
	}
	return findable_port;
}

/*
* Find ip's for a given PORT
* TMP!!!!!!
*/
void print_ips_by_port(int port_name){

	ip_node * itr = NULL;
	port_node * tcp_port = NULL, * udp_port = NULL, * icmp_port = NULL;

	ip_alert * top_senders = NULL;
	top_senders = (ip_alert*)calloc(NUMBER_TOP_SENDERS,sizeof(ip_alert));

	if(!top_senders){
		printf("Couldn't allocate top_senders\n");
		exit(-1);
	}

	int i = 0;
	for(i;i<NUMBER_TOP_SENDERS;i++){
		top_senders[i].ip_name = NULL;
		top_senders[i].upper_ip = 0;
		top_senders[i].packets = 0;
	}

	printf("ALERT! PORT SUSPICIOUS: %d\n",port_name);

	for(itr = ip_list; itr!= NULL;itr= itr->hh.next){
		int pckts = 0;		
		HASH_FIND_INT(itr->tcp_ports, &(port_name), tcp_port);
		HASH_FIND_INT(itr->udp_ports, &(port_name), udp_port);
		HASH_FIND_INT(itr->icmp_ports, &(port_name), icmp_port);

		if(tcp_port){
			pckts += tcp_port->current_packets;
		}else if(udp_port){
			pckts += udp_port->current_packets;
		}else if(icmp_port){
			pckts += icmp_port->current_packets;
		}

		for(i;i<NUMBER_TOP_SENDERS;i++){
		}

		pckts = 0;
		tcp_port = udp_port = icmp_port = NULL;

	}
}


/*
*Adds the bytes to a port in the hash of the node
*
*/
void find_port_and_increment (ip_node * ip_node, u_short protocol_id, int port_name, int current_packets) {
	
	port_node * findable_port = find_port(ip_node, protocol_id, port_name);

	if(findable_port) {
		findable_port->current_packets += current_packets;
	}

	else {
		port_node * port = create_port_node(port_name, current_packets);
		if(port)
			insert_port_in_hash(ip_node, protocol_id, port);
		else
			printf("Not allocated.\n");
	}
}

/*
* Adds an IP node to the hash list

*/
void add_to_hash(int upper_ip,int lower_ip, char * upper_name, char * lower_name, u_short protocol_id, int port_name , int current_packets){

	ip_node * findable = NULL;

	HASH_FIND_INT(ip_list,&lower_ip,findable);

	
	if(findable){		
		find_port_and_increment(findable,protocol_id, port_name, current_packets);
	}else{
		port_node * port = create_port_node(port_name, current_packets);
		ip_node * ip = create_ip_node(lower_name,lower_ip);
		insert_port_in_hash(ip,protocol_id,port);
		HASH_ADD_INT(ip_list, lower_ip, ip);
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
	for(itr = ip_list; itr!= NULL;itr= itr->hh.next){
		printf("\t%d - IP: %s\n",i++,itr->ip_name);
		printf("         TCP\n");
		for(irt_port = itr->tcp_ports; irt_port != NULL; irt_port = irt_port->hh.next)
			printf("           Port: %d, Current Packets: %d, Baseline: %f \t Detected Time: %d\n",irt_port->port_name,irt_port->current_packets,irt_port->new_baseline,irt_port->time_of_detection);
		printf("         UDP\n");
		for(irt_port = itr->udp_ports; irt_port != NULL; irt_port = irt_port->hh.next)
			printf("           Port: %d, Current Packets: %d, Baseline: %f\n",irt_port->port_name, irt_port->new_baseline, irt_port->current_packets);
		printf("         ICMP\n");
		for(irt_port = itr->icmp_ports; irt_port != NULL; irt_port = irt_port->hh.next)
			printf("           Port: %d, Current Packets: %d, Baseline: %f\n",irt_port->port_name,irt_port->new_baseline,irt_port->current_packets);
	}

	printf("Wait alert is %d, the learning time is %d, the static baseline is %d and the global threshold is %f \n\n\n", wait_alert_sys, learning_time_sys,static_baseline,global_threshold);
	free_hash_list(ip_list);
}

bool still_has_to_learn(struct timeval time_of_detection, int learning_time){
	struct timeval now;
	gettimeofday(&now,NULL);

	time_t time_of_detection_sec = (time_t) time_of_detection.tv_sec;
	time_t now_sec = (time_t)now.tv_sec;


	if((now_sec - time_of_detection_sec) > (learning_time_sys*POLL_TIME))
		return false;
	else
		return true;	

}

/*
* Set baselines
*/
void set_baselines(port_node * port_node){
	if(port_node->current_packets > 0){

		port_node->old_baseline = R0_BASELINE * port_node->new_baseline;
		port_node->new_baseline = (R1_BASELINE * port_node->current_packets) + port_node->old_baseline;
	}
	port_node->current_packets = 0;
}

/*
* Verify poisson if above threshold
*/

void verify_poisson(port_node *itr_port) {
	printf("current packets: %d\n", itr_port->current_packets);
	if(itr_port->current_packets == 0)
		itr_port->current_packets == 1;

	itr_port->poisson_result = 1 - (1 + 1/poisson(itr_port->current_packets, itr_port->new_baseline));
	printf("poisson %Lf\n", itr_port->poisson_result);
	if(itr_port->poisson_result > global_threshold) {
		itr_port->wait_alert++;
		if(itr_port->wait_alert >= wait_alert_sys) {
			print_ips_by_port(itr_port->port_name);
		}					
	}else if(itr_port->wait_alert > 0){
		itr_port->wait_alert = 0;
	}
	itr_port->current_packets = 0;
}

/*
* Iterate over the ip_list and check if the port has learned.
*/
void iterate_to_learn(ip_node *itr) {

	ip_node * next = NULL;
	port_node * itr_port = NULL, *next_port = NULL;
		for(; itr!= NULL;itr=next){
			for(itr_port = itr->tcp_ports; itr_port != NULL; itr_port = next_port) {
				//printf("port_tcp: %d\n", itr_port->port_name);
				if(itr_port->learnt){
					verify_poisson(itr_port);
				}else{
					if(still_has_to_learn(itr_port->time_of_detection,itr_port->learning_time)){
						set_baselines(itr_port);
					}else{
						itr_port->learnt = true;
					}
				}
				next_port = itr_port->hh.next;			
			}

			for(itr_port = itr->udp_ports; itr_port != NULL; itr_port = next_port) {
				//printf("port_udp: %d\n", itr_port->port_name);
				if(itr_port->learnt){
					verify_poisson(itr_port);
				}else{
					if(still_has_to_learn(itr_port->time_of_detection,itr_port->learning_time)){
						set_baselines(itr_port);
					}else{
						itr_port->learnt = true;
					}
				}
				next_port = itr_port->hh.next;			
			}
			for(itr_port = itr->icmp_ports; itr_port != NULL; itr_port = next_port) {
				if(itr_port->learnt){
					verify_poisson(itr_port);
				}else{
					if(still_has_to_learn(itr_port->time_of_detection,itr_port->learning_time)){
						set_baselines(itr_port);
					}else{
						itr_port->learnt = true;
					}
				}
				next_port = itr_port->hh.next;			
			}

			next = itr->hh.next;
		}
}

void iterate_learnt(ip_node *itr) {

	ip_node * next = NULL;
	port_node * itr_port = NULL, *next_port = NULL;
	printf("\nIteration learnt:\n");
		for(; itr!= NULL;itr=next){
			for(itr_port = itr->tcp_ports; itr_port != NULL; itr_port = next_port) {
				printf("\nport_tcp: %d, new_baseline: %f\n", itr_port->port_name,itr_port->new_baseline);
				verify_poisson(itr_port);
				next_port = itr_port->hh.next;			
			}

			for(itr_port = itr->udp_ports; itr_port != NULL; itr_port = next_port) {
				printf("\nport_udp: %d, new_baseline: %f\n", itr_port->port_name,itr_port->new_baseline);
				verify_poisson(itr_port);
				next_port = itr_port->hh.next;			
			}
			for(itr_port = itr->icmp_ports; itr_port != NULL; itr_port = next_port) {
				printf("\nport_icmp: %d, new_baseline: %f\n", itr_port->port_name,itr_port->new_baseline);
				verify_poisson(itr_port);
				next_port = itr_port->hh.next;			
			}

			next = itr->hh.next;
		}
}

/*
* Learning Control - Poll Iteration
*/
void * continuous_learning(){
	int i = 0;
	while(true){
		printf("\n POLL %d\n",i);
		iterate_to_learn(ip_list);
		//iterate_learnt(ip_list);
		printf("Sleeping...\n");
		sleep(POLL_TIME);
		i++;
	}
}



