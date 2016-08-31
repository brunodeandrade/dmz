#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <glib.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <math.h>
#include <tgmath.h>
#include "linked_list.c"
#include "slog.h"

#define POLL_TIME 20
#define MAX_CACHE 1000000
#define NUMBER_TOP_SENDERS 10

long double cache_log[MAX_CACHE];
long double cache_sum[MAX_CACHE];

typedef int ptype;
enum { TCP, UDP, ICMP };

typedef int bool;
enum {false, true};
enum {STATIC, DYNAMIC};


typedef struct port_node{
	int port_name;
	int current_packets;
	bool learnt;
	bool is_suspicious;
	long double poisson_result; //defined by poisson
	int wait_alert; //wait time until the throw of an alert
	int learning_time; //learning time of the algorithm, in polls not seconds
	float new_baseline;//The result of the learning
	float old_baseline;
	struct timeval time_of_detection;
	ip_alert_list *upper_ips;
}port_node;

typedef struct ip_node{	
	int lower_ip;//primary key
	char * ip_name;
	GHashTable * tcp_ports;
	GHashTable * udp_ports;
	GHashTable * icmp_ports;// It's a code not a port
} ip_node;


GHashTable * ip_list;
//ip_node * to_learn_list = NULL;
//ip_node * learnt_list = NULL;

int wait_alert_sys; //wait time until the throw of an alert, defined by the user for the whole system
int learning_time_sys; //learning time of the algorithm, defined by the user for the whole system
int static_baseline;
float global_threshold;
float R0_BASELINE;
float R1_BASELINE;

int package_threshold; // a package_threshold, if the current_package * package_threshold is > than baseline, should alert.
int verify_config; // should tell which verify technique the system is using (0 is poisson, 1 is baseline).
int learning_mode;

bool is_adding, is_polling;
int ip_number;
int ports[66000];

void iterator_port(gpointer key, gpointer value, gpointer user_data) {
	int chave = *(int *)key;
	port_node *port = (port_node *) value;

	printf("\t Chave: %d, Port: %d\n",chave, port->port_name);
}



void iterator(gpointer key, gpointer value, gpointer user_data) {
	int chave = *(int *)key;
	ip_node *ip = (ip_node *) value;

	printf("IP: %s  Ports:\n", ip->ip_name);
	g_hash_table_foreach(ip->udp_ports, (GHFunc)iterator_port, NULL);
 	//printf(user_data, *(gint*)key, value);
}



int init_cache() {

	ip_list = g_hash_table_new (g_direct_hash,g_int_equal);

    int i=1;

    for(; i<MAX_CACHE; i++){
            cache_log[i] = logl((long double)i);
        }

    memset(cache_sum, 0x0, MAX_CACHE);

	for(i=0; i<66000; i++) ports[i] = 0;
    is_adding = 0;
    is_polling = 0;

    /*Log library parameters
    * The three final parameters are overwritten by the log.conf file
    */ 
    slog_init("report", "log.conf", 3, 3, 1);
    slog(2, SLOG_INFO, " Execução Iniciada");

    /*
    	Examples to print the log 
	    slog(3, SLOG_INFO, " Just file");
		slog(0, SLOG_WARN, teste);
    */
}

long double poisson(int k, int lam)     {

        int c = 1;
        long double pvalue = 0;
        long double sum = 0;

        if ( cache_sum[k] ){
                sum = cache_sum[k];
            }
        else {	
                while(c <= k)   {
                        sum += cache_log[c];
                        c++;
                }
                cache_sum[k] = sum;
        }
        
        pvalue = cache_log[2] + k*cache_log[lam] - sum - lam;
        //printf("cache_log:  %LF\n, pvalue: %LF",  cache_log[lam],pvalue);
        return pvalue;
}


int load_file(){
	FILE * config_file = fopen("config.txt","r");
	if(!config_file){
		slog(1, SLOG_ERROR, " Não foi possível abrir o arquivo!");
		return -1;
	}

	fscanf(config_file,"%d %d %d %f %d %f %f %d %d",&wait_alert_sys,&learning_time_sys,&static_baseline,&global_threshold,&package_threshold,
 		&R0_BASELINE,&R1_BASELINE,&verify_config, &learning_mode);

	if ((R0_BASELINE + R1_BASELINE) >= 1.0){
		slog(1, SLOG_ERROR, " Parâmetros inválidos. Por favor verifique se R0 + R1 < 1.\n");
		//	printf("ERROR! These parameters are not set up correctly. Please check if the R0 and R1 parameters < 1.\n");
		exit (-1);
	}

	fclose(config_file);
	init_cache();
	slog(2, SLOG_INFO, "Arquivo de configuração lido com sucesso. Parâmetros do sistema:\n");
	printf("\nTempo para aprendizado: %d segundos cada poll\n", POLL_TIME);
	printf("Tempo total de aprendizado: %d polls\n", learning_time_sys);
	printf("Tempo de espera (WAIT_ALERT): %d polls\n", wait_alert_sys);
	printf("Limiar de detecção: %dx\n", package_threshold);
	printf("Tipo de deteccao: %d\n\n", learning_mode);
	//printf("Wait alert is %d, the learning time is %d, the static baseline is %d and the global package threshold is %f \n\n\n", wait_alert_sys, learning_time_sys,static_baseline,package_threshold);
	return 0;
}


void print_info(long ip_number, char *ip_name, u_short protocol, int lower_port, int packets){

	//printf("Upper number: %ld, Upper name: %s  protocol: %d port: %i  packets: %d \n\n", ip_number, ip_name, protocol,lower_port,packets);

}

/*
*Creates a new ip_node
*
*/
ip_node * create_ip_node(char * ip_name, int lower_ip){
	ip_node * node = (ip_node *) calloc (1,sizeof(ip_node));
	if(!node){
		slog(1, SLOG_ERROR, " ip_node não foi alocado corretamente\n\n");
		return NULL;
	}	
	node->ip_name = ip_name;
	node->lower_ip = lower_ip;
	node->tcp_ports = g_hash_table_new (g_direct_hash,g_int_equal);
	node->udp_ports = g_hash_table_new (g_direct_hash,g_int_equal);
	node->icmp_ports = g_hash_table_new(g_direct_hash,g_int_equal);
	return node;
}

/*
*Creates a port node
*
*/
port_node * create_port_node(int port_name, int current_packets){
	port_node * node = (port_node *) calloc (1,sizeof(port_node));

	if(!node){
		slog(1, SLOG_ERROR, " port_node não foi alocado corretamente\n\n");
		return NULL;
	}	

	
	node->upper_ips = init_list(node->upper_ips);

	if(!node->upper_ips) {
		return NULL;
	}

	node->new_baseline = 0;
	node->old_baseline = 0;
	node->wait_alert = 0;
	node->port_name = port_name;
	node->current_packets = current_packets;
	node->learnt = false;
	node->is_suspicious = false;
	
	gettimeofday(&node->time_of_detection,NULL);

	return node;
}

/*
* Remove port from list
*/
void remove_port(ip_node * ip, port_node * port, u_short protocol_id){

	// int *port_name = (int *)calloc(1,sizeof(int *));
	
	// *port_name = port->port_name;
	
	switch(protocol_id){
		case IPPROTO_TCP:
			g_hash_table_remove(ip->tcp_ports, &ports[port->port_name]);
			break;
		case IPPROTO_UDP:
			g_hash_table_remove(ip->udp_ports, &ports[port->port_name]);
			break;
		case IPPROTO_ICMP:
			g_hash_table_remove(ip->icmp_ports, &ports[port->port_name]);
			break;
		default:
			//slog(1, SLOG_ERROR, "Protocolo desconhecido @ remove_port()\n"); 
			break;
	}
	
}

/*
*Inserts a new port in the hash of the node
*
*/
void insert_port_in_hash (ip_node * ip_node, u_short protocol_id, port_node *port,int port_name) {

	ports[port_name] = port_name;
	switch(protocol_id){
		case IPPROTO_TCP:	
			/*Hash, Chave e valor*/
			g_hash_table_insert(ip_node->tcp_ports,&ports[port_name],port);
			
			break;
		case IPPROTO_UDP:
			/*Chave e valor*/
			g_hash_table_insert(ip_node->udp_ports,&ports[port_name],port);
			
			break;
		case IPPROTO_ICMP:
			/*Chave e valor*/
			g_hash_table_insert(ip_node->icmp_ports,&ports[port_name],port);			
			break;
		default: 
			//slog(1, SLOG_ERROR, "Protocolo desconhecido @ insert_port_in_hash()\n"); 
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
		findable_port = g_hash_table_lookup(ip_node->tcp_ports,&ports[port_name]);
		break;
	case IPPROTO_UDP:
		findable_port = g_hash_table_lookup(ip_node->udp_ports,&ports[port_name]);
		break;
	case IPPROTO_ICMP:
		findable_port = g_hash_table_lookup(ip_node->icmp_ports,&ports[port_name]);
		break;
	default: 
		//slog(1, SLOG_ERROR, "Protocolo desconhecido @ find_port()\n"); 
		break;
	}


	return findable_port;
}

int cmpfunc (const void * a, const void * b) {

	ip_alert *ip_alert_a = (ip_alert *)a;
	ip_alert *ip_alert_b = (ip_alert *)b;

	return ( ip_alert_b->packets - ip_alert_a->packets );
}


/*
* Find ip's for a given PORT
*/
void print_ips_by_port(port_node * port){

	//The strclr doesn't work on normal editors, such as, sublime, vim...
	slog(0, SLOG_NONE, "[%s] Ataque na porta %d", strclr(CLR_RED, "ATK"),ntohs(port->port_name));
	

	ip_alert * itr = port->upper_ips->head, *next = NULL;
	ip_alert * top_senders = NULL;
	unsigned int number_of_upper_ips = port->upper_ips->size;

	top_senders = (ip_alert*)calloc(number_of_upper_ips,sizeof(ip_alert));

	if(!top_senders){
		slog(1, SLOG_ERROR, "Couldn't allocate top_senders\n"); 
		exit(-1);
	}
	int i = 0;
	while(itr){
		if(itr->upper_name && itr->packets > 0){
			strcpy(top_senders[i].upper_name,itr->upper_name);
			top_senders[i].upper_ip = itr->upper_ip;
			top_senders[i].packets = itr->packets;
			i++;
		}
		itr = itr->next;
	}
	slog(0,SLOG_INFO,"Number of iterations: %d, size of upper ips %d",i,number_of_upper_ips);	

	qsort(top_senders,number_of_upper_ips,sizeof(ip_alert),cmpfunc);

	i = 0;

	for(i; i < number_of_upper_ips;i++) {
		if(i < NUMBER_TOP_SENDERS) {
			if (top_senders[i].upper_name){
				//printf("\t %d - IP: %s packets: %d\n",i+1,top_senders[i].upper_name, top_senders[i].packets);
				// printf("\t %d - IP: %s - Pacotes: %d\n",i+1,top_senders[i].upper_name, top_senders[i].packets);


				slog(1, SLOG_NONE, "\t[TOPSND] %d -  Top Sender IP %s (upper_ip: %d) with packets: %d", i+1, top_senders[i].upper_name, ntohs(top_senders[i].upper_ip), top_senders[i].packets);
				top_senders[i].packets = 0;
			}
		}
		else {
			slog(4, SLOG_NONE, "\t[SND] %d Other Sender IP %s with packets %d", i+1, top_senders[i].upper_name, top_senders[i].packets);
		}
	}

}

void find_upper_ip_and_increment (port_node *port, int upper_ip, char *upper_name,  int current_packets) {

	ip_alert *findable_upper = NULL;

	findable_upper = find_node(port->upper_ips,upper_ip);

	if(findable_upper) {
		// ip_alert *node = NULL;	
		// node = port->upper_ips->head;
		// printf("\n --------------1------------\n");
		// while(node) {
		// 	printf("NODE: %s\n",node->upper_name);
		// 	node = node->next;
		// }
		// printf("\n --------------2------------\n");
		findable_upper->packets += current_packets;
	}
	else {
		findable_upper = create_ip_alert_node(upper_ip,upper_name,current_packets);
		if(!findable_upper)
			return;		
		
		// printf("Vai adicionar o seguinte upper:  %s\n",upper_name);
		push_back(port->upper_ips,findable_upper);

	}

}


/*
*Adds the bytes to a port in the hash of the node
*
*/
void find_port_and_increment (ip_node * ip_node, u_short protocol_id, int port_name, int current_packets, int upper_ip, char *upper_name) {
	
	port_node * findable_port = find_port(ip_node, protocol_id, port_name);

	if(findable_port) {

		// printf("Current packets in pool: %d\n",findable_port->current_packets);
		findable_port->current_packets += current_packets;
		if(findable_port->is_suspicious){
			find_upper_ip_and_increment(findable_port,upper_ip,upper_name,current_packets);
		}

	}

	else {
		// printf("Not found port %d. Current packets: %d\n",ntohs(port_name),current_packets);
		port_node * port = create_port_node(port_name, current_packets);
		if(port)
			insert_port_in_hash(ip_node, protocol_id, port,port_name);
		else
			slog(1, SLOG_ERROR, "Não alocado @ find_port_and_increment \n");
	}
}





/*
* Adds an IP node to the hash list
*/
void add_to_hash(int upper_ip,int lower_ip, char * upper_name, char * lower_name, u_short protocol_id, int port_name , int current_packets){

	if(!is_polling) {

			is_adding = true;

			ip_node * findable_ip = NULL;

			findable_ip = g_hash_table_lookup(ip_list,&lower_ip);
			
			if(findable_ip){		
				find_port_and_increment(findable_ip,protocol_id, port_name, current_packets,upper_ip,upper_name);
			}else{
				port_node * port = create_port_node(port_name, current_packets);
				ip_node * ip = create_ip_node(lower_name,lower_ip);
				insert_port_in_hash(ip,protocol_id,port,port_name);
				g_hash_table_insert(ip_list,&lower_ip,ip);
			}	
			is_adding = false;

	}
}


static gboolean free_value(gpointer key, gpointer value, gpointer user_data) {

	g_free(value);
	return true;
}

static gboolean iterator_and_delete_ips(gpointer key, gpointer value, gpointer user_data) {
	ip_node *ip = (ip_node *) value;

	g_hash_table_foreach_remove(ip->tcp_ports,free_value,NULL); 
	g_hash_table_foreach_remove(ip->udp_ports,free_value,NULL); 
	g_hash_table_foreach_remove(ip->icmp_ports,free_value,NULL);

	free(ip);
}



/*
* Free Hash List
*/
void free_hash_list(GHashTable * hash_list){
	ip_node * itr = NULL,* next = NULL;
	port_node * itr_port = NULL, *next_port = NULL;
	int i = 0;
 

	g_hash_table_foreach_remove(hash_list,iterator_and_delete_ips,NULL); 
	
}


void iterate_and_print_ports(gpointer key, gpointer value, gpointer user_data) {
	port_node *port = (port_node *)value;

	//printf("           Port: %d, Current Packets: %d, Baseline: %f \t Detected Time: %d\n",ntohs(port->port_name),port->current_packets,port->new_baseline,port->time_of_detection);
 	//printf(user_data, *(gint*)key, value);
}

void iterate_and_print_ips(gpointer key, gpointer value, gpointer user_data) {
	ip_node *ip = (ip_node *) value;

	printf("\t%d - IP: %s\n",ip_number++,ip->ip_name);
	printf("         TCP\n");
	g_hash_table_foreach(ip->tcp_ports, (GHFunc)iterate_and_print_ports, NULL);

	printf("         UDP\n");
	g_hash_table_foreach(ip->udp_ports, (GHFunc)iterate_and_print_ports, NULL);
	printf("         ICMP\n");
	g_hash_table_foreach(ip->icmp_ports, (GHFunc)iterate_and_print_ports, NULL);
 	//printf(user_data, *(gint*)key, value);
}

/*
* Print Hash
*/
void print_hash(){
	ip_node * itr;
	port_node *irt_port;
	int ip_number = 0;

	printf("\n\tHash:\n");

	g_hash_table_foreach(ip_list, (GHFunc)iterate_and_print_ips, NULL);


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

	port_node->old_baseline = R0_BASELINE * port_node->new_baseline;
	port_node->new_baseline = (R1_BASELINE * port_node->current_packets) + port_node->old_baseline;
	port_node->current_packets = 0;
}

/*
* Verify poisson if above threshold
*/

void verify_poisson(port_node *itr_port) {
	itr_port->poisson_result = 1 - (1 + (1/poisson((int)(itr_port->current_packets), (int)(itr_port->new_baseline))));
	// Verificar o motivo de sempre o resultado da poisson estar sendo o mesmo o global_threshold
    //printf("poisson %LF, port_name: %d, global: %f, baseline: %f, packets %d\n", itr_port->poisson_result, ntohs(itr_port->port_name), global_threshold, itr_port->new_baseline, itr_port->current_packets);
	if(itr_port->poisson_result < global_threshold) {
		itr_port->wait_alert++;
		itr_port->is_suspicious = true;
		if(itr_port->wait_alert >= wait_alert_sys) {
			print_ips_by_port(itr_port);
		}					
	}else if(itr_port->wait_alert > 0){
		itr_port->wait_alert = 0;
		itr_port->is_suspicious = false;
		
	}
	delete_all(itr_port->upper_ips);
	itr_port->current_packets = 0;
}

// TODO DElete this method
char *int_to_string(const unsigned int port_name){

}

/*
* verifiy if baseline is above package_threshold
*/
void verify_baseline(port_node *port){
	if(port->current_packets > (port->new_baseline * package_threshold + 10)){
		port->wait_alert++;


		slog(1, SLOG_WARN, "Fluxo suspeito na porta %d",ntohs(port->port_name));

		port->is_suspicious = true;
		if(port->wait_alert >= wait_alert_sys) {
			printf("Port_name: %d, Current packets: %d, Current threshold: %.2f, Current Baseline: %.2f\n",ntohs(port->port_name),port->current_packets,
				 package_threshold*port->new_baseline, port->new_baseline);

       	 		print_ips_by_port(port);
		}	
	} else if(port->wait_alert > 0){
		port->wait_alert = 0;
		port->is_suspicious = false;
		
	} else {
		if (learning_mode == DYNAMIC){
			//printf("Port_name: %d, Current packets: %d, Old threshold: %.2f, Old Baseline: %.2f\n", ntohs(port->port_name),port->current_packets, package_threshold*port->new_baseline, port->new_baseline);
			set_baselines(port);
			//printf("Port_name: %d, Current packets: %d, New threshold: %.2f, New Baseline: %.2f\n", ntohs(port->port_name),port->current_packets, package_threshold*port->new_baseline, port->new_baseline);
		}
	}
	delete_all(port->upper_ips);
	port->current_packets = 0;
}

/*
* Verify if flow is above threshold
*/

void verify_flow(port_node *port){
	/* printf("\n\nconfig: %d\n\n\n", verify_config); */
	if(port->current_packets > 0){
		switch (verify_config){
			case 0: 
				verify_poisson(port);
				break;
			case 1:
				verify_baseline(port);
				break;
		}
	}
}

void iterator_ports(gpointer key, gpointer value, gpointer user_data) {

	port_node *itr_port = (port_node *) value;

	if(itr_port->learnt){
		verify_flow(itr_port);
	}else{
		if(still_has_to_learn(itr_port->time_of_detection,itr_port->learning_time)){
			set_baselines(itr_port);
		}else{
			itr_port->learnt = true;
		}
	}
}

void iterator_ips(gpointer key, gpointer value, gpointer user_data) {
	ip_node *ip = (ip_node *) value;

	g_hash_table_foreach(ip->tcp_ports, (GHFunc)iterator_ports, NULL);
	g_hash_table_foreach(ip->udp_ports, (GHFunc)iterator_ports, NULL);
	g_hash_table_foreach(ip->icmp_ports, (GHFunc)iterator_ports, NULL);
}


/*
* Iterate over the ip_list and check if the port has learned.
*/
void iterate_to_learn() {

	ip_node * next = NULL;
	port_node * itr_port = NULL, *next_port = NULL;
	g_hash_table_foreach(ip_list, (GHFunc)iterator_ips, NULL);
}

/*
* Learning Control - Poll Iteration
*/
void * continuous_learning(){
	int i = 0;
	while(true){
		printf("polling\n");
		if(!is_adding) {
			is_polling = true;
			printf("--------------------------\n");
			printf("POLL %d\n",i);
			printf("--------------------------\n");
			iterate_to_learn();
			//iterate_learnt(ip_list);
			is_polling = false;
			//printf("Sleeping...\n");
			sleep(POLL_TIME);
			i++;
		}
	}
}



