#include <stdlib.h>
#include <stdio.h>
#include <string.h>

typedef struct ip_alert{	
	int upper_ip;
	char upper_name[30];
	int packets;
	struct ip_alert * next;
	struct ip_alert * prev;
}ip_alert;

typedef struct ip_alert_list{
	struct ip_alert * head;
	struct ip_alert * tail;
	int size;
}ip_alert_list;




ip_alert_list * init_list(ip_alert_list * list){
	list = (ip_alert_list*)calloc(1,sizeof(ip_alert_list));
	if(!list)
		printf("Couldn't allocate ip_alert_list\n");
	list->head =  NULL;
	list->tail =  NULL;
	list->size = 0;
	return list;
}

ip_alert * create_ip_alert_node(int upper_ip, char * upper_name, int packets){
	ip_alert * node = NULL; 
	node = (ip_alert *) calloc(1,sizeof(ip_alert));
	if(!node) {
		printf("Couldn't allocate ip_alert\n");
		return NULL;
	}

	node->upper_ip = upper_ip;
	strcpy(node->upper_name,upper_name);
	node->packets = packets;
	node->prev = NULL;
	node->next = NULL;
	return node;
}


void delete_all(ip_alert_list * list){
	ip_alert * node = NULL, *tmp = NULL;
	node = list->tail;
	while(node){
		if(!(node == list->head)){	
			tmp = node->prev;
		} else{
			tmp = NULL;
		}
		free(node);
		node = tmp;
	}
	list->head = NULL;
	list->tail = NULL;
	list->size = 0;
}

int delete_from_list(ip_alert_list * list, int upper_ip){
	ip_alert *temp;
	ip_alert *node = list->head;

	while(node) {
		if(node->upper_ip == upper_ip){
			if(node == list->head){
				list->head = node->next;
				list->head->prev = NULL;
			}else if(node == list->tail){
				list->tail = node->prev;
				list->tail->next = NULL;
			}else{
				node->prev->next = node->next;
				node->next->prev = node->prev;
			}
			list->size--;
			free(node);
			break;			
		}
		node = node->next;
	}	
}

int push_back(ip_alert_list * list, ip_alert * node){

	if(!node){
		printf("Node is NULL\n");
		return -1;
	}

	if(list->head == NULL){
		list->head = node;
		list->tail = node;
		list->head->prev = NULL;
		list->head->next = NULL;
		list->size++;
	}else{
		list->tail->next = node;
		node->prev = list->tail;
		list->tail = node;
		list->size++;
	}
}

ip_alert * find_node(ip_alert_list * list, int upper_ip){
	ip_alert *node = NULL;	
	node = list->head;
	while(node) {
		if(node->upper_ip == upper_ip){
			return node;				
		}
		node = node->next;
	}
	return NULL;	
}
