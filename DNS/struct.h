#pragma once

#include "header.h"
#include "default.h"
#include "cmd.h"

char IPAddr[MAX_SIZE];
char domain[MAX_SIZE];

typedef struct trie_node {
	uint16_t pre;			
	uint16_t val[37];		
	uint8_t IP[4];			
	uint8_t isEnd;			
} trie;

typedef struct node {
	uint8_t IP[4];
	char domain[MAX_SIZE];
	struct node* next;
	struct node* prev;
} lru_node;


typedef struct {
	uint16_t client_ID;
	int expire_time; 
	struct sockaddr_in client_addr;
} ID_conversion;

//维护一张ID_list用于多用户并发访问，DNS header头部的ID被统一重写
ID_conversion ID_list[ID_LIST_SIZE]; 

trie list_trie[MAX_NUM];	
lru_node* head;
lru_node* tail;
int list_size;
int cache_size;

void transfer_ip(uint8_t* this_IP, char* IP_addr);

int get_num(uint8_t val);

void add_node(trie* root, uint8_t* IP, char* domain);
int query_node(trie* root, char* domain, uint8_t* ip_addr);


void init_cache();

int query_cache(char* domain, uint8_t* ip_addr);

void update_cache(uint8_t ip_addr[4], char* domain);

void delete_cache();

uint16_t update_id(uint16_t client_ID, struct sockaddr_in client_addr);

void read_host();