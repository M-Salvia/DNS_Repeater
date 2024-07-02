#pragma once

#include "header.h"
#include "default.h"
#include "struct.h"
#include "dns.h"
#include "cmd.h"

int mode;					
int client_sock;			
int server_sock;			
struct sockaddr_in client_addr;
struct sockaddr_in server_addr;
int addr_len;

int client_port;			
char* remote_dns;			
int is_listen;

void init_socket();
void close_server();
void nonblock();
void poll();
void receive_client();
void receive_server();
