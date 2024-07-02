#pragma once

#include "header.h"
#include "server.h"
#include "struct.h"

char* HOST_PATH;					
char* LOG_PATH;						

int debug_mode;
int log_mode;

void init(int argc, char* argv[]);
void get_config(int argc, char* argv[]);
void info();
void init_id_list();
void write_log(char* domain, uint8_t* ip_addr);