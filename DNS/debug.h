#pragma once
#include "dns.h"

void print_header(dns_message* msg);

void print_question(dns_message* msg);

void print_answer(dns_message* msg);