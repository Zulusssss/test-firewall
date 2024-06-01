#ifndef FIREWALL_H
#define FIREWALL_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define MAX_RULES 100
#define MAX_IP_LENGTH 16
#define MAX_ACTION_LENGTH 10

typedef struct {
    char src_ip[MAX_IP_LENGTH];
    char dst_ip[MAX_IP_LENGTH];
    char protocol[10];
    char action[MAX_ACTION_LENGTH];
} FirewallRule;

extern FirewallRule rules[MAX_RULES];
extern int rule_count;

void load_rules_from_file(const char *filename);
int ip_match(const char *ip, const char *rule_ip);
int is_ip_in_cidr(const char *ip, const char *cidr);
int is_valid_ip(const char *ip);

#endif // FIREWALL_H
