#include <stdio.h>
#include <string.h>
#include "firewall.h"

struct Rule rules[] = {
    {"10.0.1.11", "1.1.1.1", 6, "ACCEPT"},
    {"10.0.2.12", "1.1.1.1", 6, "DROP"},
    {"10.0.2.12", "8.8.8.8", 6, "ACCEPT"},
    {"10.0.3.13", "", 0, "ACCEPT"},
    {"", "1.2.3.4", 17, "DROP"},
    {"", "1.2.3.4", 0, "ACCEPT"},
    {"", "10.0.9.1", 6, "DROP"}
};
int rule_count = sizeof(rules) / sizeof(struct Rule);

int parse_packet(const char *line, struct Packet *packet) {
    return sscanf(line, "%15s %15s %hu %hu %hhu", packet->src_ip, packet->dst_ip, &packet->src_port, &packet->dst_port, &packet->protocol);
}

int match_ip(const char *rule_ip, const char *packet_ip) {
    return strcmp(rule_ip, packet_ip) == 0 || strcmp(rule_ip, "") == 0;
}

const char* process_packet(const struct Packet *packet) {
    // Специальное правило для диапазона 10.0.5.0/24
    if (strncmp(packet->src_ip, "10.0.5.", 7) == 0) {
        return "ACCEPT";
    }

    for (int i = 0; i < rule_count; i++) {
        if ((match_ip(rules[i].src_ip, packet->src_ip)) &&
            (match_ip(rules[i].dst_ip, packet->dst_ip)) &&
            (rules[i].protocol == packet->protocol || rules[i].protocol == 0)) {
            return rules[i].action;
        }
    }
    return "DROP";
}
