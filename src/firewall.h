#ifndef FIREWALL_H
#define FIREWALL_H

struct Packet {
    char src_ip[16];
    char dst_ip[16];
    unsigned short src_port;
    unsigned short dst_port;
    unsigned char protocol; // 6 for TCP, 17 for UDP
};

struct Rule {
    char src_ip[16];
    char dst_ip[16];
    unsigned char protocol; // 6 for TCP, 17 for UDP, 0 for any
    char action[7]; // "ACCEPT" or "DROP"
};

int parse_packet(const char *line, struct Packet *packet);
const char* process_packet(const struct Packet *packet);

#endif // FIREWALL_H
