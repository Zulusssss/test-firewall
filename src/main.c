#include "firewall.h"

int main(int argc, char *argv[]) {
    if (argc != 2) {
        fprintf(stderr, "Usage: %s <rules_file>\n", argv[0]);
        return EXIT_FAILURE;
    }

    load_rules_from_file(argv[1]);

    char packet[128];
    while (fgets(packet, sizeof(packet), stdin)) {
        char src_ip[MAX_IP_LENGTH], dst_ip[MAX_IP_LENGTH];
        int src_port, dst_port, protocol;
        sscanf(packet, "%s %s %d %d %d", src_ip, dst_ip, &src_port, &dst_port, &protocol);

        if (!is_valid_ip(src_ip) || !is_valid_ip(dst_ip)) {
            printf("DROP\n");
            continue;
        }

        int accepted = 0;
        for (int i = 0; i < rule_count; i++) {
            FirewallRule rule = rules[i];
            if (ip_match(src_ip, rule.src_ip) &&
                ip_match(dst_ip, rule.dst_ip) &&
                (strcmp(rule.protocol, "any") == 0 ||
                 (strcmp(rule.protocol, "tcp") == 0 && protocol == 6) ||
                 (strcmp(rule.protocol, "udp") == 0 && protocol == 17))) {
                if (strcmp(rule.action, "ACCEPT") == 0) {
                    accepted = 1;
                } else {
                    accepted = 0;
                }
                break;
            }
        }

        if (accepted) {
            printf("ACCEPT\n");
        } else {
            printf("DROP\n");
        }
    }

    return EXIT_SUCCESS;
}
