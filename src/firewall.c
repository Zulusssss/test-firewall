#include "firewall.h"

FirewallRule rules[MAX_RULES];
int rule_count = 0;

void load_rules_from_file(const char *filename) {
    FILE *file = fopen(filename, "r");
    if (!file) {
        perror("Failed to open rules file");
        exit(EXIT_FAILURE);
    }

    char line[128];
    while (fgets(line, sizeof(line), file) && rule_count < MAX_RULES) {
        FirewallRule rule;
        sscanf(line, "%s %s %s %s", rule.src_ip, rule.dst_ip, rule.protocol, rule.action);
        rules[rule_count++] = rule;
    }

    fclose(file);
}

int is_valid_ip(const char *ip) {
    int segments = 0;   // Segment count
    int chCnt = 0;      // Character count within segment
    int num = 0;        // Number being processed

    // Iterate through every character in the string
    while (*ip) {
        if (*ip == '.') {
            if (chCnt == 0 || num < 0 || num > 255) return 0; // No character between dots or invalid number
            segments++;
            chCnt = 0;                // Reset character count for next segment
            num = 0;                  // Reset number for next segment
        } else if (*ip >= '0' && *ip <= '9') {
            chCnt++;
            if (chCnt > 3) return 0; // Segment too long
            num = num * 10 + (*ip - '0'); // Update number
        } else {
            return 0; // Invalid character
        }
        ip++;
    }

    // Ensure the string ended with a valid segment and number
    if (chCnt == 0 || num < 0 || num > 255) return 0;

    // Ensure there are exactly 3 dots
    return segments == 3;
}

int ip_match(const char *ip, const char *rule_ip) {
    if (strcmp(rule_ip, "any") == 0) {
        return 1;
    }

    if (!is_valid_ip(ip)) {
        return 0;
    }

    if (strchr(rule_ip, '/')) {
        return is_ip_in_cidr(ip, rule_ip);
    }

    return strcmp(ip, rule_ip) == 0;
}

int is_ip_in_cidr(const char *ip, const char *cidr) {
    char ip_copy[MAX_IP_LENGTH];
    char cidr_copy[MAX_IP_LENGTH];

    strcpy(ip_copy, ip);
    strcpy(cidr_copy, cidr);

    char *slash = strchr(cidr_copy, '/');
    if (!slash) {
        return 0;
    }

    *slash = '\0';
    int prefix_len = atoi(slash + 1);

    unsigned int ip_addr = 0, cidr_addr = 0;
    sscanf(ip_copy, "%hhu.%hhu.%hhu.%hhu", &((unsigned char *)&ip_addr)[3], &((unsigned char *)&ip_addr)[2], &((unsigned char *)&ip_addr)[1], &((unsigned char *)&ip_addr)[0]);
    sscanf(cidr_copy, "%hhu.%hhu.%hhu.%hhu", &((unsigned char *)&cidr_addr)[3], &((unsigned char *)&cidr_addr)[2], &((unsigned char *)&cidr_addr)[1], &((unsigned char *)&cidr_addr)[0]);

    unsigned int mask = (prefix_len == 0) ? 0 : ~0U << (32 - prefix_len);

    return (ip_addr & mask) == (cidr_addr & mask);
}
