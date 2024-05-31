#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "firewall.h"

#define BUFFER_SIZE 1024

int main() {
    char buffer[BUFFER_SIZE];
    struct Packet packet;

    while (fgets(buffer, BUFFER_SIZE, stdin)) {
        if (parse_packet(buffer, &packet) == 5) {
            printf("%s\n", process_packet(&packet));
        } else {
            fprintf(stderr, "Error parsing packet: %s", buffer);
        }
    }

    return 0;
}
