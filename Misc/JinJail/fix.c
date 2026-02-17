#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <strings.h>

int main(int argc, char *argv[]) {
    if (argc > 1 && strcasecmp(argv[1], "help") == 0) {
        setuid(0);
        system("cat /root/flag.txt");
    } else {
        printf("Nope, you didnt ask for help...\n");
    }
    return 0;
}
