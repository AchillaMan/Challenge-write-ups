#include <stdio.h>
#include <stdlib.h>

int main(void) {
    FILE *f = fopen("/flag.txt", "r");
    char buf[256];

    if (f == NULL) {
        return 1;
    }
    if (fgets(buf, sizeof(buf), f) == NULL) {
        fclose(f);
        return 1;
    }
    fclose(f);
    fputs(buf, stdout);
    return 0;
}
