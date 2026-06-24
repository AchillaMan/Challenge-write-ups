#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "libs/ivi_diag.h"

int main(int argc, char **argv) {
    const char *test_id = "quick";
    char status[128];
    int rc;

    if (argc > 1) {
        test_id = argv[1];
    }

    rc = diag_run(test_id, status, sizeof(status));
    if (rc == 0) {
        printf("diag status: %s\n", status);
        return 0;
    }

    fprintf(stderr, "diag failed: %s\n", status);
    return 1;
}
