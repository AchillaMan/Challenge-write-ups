#include "ivi_diag.h"

#include <stdio.h>
#include <string.h>

int diag_run(const char *test_id, char *out, size_t out_sz) {
    if (out == NULL || out_sz == 0 || test_id == NULL) {
        return -1;
    }

    if (strcmp(test_id, "quick") == 0) {
        snprintf(out, out_sz, "quick-pass");
        return 0;
    }
    if (strcmp(test_id, "sensors") == 0) {
        snprintf(out, out_sz, "sensors-ok");
        return 0;
    }
    if (strcmp(test_id, "storage") == 0) {
        snprintf(out, out_sz, "storage-ok");
        return 0;
    }

    snprintf(out, out_sz, "unknown-test");
    return 1;
}
