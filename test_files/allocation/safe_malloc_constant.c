// safe_malloc_constant.c — constant allocation should not be flagged
#include <stdio.h>
#include <stdlib.h>

int main() {
    int *buffer = malloc(16);
    if (buffer == NULL) {
        return 1;
    }

    printf("Buffer allocated\n");
    free(buffer);
    return 0;
}
