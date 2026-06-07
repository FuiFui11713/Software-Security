// risky2.c — malloc multiplication overflow
#include <stdio.h>
#include <stdlib.h>

int main() {
    int n = 50000;

    // CRITICAL: n * sizeof(int) can overflow if n is large enough
    // attacker-controlled n could make malloc allocate far less memory than expected
    int *arr = malloc(n * sizeof(int));

    if (arr == NULL) {
        printf("Allocation failed\n");
        return 1;
    }

    printf("Allocated %d integers\n", n);
    free(arr);
    return 0;
}
