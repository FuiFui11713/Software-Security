// risky_malloc.c — malloc multiplication overflow in a flow
#include <stdio.h>
#include <stdlib.h>

static int read_count(void) {
    int n = 0;
    if (scanf("%d", &n) != 1) {
        return 0;
    }
    return n;
}

int main() {
    int n = read_count();
    if (n <= 0) {
        return 1;
    }

    int *arr = malloc(n * sizeof(int));

    if (arr == NULL) {
        printf("Allocation failed\n");
        return 1;
    }

    printf("Allocated %d integers\n", n);
    free(arr);
    return 0;
}
