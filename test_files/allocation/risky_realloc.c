// risky_realloc.c — realloc multiplication overflow in a flow
#include <stdio.h>
#include <stdlib.h>

static int read_growth(void) {
    int value = 0;
    if (scanf("%d", &value) != 1) {
        return 0;
    }
    return value;
}

int main() {
    int *arr = malloc(16);
    if (arr == NULL) {
        return 1;
    }

    int new_count = read_growth();
    if (new_count <= 0) {
        free(arr);
        return 1;
    }

    int *grown = realloc(arr, new_count * sizeof(int));
    if (grown == NULL) {
        free(arr);
        return 1;
    }

    printf("Resized array to %d integers\n", new_count);
    free(grown);
    return 0;
}
