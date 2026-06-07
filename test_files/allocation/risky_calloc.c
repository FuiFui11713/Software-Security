// risky_calloc.c — calloc multiplication overflow risk in a flow
#include <stdio.h>
#include <stdlib.h>

int main() {
    int rows = 0;
    int cols = 0;

    if (scanf("%d %d", &rows, &cols) != 2) {
        return 1;
    }

    if (rows <= 0 || cols <= 0) {
        return 1;
    }

    int *matrix = calloc(rows, cols * sizeof(int));
    if (matrix == NULL) {
        printf("Allocation failed\n");
        return 1;
    }

    printf("Matrix allocated\n");
    free(matrix);
    return 0;
}
