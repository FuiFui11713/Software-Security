// risky_malloc_rows_cols.c — allocation overflow with rows * cols * sizeof(int)
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

    int *matrix = malloc(rows * cols * sizeof(int));
    if (matrix == NULL) {
        return 1;
    }

    printf("Matrix allocated\n");
    free(matrix);
    return 0;
}
