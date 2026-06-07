// risky_realloc_rows_cols.c — realloc overflow with multiplication in size expression
#include <stdio.h>
#include <stdlib.h>

int main() {
    int *buffer = malloc(32);
    if (buffer == NULL) {
        return 1;
    }

    int rows = 0;
    int cols = 0;
    if (scanf("%d %d", &rows, &cols) != 2) {
        free(buffer);
        return 1;
    }

    if (rows <= 0 || cols <= 0) {
        free(buffer);
        return 1;
    }

    int *grown = realloc(buffer, rows * cols * sizeof(int));
    if (grown == NULL) {
        free(buffer);
        return 1;
    }

    free(grown);
    return 0;
}
