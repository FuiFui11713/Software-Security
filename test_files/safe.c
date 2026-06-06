/* safe.c - Demonstrates properly guarded integer operations (no overflows) */
#include <stdio.h>
#include <stdlib.h>
#include <limits.h>
#include <stddef.h>

/* Safely allocates n elements of given size. Returns NULL on overflow. */
void *safe_alloc(size_t n, size_t elem_size) {
    if (n == 0 || elem_size == 0) return NULL;
    if (n > SIZE_MAX / elem_size) return NULL;   /* overflow guard */
    return malloc(n * elem_size);                /* safe: guarded above */
}

/* Safely adds two ints. Returns 0 and sets overflow=1 on overflow. */
int safe_add(int a, int b, int *overflow) {
    *overflow = 0;
    if (b > 0 && a > INT_MAX - b) { *overflow = 1; return 0; }
    if (b < 0 && a < INT_MIN - b) { *overflow = 1; return 0; }
    return a + b;                                /* safe: guarded above */
}

int main() {
    int overflow = 0;

    /* These are constant-folded literals — no runtime risk */
    int count = 10;
    int factor = 4;

    /* Safe allocation through wrapper */
    int *buf = safe_alloc((size_t)count, sizeof(int));
    if (!buf) { fprintf(stderr, "Allocation failed\n"); return 1; }

    /* Safe addition through wrapper */
    int total = safe_add(count, factor, &overflow);
    if (overflow) { fprintf(stderr, "Overflow detected\n"); free(buf); return 1; }

    printf("Total: %d\n", total);
    free(buf);
    return 0;
}
