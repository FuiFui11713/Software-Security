// risky_intmax.c — INT_MAX boundary risk in a flow
#include <stdio.h>
#include <limits.h>

static int apply_growth(int delta) {
    return INT_MAX + delta;
}

int main() {
    int delta = 0;
    if (scanf("%d", &delta) != 1) {
        return 1;
    }

    if (delta <= 0) {
        return 0;
    }

    int x = apply_growth(delta);

    printf("x = %d\n", x);
    return 0;
}
