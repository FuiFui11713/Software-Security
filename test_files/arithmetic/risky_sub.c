// risky_sub.c — unbounded subtraction risk in a flow
#include <stdio.h>

static int read_value(void) {
    int value = 0;
    if (scanf("%d", &value) != 1) {
        return 0;
    }
    return value;
}

static int compute_diff(int a, int b) {
    int diff = a - b;
    return diff;
}

int main() {
    int a = read_value();
    int b = read_value();

    int diff = compute_diff(a, b);
    printf("%d\n", diff);
    return 0;
}
