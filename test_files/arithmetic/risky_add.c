// risky_add.c — unbounded addition risk in a flow
#include <stdio.h>

static int read_value(void) {
    int value = 0;
    if (scanf("%d", &value) != 1) {
        return 0;
    }
    return value;
}

static int compute_sum(int a, int b) {
    int sum = a + b;
    return sum;
}

int main() {
    int a = read_value();
    int b = read_value();

    int sum = compute_sum(a, b);
    printf("%d\n", sum);
    return 0;
}
