// risky_mul.c — unbounded multiplication risk in a flow
#include <stdio.h>

static int read_value(void) {
    int value = 0;
    if (scanf("%d", &value) != 1) {
        return 0;
    }
    return value;
}

static int compute_product(int a, int b) {
    int product = a * b;
    return product;
}

int main() {
    int a = read_value();
    int b = read_value();

    int product = compute_product(a, b);
    printf("%d\n", product);
    return 0;
}
