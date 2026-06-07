// risky3.c — Multiple risk levels: HIGH, MEDIUM, LOW
#include <stdio.h>

int main() {
    int a = 1000;
    int b = 2000;

    // HIGH: multiplication overflow risk
    int product = a * b;

    // MEDIUM: addition overflow risk
    int sum = a + b;

    // LOW: subtraction underflow risk
    int diff = a - b;

    printf("product=%d sum=%d diff=%d\n", product, sum, diff);
    return 0;
}
