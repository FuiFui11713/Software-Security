// safe_mul_guarded.c — guarded multiplication should be treated as safe
#include <stdio.h>
#include <limits.h>

int main() {
    int a = 12;
    int b = 3;

    if (a != 0 && b > INT_MAX / a) {
        return 1;
    }

    int product = a * b;
    printf("%d\n", product);
    return 0;
}
