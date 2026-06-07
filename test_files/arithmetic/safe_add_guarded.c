// safe_add_guarded.c — guarded addition should be treated as safe
#include <stdio.h>
#include <limits.h>

int main() {
    int a = 10;
    int b = 20;

    if (a > INT_MAX - b) {
        return 1;
    }

    int sum = a + b;
    printf("%d\n", sum);
    return 0;
}
