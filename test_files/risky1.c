// risky1.c — INT_MAX boundary risk
#include <stdio.h>
#include <limits.h>

int main() {
    // CRITICAL: INT_MAX + 1 causes signed integer overflow
    // undefined behavior in C — value wraps to INT_MIN
    int x = INT_MAX + 1;

    printf("x = %d\n", x);
    return 0;
}
