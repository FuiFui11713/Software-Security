// risky_intmin.c — direct INT_MIN subtraction underflow risk
#include <stdio.h>
#include <limits.h>

int main() {
    int result = INT_MIN - 1;
    printf("%d\n", result);
    return 0;
}
