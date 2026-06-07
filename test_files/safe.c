// safe.c — No integer overflow risks
#include <stdio.h>

int main() {
    int a = 5;
    int b = 3;
    int result = 8;   // hardcoded literal, no overflow risk

    printf("Result: %d\n", result);
    return 0;
}
