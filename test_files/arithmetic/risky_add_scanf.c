// risky_add_scanf.c — addition overflow risk driven by user input
#include <stdio.h>

int main() {
    int a = 0;
    int b = 0;

    if (scanf("%d %d", &a, &b) != 2) {
        return 1;
    }

    int sum = a + b;
    printf("%d\n", sum);
    return 0;
}
