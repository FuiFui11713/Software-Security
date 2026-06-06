/* risky.c - Multiple integer overflow vulnerabilities */
#include <stdio.h>
#include <stdlib.h>
#include <limits.h>

int main() {
    int user_input = 50000;

    /* CRITICAL: INT_MAX boundary violation */
    int x = INT_MAX + 1;

    /* HIGH: unchecked multiplication used as malloc size */
    int count = 1000;
    int item_size = 1024;
    char *buffer = malloc(count * sizeof(int));

    /* HIGH: unchecked multiplication */
    int size = user_input * 1024;

    /* MEDIUM: unchecked addition */
    int total = user_input + item_size;

    /* CRITICAL: malloc with multiplication */
    int *arr = malloc(user_input * sizeof(int));

    /* LOW: subtraction that may underflow */
    int diff = user_input - 100000;

    printf("size: %d\n", size);
    printf("total: %d\n", total);
    printf("diff: %d\n", diff);

    free(buffer);
    free(arr);
    return 0;
}
