#include <stddef.h>
#include <internal/syscall.h>
#include <unistd.h>

size_t strlen(const char *str)
{
    size_t i = 0;

    for (; *str != '\0'; str++, i++);

    return i;
}

int puts(const char *s)
{
    if (write(1, s, strlen(s)) < 0 || write(1, "\n", 1) < 0) {
        return -1;
    } else {
        return 1;
    }
}
