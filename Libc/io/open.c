// SPDX-License-Identifier: BSD-3-Clause

#include <fcntl.h>
#include <internal/syscall.h>
#include <stdarg.h>
#include <errno.h>

static inline int perror(const char *str, int fd, const char *filename, int flags)
{
    errno = -syscall(__NR_open, filename, flags);
    return -1;
}

int open(const char *filename, int flags, ...)
{
    int fd;
    if ((fd = syscall(__NR_open, filename, flags)) < 0) {
        return perror("my_open", fd, filename, flags);
    } else return fd;
}
