// SPDX-License-Identifier: BSD-3-Clause

#include <sys/stat.h>
#include <errno.h>

static inline int perror(const char *str, int fd, struct stat *st)
{
    errno = -syscall(5, fd, st);
    return -1;
}

int fstat(int fd, struct stat *st)
{
    int res;
    if ((res = syscall(5, fd, st)) < 0) {
        return perror("my_stat", fd, st);
    } else return res;
}

