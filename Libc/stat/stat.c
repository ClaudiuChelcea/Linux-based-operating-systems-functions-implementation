// SPDX-License-Identifier: BSD-3-Clause

#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>

static inline int perror(const char *restrict path, struct stat *restrict buf)
{
    errno = -syscall(4, path, buf);
    return -1;
}

int stat(const char *restrict path, struct stat *restrict buf)
{
    int res;
    if ((res = syscall(4, path, buf)) < 0) {
        return perror(path, buf);
    } else return res;
}

