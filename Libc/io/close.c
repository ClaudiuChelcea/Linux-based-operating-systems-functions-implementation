// SPDX-License-Identifier: BSD-3-Clause

#include <unistd.h>
#include <internal/syscall.h>
#include <stdarg.h>
#include <errno.h>

int close(int fd)
{
    long result = 0;
    if ((result = syscall(__NR_close, fd)) >=
     0) {
        return 0;
    } else if ((result = syscall(__NR_close, fd)) < 0) {
        errno = -result;
    }

    return -1;
}
