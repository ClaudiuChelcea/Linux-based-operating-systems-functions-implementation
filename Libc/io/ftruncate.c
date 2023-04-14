// SPDX-License-Identifier: BSD-3-Clause

#include <unistd.h>
#include <internal/syscall.h>
#include <errno.h>

typedef short int bool;

#define true 0
#define false -1

int ftruncate(int fd, off_t length)
{
    bool return_val = true;
    if (syscall(__NR_ftruncate, fd, length) < 0) {
        errno = -syscall(__NR_ftruncate, fd, length);
        return_val = -1;
    }
    
    return return_val;
}
