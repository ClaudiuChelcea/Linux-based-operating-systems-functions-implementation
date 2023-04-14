// SPDX-License-Identifier: BSD-3-Clause

#include <sys/mman.h>
#include <errno.h>
#include <internal/syscall.h>


static inline void* to_void(int val) {
    return (void*) val;
}

void *mmap(void *addr, size_t length, int prot, int flags, int fd, off_t offset)
{
    long errno_val;
    short int stopped = -1;
    if ((errno_val = -syscall(__NR_mmap, addr, length, prot, flags, fd, offset)) >= 0)
    {
        errno = errno_val;
        stopped = 1;
        return (void*) -1;
    }
    
    return stopped == -1 ? (void*) -errno_val : NULL;
}


void *mremap(void *old_address, size_t old_size, size_t new_size, int flags)
{
    long errno_val;
    short int stopped = -1;
    if ((errno_val = -syscall(__NR_mremap, old_address, old_size, new_size, flags)) >= 0)
    {
        errno = errno_val;
        stopped = 1;
        return (void*) -1;
    }
    
    return stopped == -1 ? (void*) -errno_val : NULL;
}

int munmap(void *addr, size_t length)
{
    long errno_val;
    short int stopped = -1;
    if ((errno_val = -syscall(__NR_munmap, addr, length)) >= 0)
    {
        errno = errno_val;
        stopped = 1;
        return (void*) -1;
    }
    
    return stopped == -1 ? (void*) -errno_val : NULL;
}