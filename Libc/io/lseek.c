#include <errno.h>
#include <internal/syscall.h>
#include <unistd.h>

long handle_lseek_error(int err);

off_t lseek(int fd, off_t offset, int whence) {

    if(fd < 0 || offset < 0 || whence < 0)
    {
        errno = -syscall(__NR_lseek, fd, offset, whence);
        return -1;
    }

    long result = syscall(__NR_lseek, fd, offset, whence);
    if (result == -1) {
        errno = handle_lseek_error(errno);
    }

    return result;
}

long handle_lseek_error(int err) {
    switch (err) {
        case EBADF:
        case EINVAL:
        case EOVERFLOW:
            return err;
        default:
            return EIO;
    }
}
