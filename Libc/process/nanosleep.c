#include <fcntl.h>
#include <internal/syscall.h>
#include <stdarg.h>
#include <errno.h>
#include <time.h>

int wait_for_nanosleep(int *syscall_response);
int handle_nanosleep_error(int err);
int call_nanosleep(const struct timespec *req, struct timespec *rem);

int nanosleep(const struct timespec *req, struct timespec *rem) {
    int syscall_response = call_nanosleep(req, rem);
    if (wait_for_nanosleep(&syscall_response) < 0) {
        errno = handle_nanosleep_error(errno);
    }
    return syscall_response;
}

int call_nanosleep(const struct timespec *req, struct timespec *rem) {
    return syscall(__NR_nanosleep, req, rem);
}

int wait_for_nanosleep(int *syscall_response) {
    int s_a_terminat = 0;
    while (errno == EINTR) {
        if(*syscall_response > 0) {
            s_a_terminat = 1;
            break;
        } else {
            *syscall_response = call_nanosleep(NULL, NULL);
        }
    }

    if(s_a_terminat == 1)
        return *syscall_response;
    else
        return -1;
}

int handle_nanosleep_error(int err) {
    int output_val = 0;
    switch (err) {
        case EFAULT:
            output_val = err;
            break;
        case EINVAL:
            output_val = err;
            break;
        default:
            output_val = EIO;
            break;
    }
}