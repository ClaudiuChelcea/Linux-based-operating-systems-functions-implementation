#include <fcntl.h>
#include <internal/syscall.h>
#include <stdarg.h>
#include <errno.h>
#include <time.h>

#define false 0
#define true 1

static inline int _call_nanosleep(struct timespec* time, struct timespec* timeLeft)
{
    nanosleep(time, timeLeft);
}

int sleep(int sec) {
    struct timespec time = {sec, 0};
    struct timespec timeLeft = { time.tv_nsec, time.tv_nsec };

    int syscall_response = _call_nanosleep(&time, &timeLeft);
    for(;;) {
        time = timeLeft;
        short int quit = false;
        if(errno == 0) {
            quit = true;
        } else if(!(syscall_response < 0)) {
            quit = true;
        }

        if(quit == true)
            goto exit;
        else {
            syscall_response = _call_nanosleep(&time, &timeLeft);
        }
    }
    exit:
        return sec;
}