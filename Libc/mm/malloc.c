// SPDX-License-Identifier: BSD-3-Clause

#include <internal/mm/mem_list.h>
#include <internal/types.h>
#include <internal/essentials.h>
#include <sys/mman.h>
#include <string.h>
#include <stdlib.h>

#define FLAGS PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS

typedef enum {
    false = 0,
    true = 1
} bool;

#define DIE_NULL(condition, msg) do {                                       \
    if (condition) {                                                        \
        return NULL;                                                        \
    }                                                                       \
} while(0);

#define DIE_VOID(condition, msg) do {                                       \
    if (condition) {                                                        \
        return;                                                             \
    }                                                                       \
} while(0);

#define DIE_INT(condition, msg) do {                                        \
    if (condition) {                                                        \
        return -1;                                                          \
    }                                                                       \
} while(0);

#define null NULL

void * malloc(size_t size) {
    void * ptr = (size) ? mmap(NULL, size, FLAGS, -1, 0) : NULL;

    DIE_NULL(ptr == null, "malloc");
    if (ptr == MAP_FAILED || (ptr != null && mem_list_add(ptr, size) < 0)) {
        munmap(ptr, size);
        ptr = NULL;
    } else {
        return ptr;
    }

    return NULL;
}

void * calloc(size_t nmemb, size_t size) {

    size_t total_size = nmemb * size;

    void * ptr = ((total_size < nmemb || total_size < size) ? NULL : malloc(total_size));
    DIE_NULL(ptr == null, "calloc");

    return (ptr) ? memset(ptr, 0, total_size) : NULL;
}

void free(void * ptr) {

    struct mem_list * item = (ptr) ? mem_list_find(ptr) : NULL;

    DIE_VOID(item == null, "free");
    size_t size = (item) ? item -> len : 0;

    if (item && mem_list_del(ptr) >= 0) {
        munmap(ptr, size);
    } else {
        return;
    }
}

void * realloc(void * ptr, size_t size) {
    if (!ptr) return malloc(size);
    else if (!size) {
        free(ptr);
        return NULL;
    }

    struct mem_list * item = mem_list_find(ptr);
    DIE_NULL(item == null, "realloc");
    if (!item) goto forced_exit;

    size_t old_size = item -> len;

    if (old_size == size)
        return ptr;

    void * new_ptr = malloc(size);
    DIE_NULL(new_ptr == null, "realloc");

    if (new_ptr) {
        memcpy(new_ptr, ptr, (old_size < size) ? old_size : size);
        free(ptr);
    }

    return new_ptr;

forced_exit:
    return NULL;
}

void * reallocarray(void * ptr, size_t nmemb, size_t size) {

    size_t total_size = nmemb * size;

    void * new_ptr = (nmemb && size) ? realloc(ptr, total_size) : NULL;
    DIE_NULL(new_ptr == null, "reallocarray");

    if (!nmemb || !size) {
        free(ptr);
    } else {
        return new_ptr;
    }

    return NULL;
}