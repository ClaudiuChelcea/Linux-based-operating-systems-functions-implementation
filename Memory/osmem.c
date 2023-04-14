// SPDX-License-Identifier: BSD-3-Clause

#include "osmem.h"
#include "helpers.h"
#include <stdio.h>

#define MMAP_THRESHOLD 131072

typedef enum {
FAILURE = -1,
FALSE = 0,
TRUE = 1
}
bool;

// Strings are equal
#define STRING_EQ 0

typedef struct block_meta mini_meta;

typedef struct content {
    mini_meta* beginning;
    mini_meta* the_end;
}
full_block;

mini_meta* beginning = NULL;
mini_meta* the_end = NULL;

typedef struct meta {
    size_t size;
    int status;
    struct meta * next;
}
meta;

typedef enum {
    ALLOC_NORMAL,
    ALLOC_MAPPED
}
AllocType;

size_t align_size(size_t size) {
    return size + ((8 - size % 8) % 8);
}

meta * get_last(meta * node) {
    while (node && node -> next) {
        node = node -> next;
    }
    return node;
}

static inline int is_reusable_block(meta *block, size_t size) {
    return block && block->status == STATUS_FREE && block->size >= size;
}

meta* fd_blk(size_t size) {
    meta* aux = beginning;
    for (; aux;) {
        if (is_reusable_block(aux, size)) {
            return aux;
        }
        aux = aux->next;
    }
    return NULL;
}

void * allocate_memory(size_t size) {
    void * memory = sbrk(size);
    return (memory == (void * ) - 1) ? NULL : memory;
}

void * allocate_mapped_memory(size_t size) {
    void * memory = mmap(NULL, size, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    return (memory == MAP_FAILED) ? NULL : memory;
}

meta * create_node(void * memory, size_t size, int status) {
    meta * node = (meta * ) memory;
    node -> size = size;
    node -> status = status;
    node -> next = NULL;
    return node;
}

void * get_data_ptr(meta * node) {
    return (void * )((char * ) node + sizeof(meta));
}

meta * split_block(meta * node, size_t size) {
    size_t new_size = align_size(size);
    if (node -> size - new_size >= sizeof(meta) + 1) {
        meta * new_node = (char * ) node + sizeof(meta) + new_size;
        new_node -> size = node -> size - new_size - sizeof(meta);
        new_node -> status = STATUS_FREE;
        new_node -> next = node -> next;
        node -> size = new_size;
        node -> next = new_node;
    }
    return node;
}

void * os_malloc(size_t size) {
    if (!size) return NULL;

    size_t total_size = align_size(size) + sizeof(meta);
    bool beats_threshold = total_size < MMAP_THRESHOLD;
    AllocType alloc_type = beats_threshold ? ALLOC_NORMAL : ALLOC_MAPPED;

    switch (alloc_type) {
    case ALLOC_NORMAL: {
        if (!beginning) {
            void * memory = allocate_memory(MMAP_THRESHOLD);
            if (!memory) return NULL;
            meta * node = create_node(memory, align_size(size), STATUS_ALLOC);
            beginning = the_end = node;
            return get_data_ptr(node);
        } else {
            meta * answer = fd_blk(align_size(size));
            if (answer) {
                answer -> status = STATUS_ALLOC;
                split_block(answer, size);
                return get_data_ptr(answer);
            } else {
                the_end = get_last(beginning);
                if (the_end -> status == STATUS_FREE) {
                    size_t increment = align_size(size) - the_end -> size;
                    void * memory = allocate_memory(increment);
                    if (!memory) return NULL;
                    the_end -> size += increment;
                    the_end -> status = STATUS_ALLOC;
                    return get_data_ptr(the_end);
                } else {
                    void * memory = allocate_memory(total_size);
                    if (!memory) return NULL;
                    meta * node = create_node(memory, align_size(size), STATUS_ALLOC);
                    the_end -> next = node;
                    the_end = node;
                    return get_data_ptr(node);
                }
            }
        }
    }
    break;
    case ALLOC_MAPPED: {
        void * memory = allocate_mapped_memory(total_size);
        if (!memory) return NULL;
        meta * node = create_node(memory, align_size(size), STATUS_MAPPED);
        if (!beginning) {
            beginning = the_end = node;
        } else {
            the_end = get_last(beginning);
            the_end -> next = node;
            the_end = node;
        }
        return get_data_ptr(node);
    }
    break;
    default:
        return NULL;
    }
}

static inline bool is_allocated(meta * block) {
    return block && (block -> status == STATUS_ALLOC);
}

static inline bool is_free(meta * block) {
    return block && (block -> status == STATUS_FREE);
}

static meta * find_prev(meta * start, meta * target) {
    meta * prev = NULL;
    while (start && start != target) {
        prev = start;
        start = start -> next;
    }
    return prev;
}

static meta * find_last(meta * start) {
    while (start && start -> next) {
        start = start -> next;
    }
    return start;
}

static void merge_free_blocks(meta * block) {
    meta * prev = find_prev(beginning, block);
    if (prev && is_free(prev)) {
        prev -> size += block -> size + sizeof(meta);
        prev -> next = block -> next;
        block = prev;
    }
    if (is_free(block -> next)) {
        block -> size += block -> next -> size + sizeof(meta);
        block -> next = block -> next -> next;
    }
}

static inline void remove_block_from_list(meta *prev, meta *block) {
    if (block == beginning) {
        beginning = beginning->next;
    } else {
        prev->next = block->next;
    }
}

static inline void deallocate_block(meta *block) {
    size_t size = block->size;
    munmap(block, size + sizeof(meta));
    block->status = STATUS_FREE;
}

void free_block(meta *block) {
    size_t block_size = block->size + sizeof(meta);
    void *block_ptr = (void *)block;
    munmap(block_ptr, block_size);
}

meta* delete_block(meta* beginning, meta* block, meta* prev) {
    if (block != beginning) {
        prev->next = block->next;
        return beginning;

    } else {
        beginning = beginning->next;
        return beginning;
    }

    return NULL;
}

void os_free(void * ptr) {
    if (!ptr) return;
    meta * block = (meta * ) ptr - 1;
    meta * prev = find_prev(beginning, block);

    if (is_allocated(block)) {
        block->status = STATUS_FREE;
        merge_free_blocks(block);
        the_end = find_last(beginning);
    } else {
        beginning = delete_block(beginning, block, prev);
        free_block(block);
    }
}

static inline size_t padded_size(size_t size) {
    return size + (8 - size % 8) % 8;
}

void * os_calloc(size_t nmemb, size_t size) {
    size_t total_size = nmemb * size;
    void * memory = total_size ? os_malloc(total_size) : NULL;

    if (memory) {
        memset(memory, 0, total_size);
    }

    return memory;
}

static inline meta * create_meta(size_t size, int status, meta * next) {
    meta * new_meta = mmap(NULL, size + sizeof(meta), PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (new_meta == MAP_FAILED) {
        return NULL;
    }
    new_meta->size = size;
    new_meta->status = status;
    new_meta->next = next;
    return new_meta;
}

static inline meta * insert_meta_after(meta * beginning, meta * prev_meta, meta * new_meta) {
    if (!beginning || !prev_meta || !new_meta) {
        return NULL;
    }
    new_meta->next = prev_meta->next;
    prev_meta->next = new_meta;
    return beginning;
}

static inline meta * allocate_new_meta(size_t memory_size, size_t new_size) {
    meta * new_meta = (meta *)mmap(NULL, memory_size, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (new_meta == MAP_FAILED) {
        return NULL;
    }
    new_meta->size = new_size;
    new_meta->status = STATUS_ALLOC;
    new_meta->next = NULL;
    return new_meta;
}

static inline meta * insert_meta_at_end(meta * beginning, meta * end, meta * new_meta) {
    return beginning == NULL ? new_meta : (end->next = new_meta, end = new_meta, beginning);
}

void * os_realloc(void * ptr, size_t size) {
    if (ptr == NULL) {
        return os_malloc(size);
    }
    if (size == 0) {
        os_free(ptr);
        return NULL;
    }

    size_t new_size = size + (8 - size % 8) % 8;
    if (new_size == 0) {
        return NULL;
    }

    meta * block_meta = (meta * ) ptr - 1;

    switch (block_meta -> status) {
    case STATUS_ALLOC:
    case STATUS_FREE:
        if (new_size <= block_meta -> size) {
            size_t leftover_size = block_meta -> size - new_size;
            if (leftover_size >= sizeof(meta) + 1) {
                meta * leftover_meta = (meta * )(((char * ) block_meta) + new_size + sizeof(meta));
                leftover_meta -> size = leftover_size - sizeof(meta);
                leftover_meta -> status = STATUS_FREE;
                leftover_meta -> next = block_meta -> next;
                block_meta -> size = new_size;
                block_meta -> next = leftover_meta;
            }
            return ptr;
        } else {
            meta * next_meta = block_meta -> next;
            if (next_meta && next_meta -> status == STATUS_FREE && block_meta -> size + sizeof(meta) + next_meta -> size >= new_size) {
                block_meta -> size = block_meta -> size + sizeof(meta) + next_meta -> size;
                block_meta -> next = next_meta -> next;
                return ptr;
            }
        }
        break;
    case STATUS_MAPPED:
        if (new_size <= MMAP_THRESHOLD) {
            void *new_memory = sbrk(MMAP_THRESHOLD);
            if (new_memory != (void *)-1) {
                meta *new_meta = create_meta(new_size, STATUS_ALLOC, block_meta->next);
                if (!new_meta) {
                    return NULL;
                }
                beginning = insert_meta_after(beginning, block_meta, new_meta);
                memcpy((char *)new_memory + sizeof(meta), ptr, block_meta->size);
                munmap(block_meta, block_meta->size + sizeof(meta));
                return (char *)new_memory + sizeof(meta);
            }
        }
        break;
    }

    void * new_ptr = NULL;

    if (new_size < MMAP_THRESHOLD) {
        meta * new_meta = fd_blk(new_size);
        if (new_meta != NULL) {
            new_meta -> status = STATUS_ALLOC;
            if (new_meta -> size - new_size >= sizeof(meta) + 1) {
                meta * leftover_meta = (meta * )(((char * ) new_meta) + new_size + sizeof(meta));
                leftover_meta -> size = new_meta -> size - new_size - sizeof(meta);
                leftover_meta -> status = STATUS_FREE;
                leftover_meta -> next = new_meta -> next;
                new_meta -> size = new_size;
                new_meta -> next = leftover_meta;
            }
            new_ptr = (void * )(new_meta + 1);
        }
    }
    if (new_ptr == NULL) {
        size_t memory_size = new_size + sizeof(meta) + (8 - new_size % 8) % 8;
        meta * new_meta = allocate_new_meta(memory_size, new_size);
        if (new_meta) {
            beginning = insert_meta_at_end(beginning, the_end, new_meta);
            new_ptr = (void *)(new_meta + 1);
        }
    }

    if (new_ptr != NULL) {
        memcpy(new_ptr, ptr, block_meta -> size);
        os_free(ptr);
    }
    return new_ptr;
}