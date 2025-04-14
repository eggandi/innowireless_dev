#include "relay-internal-system.h"
#include "relay-extern-defines.h"

#ifndef _D_HEADER_RELAY_INNO_BUFFER
#define _D_HEADER_RELAY_INNO_BUFFER

#define _GNU_SOURCE
#define RELAY_INNO_DEFAULT_BUFFER_ARRAY_SIZE 128

struct relay_inno_buffer_status_t {
    int buffer_size_max;
    int buffer_size_now;
    bool buffer_pop_flag;
    bool buffer_push_flag;
};

struct relay_inno_default_buffer_array_t {
    void *data;
    size_t size;
    int id;

    struct relay_inno_default_buffer_array_t *next;
    struct relay_inno_default_buffer_array_t *prev;
};

struct relay_inno_buffer_t {
    struct relay_inno_buffer_status_t status;
    struct relay_inno_default_buffer_array_t *front;
    struct relay_inno_default_buffer_array_t *array;
};

struct buffer_array_setup_t {
    int buffer_size;

    struct relay_inno_buffer_t *buffer_ptr;
};

#endif //?_D_HEADER_RELAY_INNO_BUFFER

extern void *RELAY_INNO_Buffer_Array_Init(struct buffer_array_setup_t *setup);
extern int RELAY_INNO_Buffer_Array_Push(void *data, size_t size, int *id, struct relay_inno_buffer_t *user_buffer);
extern int RELAY_INNO_Buffer_Array_Pop(struct relay_inno_default_buffer_array_t *out_buffer, struct relay_inno_buffer_t *user_buffer);
