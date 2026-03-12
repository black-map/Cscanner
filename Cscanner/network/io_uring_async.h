#ifndef ASYNC_NETWORK_H
#define ASYNC_NETWORK_H

#include "../include/common.h"

int async_init(async_context_t *ctx, int max_events);
int async_add_socket(async_context_t *ctx, int sock_fd, uint32_t events, void *user_data);
int async_modify_socket(async_context_t *ctx, int sock_fd, uint32_t events, void *user_data);
int async_remove_socket(async_context_t *ctx, int sock_fd);
int async_wait(async_context_t *ctx, int timeout_ms);
int async_get_events(async_context_t *ctx, int index, void **user_data);
void async_cleanup(async_context_t *ctx);

#endif
