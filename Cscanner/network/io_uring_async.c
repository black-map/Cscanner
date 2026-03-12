#include "io_uring_async.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>

typedef struct {
    int sock_fd;
    void *user_data;
} socket_context_t;

static socket_context_t *socket_contexts[EPOLL_MAX_EVENTS];
static int context_count = 0;

int async_init(async_context_t *ctx, int max_events) {
    ctx->max_events = max_events;
    ctx->events = malloc(sizeof(struct epoll_event) * max_events);
    if (!ctx->events) {
        return -1;
    }
    
    ctx->epoll_fd = epoll_create1(0);
    if (ctx->epoll_fd < 0) {
        free(ctx->events);
        ctx->events = NULL;
        return -1;
    }
    
    ctx->initialized = 1;
    ctx->use_epoll = 1;
    return 0;
}

int async_add_socket(async_context_t *ctx, int sock_fd, uint32_t events, void *user_data) {
    if (!ctx || !ctx->initialized) return -1;
    
    struct epoll_event ev;
    ev.events = events;
    ev.data.fd = sock_fd;
    
    socket_context_t *sc = malloc(sizeof(socket_context_t));
    if (!sc) return -1;
    sc->sock_fd = sock_fd;
    sc->user_data = user_data;
    
    if (epoll_ctl(ctx->epoll_fd, EPOLL_CTL_ADD, sock_fd, &ev) < 0) {
        free(sc);
        return -1;
    }
    
    socket_contexts[context_count++] = sc;
    return 0;
}

int async_modify_socket(async_context_t *ctx, int sock_fd, uint32_t events, void *user_data) {
    if (!ctx || !ctx->initialized) return -1;
    
    struct epoll_event ev;
    ev.events = events;
    ev.data.fd = sock_fd;
    
    return epoll_ctl(ctx->epoll_fd, EPOLL_CTL_MOD, sock_fd, &ev);
}

int async_remove_socket(async_context_t *ctx, int sock_fd) {
    if (!ctx || !ctx->initialized) return -1;
    
    return epoll_ctl(ctx->epoll_fd, EPOLL_CTL_DEL, sock_fd, NULL);
}

int async_wait(async_context_t *ctx, int timeout_ms) {
    if (!ctx || !ctx->initialized) return 0;
    
    return epoll_wait(ctx->epoll_fd, ctx->events, ctx->max_events, timeout_ms);
}

int async_get_events(async_context_t *ctx, int index, void **user_data) {
    if (!ctx || index < 0 || index >= ctx->max_events) return -1;
    
    int fd = ctx->events[index].data.fd;
    *user_data = NULL;
    
    for (int i = 0; i < context_count; i++) {
        if (socket_contexts[i] && socket_contexts[i]->sock_fd == fd) {
            *user_data = socket_contexts[i]->user_data;
            break;
        }
    }
    
    return ctx->events[index].events;
}

void async_cleanup(async_context_t *ctx) {
    if (!ctx) return;
    
    if (ctx->epoll_fd >= 0) {
        close(ctx->epoll_fd);
    }
    if (ctx->events) {
        free(ctx->events);
    }
    
    for (int i = 0; i < context_count; i++) {
        if (socket_contexts[i]) {
            free(socket_contexts[i]);
        }
    }
    context_count = 0;
    
    ctx->initialized = 0;
}
