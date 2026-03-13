#ifndef LUA_SCRIPTING_H
#define LUA_SCRIPTING_H

#include "../include/common.h"

typedef struct {
    void *L;
    int initialized;
} lua_context_t;

int lua_init(lua_context_t *ctx, const char *script_path);
void lua_cleanup(lua_context_t *ctx);
int lua_execute_post_scan(lua_context_t *ctx, scan_result_t *results, int count);

#endif
