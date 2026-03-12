#include "lua_scripting.h"
#include <stdio.h>
#include <string.h>

#ifdef LUA_AVAILABLE
#include <lua5.3/lua.h>
#include <lua5.3/lauxlib.h>
#include <lua5.3/lualib.h>
#else

typedef struct lua_State {
    int dummy;
} lua_State;

#endif

int lua_init(lua_context_t *ctx, const char *script_path) {
    memset(ctx, 0, sizeof(lua_context_t));
    
#ifdef LUA_AVAILABLE
    ctx->L = luaL_newstate();
    if (!ctx->L) {
        return -1;
    }
    
    luaL_openlibs(ctx->L);
    
    if (luaL_dofile(ctx->L, script_path) != LUA_OK) {
        lua_close(ctx->L);
        ctx->L = NULL;
        return -1;
    }
    
    ctx->initialized = 1;
    return 0;
#else
    if (verbose_mode) {
        fprintf(stderr, "[Lua] Lua support not compiled. Install liblua5.3-dev and rebuild.\n");
    }
    return -1;
#endif
}

void lua_cleanup(lua_context_t *ctx) {
    if (!ctx) return;
    
#ifdef LUA_AVAILABLE
    if (ctx->L) {
        lua_close(ctx->L);
    }
#endif
    ctx->initialized = 0;
}

int lua_execute_post_scan(lua_context_t *ctx, scan_result_t *results, int count) {
    if (!ctx || !ctx->initialized) {
        return -1;
    }
    
#ifdef LUA_AVAILABLE
    lua_getglobal(ctx->L, "on_scan_complete");
    if (!lua_isfunction(ctx->L, -1)) {
        lua_pop(ctx->L, 1);
        return 0;
    }
    
    lua_createtable(ctx->L, count, 0);
    
    for (int i = 0; i < count; i++) {
        lua_createtable(ctx->L, 0, 4);
        
        lua_pushinteger(ctx->L, results[i].port);
        lua_setfield(ctx->L, -2, "port");
        
        lua_pushstring(ctx->L, results[i].service);
        lua_setfield(ctx->L, -2, "service");
        
        lua_pushstring(ctx->L, results[i].version);
        lua_setfield(ctx->L, -2, "version");
        
        lua_pushinteger(ctx->L, results[i].state);
        lua_setfield(ctx->L, -2, "state");
        
        lua_rawseti(ctx->L, -2, i + 1);
    }
    
    if (lua_pcall(ctx->L, 1, 0, 0) != LUA_OK) {
        if (verbose_mode) {
            fprintf(stderr, "[Lua] Error: %s\n", lua_tostring(ctx->L, -1));
        }
        return -1;
    }
    
    return 0;
#else
    return -1;
#endif
}
