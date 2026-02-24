/*
* SPDX-FileCopyrightText: (c) 2026 Ring Zero Desenvolvimento de Software LTDA
* SPDX-License-Identifier: MIT OR GPL-2.0-only
*/

#include "lunatik.h"

void lunatik_checkvalue(lua_State *L, int ix, lunatik_value_t *value)
{
	value->type = lua_type(L, ix);
	switch (value->type) {
	case LUA_TNIL:
		break;
	case LUA_TBOOLEAN:
		value->boolean = lua_toboolean(L, ix);
		break;
	case LUA_TNUMBER:
		value->integer = lua_tointeger(L, ix);
		break;
	case LUA_TUSERDATA:
		value->object = lunatik_checkobject(L, ix);
		break;
	default:
		luaL_argerror(L, ix, "unsupported type");
		break;
	}
}
EXPORT_SYMBOL(lunatik_checkvalue);

void lunatik_pushvalue(lua_State *L, lunatik_value_t *value)
{
	switch (value->type) {
	case LUA_TNIL:
		lua_pushnil(L);
		break;
	case LUA_TBOOLEAN:
		lua_pushboolean(L, value->boolean);
		break;
	case LUA_TNUMBER:
		lua_pushinteger(L, value->integer);
		break;
	case LUA_TUSERDATA:
		lunatik_cloneobject(L, value->object);
		break;
	}
}
EXPORT_SYMBOL(lunatik_pushvalue);

