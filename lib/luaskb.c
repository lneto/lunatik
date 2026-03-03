/*
* SPDX-FileCopyrightText: (c) 2026 Ring Zero Desenvolvimento de Software LTDA
* SPDX-License-Identifier: MIT OR GPL-2.0-only
*/

/***
* Socket buffer (skb) interface.
* Provides access to Linux socket buffer fields and operations from Lua.
* @module skb
*/

#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt
#include <linux/skbuff.h>
#include <linux/if_vlan.h>
#include <linux/netdevice.h>
#include <net/checksum.h>

#include "luadata.h"
#include "luaskb.h"

LUNATIK_PRIVATECHECKER(luaskb_check, luaskb_t *,
	luaL_argcheck(L, private->skb != NULL, ix, "skb is not set");
);

/***
* Returns the length of the skb data.
* This is the Lua __len metamethod, allowing use of the # operator.
* @function __len
* @treturn integer Length in bytes.
*/
static int luaskb_len(lua_State *L)
{
	luaskb_t *lskb = luaskb_check(L, 1);
	lua_pushinteger(L, lskb->skb->len);
	return 1;
}

/***
* Returns the network interface index.
* @function ifindex
* @treturn integer Interface index, or nil if not available.
*/
static int luaskb_ifindex(lua_State *L)
{
	luaskb_t *lskb = luaskb_check(L, 1);
	struct net_device *dev = lskb->skb->dev;

	if (dev)
		lua_pushinteger(L, dev->ifindex);
	else
		lua_pushnil(L);
	return 1;
}

/***
* Returns the VLAN tag ID if present.
* @function vlan
* @treturn integer VLAN ID, or nil if no VLAN tag.
*/
static int luaskb_vlan(lua_State *L)
{
	luaskb_t *lskb = luaskb_check(L, 1);

	if (skb_vlan_tag_present(lskb->skb))
		lua_pushinteger(L, skb_vlan_tag_get_id(lskb->skb));
	else
		lua_pushnil(L);
	return 1;
}

/***
* Exports the skb buffer as a data object for direct manipulation.
* With no argument, starts at the network layer (L3).
* With "mac", includes the MAC header (L2): offset = skb_mac_offset,
* size includes skb_mac_header_len.
* @function data
* @tparam[opt] string layer Pass "mac" to include the L2 MAC header.
* @treturn data A data object pointing into the skb buffer.
* @raise Error if skb linearization fails or layer is invalid.
*/
static int luaskb_data(lua_State *L)
{
	luaskb_t *lskb = luaskb_check(L, 1);
	static const char *const layers[] = {"", "mac", NULL};
	bool mac = luaL_checkoption(L, 2, "", layers);

	luaL_argcheck(L, !mac || skb_mac_header_was_set(lskb->skb), 2, "MAC header not set");
	luaL_argcheck(L, skb_linearize(lskb->skb) == 0, 1, "skb linearize failed");

	void *ptr = mac ? (void *)skb_mac_header(lskb->skb) : (void *)lskb->skb->data;
	size_t size = mac ? skb_headlen(lskb->skb) + skb_mac_header_len(lskb->skb) : skb_headlen(lskb->skb);

	luadata_reset(lskb->data, ptr, 0, size, LUADATA_OPT_NONE);
	luaL_argcheck(L, lunatik_getregistry(L, lskb->data) == LUA_TUSERDATA, 1, "could not find data");
	return 1;
}

/***
* Resizes the skb data area.
* Expands via skb_put() or shrinks via skb_trim().
* @function resize
* @tparam integer new_size Desired size in bytes.
* @raise Error if insufficient tailroom for expansion.
*/
static int luaskb_resize(lua_State *L)
{
	luaskb_t *lskb = luaskb_check(L, 1);
	size_t new_size = (size_t)luaL_checkinteger(L, 2);
	size_t cur_size = skb_headlen(lskb->skb);

	if (new_size > cur_size) {
		size_t needed = new_size - cur_size;
		luaL_argcheck(L, skb_tailroom(lskb->skb) >= needed, 2, "insufficient tailroom");
		skb_put(lskb->skb, needed);
	}
	else if (new_size < cur_size)
		skb_trim(lskb->skb, new_size);
	return 0;
}

/***
* Computes the Internet checksum over the skb data.
* @function checksum
* @tparam[opt] integer offset Byte offset to start from (default 0).
* @tparam[opt] integer length Number of bytes to checksum (default: all from offset).
* @treturn integer Folded 16-bit checksum.
* @raise Error if offset/length is out of bounds.
*/
static int luaskb_checksum(lua_State *L)
{
	luaskb_t *lskb = luaskb_check(L, 1);
	size_t total = skb_headlen(lskb->skb);
	lua_Integer offset = luaL_optinteger(L, 2, 0);
	lua_Integer length = luaL_optinteger(L, 3, total - offset);
	luaL_argcheck(L, offset >= 0 && length > 0 && offset + length <= (lua_Integer)total, 2, "out of bounds");

	__wsum sum = csum_partial(lskb->skb->data + offset, length, 0);
	lua_pushinteger(L, csum_fold(sum));
	return 1;
}

/***
* Forwards the skb out through its ingress device (bridge TX path).
* Clones the skb, rewinds data pointer to the MAC header, and calls
* dev_queue_xmit() directly — bypassing the bridge RX path and its
* loop-detection check. The caller should return DROP for the original skb.
* @function forward
* @raise Error if skb has no device, MAC header is not set, or clone fails.
*/
static int luaskb_forward(lua_State *L)
{
	luaskb_t *lskb = luaskb_check(L, 1);
	struct net_device *dev = lskb->skb->dev;

	luaL_argcheck(L, dev != NULL, 1, "skb has no device");
	luaL_argcheck(L, skb_mac_header_was_set(lskb->skb), 1, "MAC header not set");

	struct sk_buff *nskb = skb_clone(lskb->skb, GFP_ATOMIC);
	luaL_argcheck(L, nskb != NULL, 1, "skb clone failed");

	skb_push(nskb, nskb->data - skb_mac_header(nskb));
	dev_queue_xmit(nskb);
	return 0;
}

static void luaskb_release(void *private)
{
	luaskb_t *lskb = (luaskb_t *)private;
	luadata_close(lskb->data);
}

static const luaL_Reg luaskb_lib[] = {
	{NULL, NULL}
};

static const luaL_Reg luaskb_mt[] = {
	{"__gc",    lunatik_deleteobject},
	{"__len",   luaskb_len},
	{"ifindex", luaskb_ifindex},
	{"vlan",    luaskb_vlan},
	{"data",    luaskb_data},
	{"resize",   luaskb_resize},
	{"checksum", luaskb_checksum},
	{"forward",  luaskb_forward},
	{NULL, NULL}
};

static const lunatik_class_t luaskb_class = {
	.name    = "skb",
	.methods = luaskb_mt,
	.release = luaskb_release,
	.sleep   = false,
	.shared  = true,
};

lunatik_object_t *luaskb_new(lua_State *L)
{
	lunatik_object_t *object = lunatik_createprivate(L, &luaskb_class, luaskb_t, false, false);
	luaskb_t *lskb = (luaskb_t *)object->private;
	lskb->skb = NULL;
	lunatik_cloneobject(L, object);
	lskb->data = luadata_new(L, false);
	lunatik_getobject(lskb->data);
	lunatik_register(L, -1, lskb->data);
	lua_pop(L, 1);
	return object;
}
EXPORT_SYMBOL(luaskb_new);

LUNATIK_NEWLIB(skb, luaskb_lib, &luaskb_class, NULL);

static int __init luaskb_init(void)
{
	return 0;
}

static void __exit luaskb_exit(void)
{
}

module_init(luaskb_init);
module_exit(luaskb_exit);
MODULE_LICENSE("Dual MIT/GPL");
MODULE_AUTHOR("Lourival Vieira Neto <lourival.neto@ringzero.com.br>");

