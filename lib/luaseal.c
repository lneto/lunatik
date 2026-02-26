/*
* SPDX-FileCopyrightText: (c) 2026 Ring Zero Desenvolvimento de Software LTDA
* SPDX-License-Identifier: MIT OR GPL-2.0-only
*/

/***
* Encrypted Lua script loader using AES-256-GCM.
*
* This module provides a single function to decrypt and execute
* encrypted Lua scripts. Scripts are encrypted with AES-256-GCM
* (authenticated encryption) using a runtime-configured key stored
* in `lunatik._ENV`.
*
* @module seal
*/

#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <crypto/aead.h>
#include <linux/err.h>
#include <linux/scatterlist.h>

#include <lunatik.h>

#include "luarcu.h"

#define LUASEAL_KEYSIZE	32
#define LUASEAL_NONCESIZE	12
#define LUASEAL_BLOBSIZE	(LUASEAL_KEYSIZE + LUASEAL_NONCESIZE)
#define LUASEAL_AUTHSIZE	16
#define LUASEAL_ALGO	"gcm(aes)"

/* mirrors luadata_t from luadata.c */
typedef struct luaseal_data_s {
	void *ptr;
	ptrdiff_t offset;
	size_t size;
	uint8_t opt;
} luaseal_data_t;

/***
* Decrypts and executes an encrypted Lua script.
*
* The key and nonce are looked up from `lunatik._ENV[name]` where
* `name` is the script name passed as the second argument. The _ENV
* entry must be a 44-byte `data` object: key (32 bytes) + nonce (12 bytes).
*
* @function run
* @tparam string ciphertext The encrypted script with appended GCM tag.
* @tparam string name Script name used to look up the key blob in _ENV.
* @return ... Any values returned by the executed script.
* @raise Error on decryption failure, authentication failure, or Lua errors.
* @usage
*   local seal = require("seal")
*   local util = require("util")
*   return seal.run(util.hex2bin("..."), "myscript")
*/
static int luaseal_run(lua_State *L)
{
	size_t len;
	const char *ct = luaL_checklstring(L, 1, &len);
	size_t namelen;
	const char *name = luaL_checklstring(L, 2, &namelen);
	int top = lua_gettop(L);
	lunatik_object_t *obj;
	luaseal_data_t *data;
	struct crypto_aead *tfm;
	struct aead_request *req;
	struct scatterlist sg;
	char *buf;
	u8 key[LUASEAL_KEYSIZE];
	u8 iv[LUASEAL_NONCESIZE];
	int ret;

	luaL_argcheck(L, len > LUASEAL_AUTHSIZE, 1, "ciphertext too short");

	/* look up key+nonce blob from lunatik._ENV[name] */
	obj = luarcu_gettable(lunatik_env, name, namelen);
	if (obj == NULL)
		return luaL_error(L, "no key blob in _ENV['%s']", name);

	lunatik_lock(obj);
	data = (luaseal_data_t *)obj->private;
	if (data == NULL || data->size < LUASEAL_BLOBSIZE) {
		lunatik_unlock(obj);
		lunatik_putobject(obj);
		return luaL_error(L, "invalid key blob in _ENV['%s']", name);
	}
	memcpy(key, (u8 *)data->ptr + data->offset, LUASEAL_KEYSIZE);
	memcpy(iv, (u8 *)data->ptr + data->offset + LUASEAL_KEYSIZE, LUASEAL_NONCESIZE);
	lunatik_unlock(obj);
	lunatik_putobject(obj);

	tfm = crypto_alloc_aead(LUASEAL_ALGO, 0, 0);
	if (IS_ERR(tfm))
		return luaL_error(L, "failed to allocate aead transform (%ld)",
				  PTR_ERR(tfm));

	ret = crypto_aead_setkey(tfm, key, LUASEAL_KEYSIZE);
	if (ret < 0) {
		crypto_free_aead(tfm);
		return luaL_error(L, "failed to set key (%d)", ret);
	}

	ret = crypto_aead_setauthsize(tfm, LUASEAL_AUTHSIZE);
	if (ret < 0) {
		crypto_free_aead(tfm);
		return luaL_error(L, "failed to set authsize (%d)", ret);
	}

	buf = (char *)lunatik_malloc(L, len);
	if (buf == NULL) {
		crypto_free_aead(tfm);
		return luaL_error(L, "not enough memory");
	}
	memcpy(buf, ct, len);

	req = aead_request_alloc(tfm, lunatik_gfp(lunatik_toruntime(L)));
	if (req == NULL) {
		lunatik_free(buf);
		crypto_free_aead(tfm);
		return luaL_error(L, "not enough memory");
	}

	sg_init_one(&sg, buf, len);
	aead_request_set_ad(req, 0);
	aead_request_set_crypt(req, &sg, &sg, len, iv);
	aead_request_set_callback(req, 0, NULL, NULL);

	ret = crypto_aead_decrypt(req);

	aead_request_free(req);
	crypto_free_aead(tfm);

	if (ret < 0) {
		lunatik_free(buf);
		return luaL_error(L, "decryption failed (%d)", ret);
	}

	/* plaintext is in buf[0 .. len - LUASEAL_AUTHSIZE) */
	ret = luaL_loadbuffer(L, buf, len - LUASEAL_AUTHSIZE, "=sealed");
	lunatik_free(buf);

	if (ret != LUA_OK)
		return lua_error(L);

	lua_call(L, 0, LUA_MULTRET);
	return lua_gettop(L) - top;
}

static const luaL_Reg luaseal_lib[] = {
	{"run", luaseal_run},
	{NULL, NULL}
};

LUNATIK_NEWLIB(seal, luaseal_lib, NULL, NULL);

static int __init luaseal_init(void)
{
	return 0;
}

static void __exit luaseal_exit(void)
{
}

module_init(luaseal_init);
module_exit(luaseal_exit);
MODULE_LICENSE("Dual MIT/GPL");
MODULE_AUTHOR("Lourival Vieira Neto <lourival.neto@ring-0.io>");
MODULE_DESCRIPTION("Lunatik encrypted Lua script loader (AES-256-GCM)");

