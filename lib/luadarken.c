/*
* SPDX-FileCopyrightText: (c) 2026 Ring Zero Desenvolvimento de Software LTDA
* SPDX-License-Identifier: MIT OR GPL-2.0-only
*/

/***
* Encrypted Lua script loader.
*
* This module provides a single function to decrypt and execute
* encrypted Lua scripts using authenticated encryption (AEAD).
* The key is looked up from `lunatik._ENV["light"]` (32 bytes).
* The default algorithm is AES-256-GCM.
*
* @module darken
*/

#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <crypto/aead.h>
#include <linux/err.h>
#include <linux/scatterlist.h>

#include <lunatik.h>

#include "luadata.h"
#include "luarcu.h"

#define LUADARKEN_KEYSIZE	32
#define LUADARKEN_NONCESIZE	12
#define LUADARKEN_AUTHSIZE	16
#define LUADARKEN_ALGO	"gcm(aes)"

/***
* Decrypts and executes an encrypted Lua script.
*
* The key is looked up from `lunatik._ENV["light"]` (32 bytes).
* The nonce and optional algorithm are passed as arguments.
*
* @function run
* @tparam string ciphertext The encrypted script with appended GCM tag.
* @tparam string nonce The 12-byte nonce used during encryption.
* @tparam[opt="gcm(aes)"] string algo The AEAD algorithm name.
* @return ... Any values returned by the executed script.
* @raise Error on decryption failure, authentication failure, or Lua errors.
* @usage
*   local darken = require("darken")
*   local util = require("util")
*   return darken.run(util.hex2bin("..."), util.hex2bin("..."))
*/
static int luadarken_run(lua_State *L)
{
	size_t len;
	const char *ct = luaL_checklstring(L, 1, &len);
	size_t noncelen;
	const char *nonce = luaL_checklstring(L, 2, &noncelen);
	const char *algo = luaL_optstring(L, 3, LUADARKEN_ALGO);
	int top = lua_gettop(L);
	u8 key[LUADARKEN_KEYSIZE];
	int ret;

	luaL_argcheck(L, len > LUADARKEN_AUTHSIZE, 1, "ciphertext too short");
	luaL_argcheck(L, noncelen == LUADARKEN_NONCESIZE, 2, "nonce must be 12 bytes");

	/* look up key from lunatik._ENV["light"] */
	lunatik_object_t *obj = luarcu_gettable(lunatik_env, "light", 5);
	if (obj == NULL)
		return luaL_error(L, "no key in _ENV['light']");

	ssize_t keysize = luadata_getbytes(obj, key, 0, LUADARKEN_KEYSIZE);
	lunatik_putobject(obj);
	if (keysize < 0)
		return luaL_error(L, "invalid key in _ENV['light']");

	struct crypto_aead *tfm = crypto_alloc_aead(algo, 0, 0);
	if (IS_ERR(tfm))
		return luaL_error(L, "failed to allocate aead transform (%ld)",
				  PTR_ERR(tfm));

	ret = crypto_aead_setkey(tfm, key, LUADARKEN_KEYSIZE);
	if (ret < 0) {
		crypto_free_aead(tfm);
		return luaL_error(L, "failed to set key (%d)", ret);
	}

	ret = crypto_aead_setauthsize(tfm, LUADARKEN_AUTHSIZE);
	if (ret < 0) {
		crypto_free_aead(tfm);
		return luaL_error(L, "failed to set authsize (%d)", ret);
	}

	char *buf = (char *)lunatik_malloc(L, len);
	if (buf == NULL) {
		crypto_free_aead(tfm);
		return luaL_error(L, "not enough memory");
	}
	memcpy(buf, ct, len);

	struct aead_request *req = aead_request_alloc(tfm, lunatik_gfp(lunatik_toruntime(L)));
	if (req == NULL) {
		lunatik_free(buf);
		crypto_free_aead(tfm);
		return luaL_error(L, "not enough memory");
	}

	struct scatterlist sg;
	sg_init_one(&sg, buf, len);
	aead_request_set_ad(req, 0);
	aead_request_set_crypt(req, &sg, &sg, len, (u8 *)nonce);
	aead_request_set_callback(req, 0, NULL, NULL);

	ret = crypto_aead_decrypt(req);

	aead_request_free(req);
	crypto_free_aead(tfm);

	if (ret < 0) {
		lunatik_free(buf);
		return luaL_error(L, "decryption failed (%d)", ret);
	}

	/* plaintext is in buf[0 .. len - LUADARKEN_AUTHSIZE) */
	ret = luaL_loadbuffer(L, buf, len - LUADARKEN_AUTHSIZE, "=darkened");
	lunatik_free(buf);

	if (ret != LUA_OK)
		return lua_error(L);

	lua_call(L, 0, LUA_MULTRET);
	return lua_gettop(L) - top;
}

static const luaL_Reg luadarken_lib[] = {
	{"run", luadarken_run},
	{NULL, NULL}
};

LUNATIK_NEWLIB(darken, luadarken_lib, NULL, NULL);

static int __init luadarken_init(void)
{
	return 0;
}

static void __exit luadarken_exit(void)
{
}

module_init(luadarken_init);
module_exit(luadarken_exit);
MODULE_LICENSE("Dual MIT/GPL");
MODULE_AUTHOR("Lourival Vieira Neto <lourival.neto@ringzero.com.br>");
MODULE_DESCRIPTION("Lunatik encrypted Lua script loader (AES-256-GCM)");
