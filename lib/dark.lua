--
-- SPDX-FileCopyrightText: (c) 2026 Ring Zero Desenvolvimento de Software LTDA
-- SPDX-License-Identifier: MIT OR GPL-2.0-only
--

--- Darken: encrypted Lua script support.
-- Provides encryption of Lua scripts using AEAD (AES-256-GCM by default)
-- with HKDF time-based key derivation, and decryption via the C `darken`
-- module.
-- @module dark

local darken = require("darken")
local aead  = require("crypto.aead")
local data  = require("data")
local hkdf  = require("crypto.hkdf")
local linux = require("linux")
local rng   = require("crypto_rng")
local util  = require("util")
local lunatik = require("lunatik")
local env   = lunatik._ENV

local dark = {}

--- Decrypts and executes an encrypted Lua script.
-- Delegates to the C `darken.run` function, which looks up the key
-- from `_ENV["light"]`.
-- @function run
-- @tparam string ciphertext The encrypted script with appended GCM tag.
-- @tparam string nonce The 12-byte nonce used during encryption.
-- @tparam[opt="gcm(aes)"] string algo The AEAD algorithm name.
-- @return ... Any values returned by the executed script.
dark.run = darken.run

--- Encrypts a Lua script using AEAD with HKDF-derived key.
-- Derives an ephemeral key from `secret_hex` using HKDF-SHA256 with
-- a time-step salt (30-second window). Generates a random 12-byte nonce.
-- @function encrypt
-- @tparam string plaintext_hex Hex-encoded Lua script source.
-- @tparam string secret_hex Hex-encoded 32-byte shared secret.
-- @tparam[opt="gcm(aes)"] string algo The AEAD algorithm name.
-- @treturn string Tab-separated `nonce_hex \t ct_hex`.
function dark.encrypt(plaintext_hex, secret_hex, algo)
	algo = algo or "gcm(aes)"
	local secret = util.hex2bin(secret_hex)
	local time_step = linux.time() // 30000000000
	local salt = string.pack(">I8", time_step)

	local h <close> = hkdf.new("sha256")
	local key = h:hkdf(salt, secret, "darken", 32)

	local r <close> = rng.new("stdrng")
	local nonce = r:getbytes(12)

	local c <close> = aead.new(algo)
	c:setkey(key)
	c:setauthsize(16)
	local ct = c:encrypt(nonce, (util.hex2bin(plaintext_hex)))

	return util.bin2hex(nonce) .. "\t" .. util.bin2hex(ct)
end

--- Loads a decryption key into `_ENV["light"]`.
-- Converts the hex-encoded key to binary and stores it as a `data`
-- object in `lunatik._ENV["light"]`, where the C `darken` module
-- looks it up during decryption.
-- @function loadkey
-- @tparam string key_hex Hex-encoded 32-byte AES key.
function dark.loadkey(key_hex)
	local key = util.hex2bin(key_hex)
	local d = data.new(#key)
	d:setstring(0, key)
	env["light"] = d
end

return dark
