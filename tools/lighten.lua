#!/usr/bin/lua5.4
--
-- SPDX-FileCopyrightText: (c) 2026 Ring Zero Desenvolvimento de Software LTDA
-- SPDX-License-Identifier: MIT OR GPL-2.0-only
--

-- lighten key generator
-- Usage: lighten <secret_hex> [path]
-- Generates lighten.lua (kernel script)

local function hex2bin(hex)
	return (hex:gsub("..", function(cc) return string.char(tonumber(cc, 16)) end))
end

local function bin2hex(bin)
	return (bin:gsub(".", function(c) return string.format("%.2x", string.byte(c)) end))
end

local function hmac_sha256(key, data)
	local df = os.tmpname()
	local f = io.open(df, "wb"); f:write(data); f:close()
	local cmd = string.format(
		"openssl dgst -sha256 -mac HMAC -macopt hexkey:%s -binary %s",
		bin2hex(key), df)
	local p = io.popen(cmd, "r")
	local result = p:read("a")
	p:close()
	os.remove(df)
	return result
end

local function hkdf(salt, ikm, info, length)
	local prk = hmac_sha256(salt, ikm)
	local okm = hmac_sha256(prk, info .. "\x01")
	return okm:sub(1, length)
end

local secret_hex = arg[1]
if not secret_hex then
	io.stderr:write("usage: lighten <secret_hex> [path]\n")
	os.exit(false)
end

local secret = hex2bin(secret_hex)
local time_step = os.time() // 30
local salt = string.pack(">I8", time_step)
local key = hkdf(salt, secret, "darken", 32)
local key_hex = bin2hex(key)

local lighten_path = arg[2] or "light.lua"
local f <close> = assert(io.open(lighten_path, "w"))
f:write(string.format(
	"local dark = require(\"dark\")\n" ..
	"dark.loadkey(\"%s\")\n",
	key_hex))

print("Lighten: " .. lighten_path)
