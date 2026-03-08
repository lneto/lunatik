--
-- SPDX-FileCopyrightText: (c) 2026 Ring Zero Desenvolvimento de Software LTDA
-- SPDX-License-Identifier: MIT OR GPL-2.0-only
--

local nf        = require("netfilter")
local byteorder = require("byteorder")

local UDP  = 17
local PORT = 5555

local function drop(skb)
	local pkt = skb:data()
	if pkt:getuint8(9) == UDP then
		local ihl = (pkt:getuint8(0) & 0x0F) * 4
		if byteorder.ntoh16(pkt:getuint16(ihl + 2)) == PORT then
			return nf.action.DROP
		end
	end
	return nf.action.ACCEPT
end

nf.register{
	hook     = drop,
	pf       = nf.family.INET,
	hooknum  = nf.inet_hooks.LOCAL_OUT,
	priority = nf.ip_priority.FILTER,
}

