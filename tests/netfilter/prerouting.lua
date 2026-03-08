--
-- SPDX-FileCopyrightText: (c) 2026 Ring Zero Desenvolvimento de Software LTDA
-- SPDX-License-Identifier: MIT OR GPL-2.0-only
--

local nf = require("netfilter")

local ICMP     = 1
local ECHO_REQ = 8

local function drop_ping(skb)
	local pkt = skb:data()
	if pkt:getuint8(9) == ICMP then
		local ihl = (pkt:getuint8(0) & 0x0F) * 4
		if pkt:getuint8(ihl) == ECHO_REQ then
			return nf.action.DROP
		end
	end
	return nf.action.ACCEPT
end

nf.register{
	hook     = drop_ping,
	pf       = nf.family.INET,
	hooknum  = nf.inet_hooks.PRE_ROUTING,
	priority = nf.ip_priority.FILTER,
}

