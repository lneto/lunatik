--
-- SPDX-FileCopyrightText: (c) 2026 Ring Zero Desenvolvimento de Software LTDA
-- SPDX-License-Identifier: MIT OR GPL-2.0-only
--
-- Registers two hooks to verify the mark filter:
--   hook_zero (mark=0): fires for unmarked packets — drops UDP to PORT_ZERO
--   hook_one  (mark=1): skipped for unmarked packets — drops UDP to PORT_ONE
--

local nf        = require("netfilter")
local byteorder = require("byteorder")

local UDP       = 17
local PORT_ZERO = 5560
local PORT_ONE  = 5561

local function drop_port(port)
	return function(skb)
		local pkt = skb:data()
		if pkt:getuint8(9) == UDP then
			local ihl = (pkt:getuint8(0) & 0x0F) * 4
			if byteorder.ntoh16(pkt:getuint16(ihl + 2)) == port then
				return nf.action.DROP
			end
		end
		return nf.action.ACCEPT
	end
end

nf.register{
	hook     = drop_port(PORT_ZERO),
	pf       = nf.family.INET,
	hooknum  = nf.inet_hooks.LOCAL_OUT,
	priority = nf.ip_priority.FILTER,
	mark     = 0,
}

nf.register{
	hook     = drop_port(PORT_ONE),
	pf       = nf.family.INET,
	hooknum  = nf.inet_hooks.LOCAL_OUT,
	priority = nf.ip_priority.FILTER,
	mark     = 1,
}

