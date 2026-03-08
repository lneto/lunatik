--
-- SPDX-FileCopyrightText: (c) 2026 Ring Zero Desenvolvimento de Software LTDA
-- SPDX-License-Identifier: MIT OR GPL-2.0-only
--
-- Regression test for GC running under spinlock in lunatik_monitor.
-- Allocates Lua tables on every packet to build GC pressure.
-- If GC finalizers run inside the spinlock, the kernel crashes with
-- "scheduling while atomic".
--

local nf        = require("netfilter")
local byteorder = require("byteorder")

local UDP  = 17
local PORT = 5570

local function gc_pressure(skb)
	local pkt = skb:data()
	if pkt:getuint8(9) == UDP then
		local ihl = (pkt:getuint8(0) & 0x0F) * 4
		if byteorder.ntoh16(pkt:getuint16(ihl + 2)) == PORT then
			local t = {}
			for i = 1, 50 do
				t[i] = {}
			end
		end
	end
	return nf.action.ACCEPT
end

nf.register{
	hook     = gc_pressure,
	pf       = nf.family.INET,
	hooknum  = nf.inet_hooks.LOCAL_OUT,
	priority = nf.ip_priority.FILTER,
}

