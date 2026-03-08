--
-- SPDX-FileCopyrightText: (c) 2026 Ring Zero Desenvolvimento de Software LTDA
-- SPDX-License-Identifier: MIT OR GPL-2.0-only
--
-- Regression test for lunatik spawn and thread termination.
-- The returned function is the kthread body: it polls shouldstop()
-- and yields periodically, then exits cleanly when stopped.
--

local thread = require("thread")
local linux  = require("linux")

return function()
	while not thread.shouldstop() do
		linux.schedule(100)
	end
end

