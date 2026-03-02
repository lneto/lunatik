--
-- SPDX-FileCopyrightText: (c) 2026 Ring Zero Desenvolvimento de Software LTDA
-- SPDX-License-Identifier: MIT OR GPL-2.0-only
--

--- UBUS client over UNIX domain socket (kernel)
-- @module ubus.client

local socket   = require("socket")
local protocol = require("ubus.protocol")
local json     = require("ubus.json")

local client = {}
client.__index = client

local DEFAULT_PATH = "/var/run/ubus/ubus.sock"
local HEADER_LEN   = 8

--- Read exactly n bytes from socket
-- @tparam userdata sock Socket object
-- @tparam number n Number of bytes to read
-- @treturn string|nil Data or nil on error
-- @treturn string|nil Error message
local function recvn(sock, n)
	local buf = ""
	while #buf < n do
		local chunk, err = sock:receive(n - #buf)
		if not chunk then
			return nil, err
		end
		buf = buf .. chunk
	end
	return buf
end

--- Connect to UBUS daemon
-- @tparam[opt] string path Socket path (default: /var/run/ubus/ubus.sock)
-- @treturn table|nil Client context or nil on error
-- @treturn string|nil Error message
function client.connect(path)
	path = path or DEFAULT_PATH

	local sock, err = socket.new(socket.af.UNIX, socket.sock.STREAM, 0)
	if not sock then
		return nil, err
	end

	local ok, err = sock:connect(path)
	if not ok then
		return nil, err
	end

	local ctx = setmetatable({ sock = sock, seq = 0, peer = 0 }, client)

	-- Wait for HELLO
	local msg, err = ctx:recv_msg()
	if not msg then
		sock:close()
		return nil, "no hello: " .. tostring(err)
	end

	if msg.hdr.type ~= protocol.MSG_HELLO then
		sock:close()
		return nil, "expected HELLO, got type " .. msg.hdr.type
	end

	ctx.peer = msg.hdr.peer
	return ctx
end

--- Send a UBUS message
-- @tparam number msgtype Message type
-- @tparam table attrs Attributes table
-- @treturn number|nil Sequence number or nil on error
-- @treturn string|nil Error message
function client:send_msg(msgtype, attrs)
	self.seq = (self.seq + 1) % 65536

	local header  = protocol.encode_header(msgtype, self.seq, self.peer)
	local payload = attrs and protocol.encode_attrs(attrs) or ""
	local ok, err = self.sock:send(header .. payload)
	if not ok then
		return nil, err
	end

	return self.seq
end

--- Receive a UBUS message
-- @treturn table|nil {hdr, attrs} or nil on error
-- @treturn string|nil Error message
function client:recv_msg()
	local header, err = recvn(self.sock, HEADER_LEN)
	if not header then
		return nil, err
	end

	local hdr = protocol.decode_header(header)

	local payload = self.sock:receive(65536) or ""
	local attrs   = #payload > 0 and protocol.decode_attrs(payload) or {}

	return { hdr = hdr, attrs = attrs }
end

--- Lookup an object by path
-- @tparam string path Object path (e.g. "system")
-- @treturn number|nil Object ID or nil on error
-- @treturn string|nil Error message
function client:lookup(path)
	local seq, err = self:send_msg(protocol.MSG_LOOKUP, {
		[protocol.ATTR_OBJPATH] = path
	})
	if not seq then
		return nil, err
	end

	local msg, err = self:recv_msg()
	if not msg then
		return nil, err
	end

	if msg.hdr.type == protocol.MSG_DATA then
		return msg.attrs[protocol.ATTR_OBJID]
	elseif msg.hdr.type == protocol.MSG_STATUS then
		return nil, "status=" .. (msg.attrs[protocol.ATTR_STATUS] or -1)
	else
		return nil, "unexpected reply type " .. msg.hdr.type
	end
end

--- Invoke a method on an object
-- @tparam number objid Object ID (from lookup)
-- @tparam string method Method name
-- @tparam[opt] table args Method arguments
-- @treturn table|nil Result or nil on error
-- @treturn string|nil Error message
function client:invoke(objid, method, args)
	local attrs = {
		[protocol.ATTR_OBJID]  = objid,
		[protocol.ATTR_METHOD] = method,
	}
	if args then
		attrs[protocol.ATTR_DATA] = json.encode(args)
	end

	local seq, err = self:send_msg(protocol.MSG_INVOKE, attrs)
	if not seq then
		return nil, err
	end

	local msg, err = self:recv_msg()
	if not msg then
		return nil, err
	end

	if msg.hdr.type == protocol.MSG_DATA then
		local data = msg.attrs[protocol.ATTR_DATA]
		return data and json.decode(data) or {}
	elseif msg.hdr.type == protocol.MSG_STATUS then
		return nil, "status=" .. (msg.attrs[protocol.ATTR_STATUS] or -1)
	else
		return nil, "unexpected reply type " .. msg.hdr.type
	end
end

--- Close the connection
function client:close()
	if self.sock then
		self.sock:close()
		self.sock = nil
	end
end

return client
