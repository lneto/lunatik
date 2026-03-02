--
-- SPDX-FileCopyrightText: (c) 2026 Ring Zero Desenvolvimento de Software LTDA
-- SPDX-License-Identifier: MIT OR GPL-2.0-only
--

--- UBUS protocol constants and encoding/decoding
-- @module ubus.protocol

local protocol = {}

-- Message types
protocol.MSG_HELLO         = 0
protocol.MSG_STATUS        = 1
protocol.MSG_DATA          = 2
protocol.MSG_PING          = 3
protocol.MSG_LOOKUP        = 4
protocol.MSG_INVOKE        = 5
protocol.MSG_ADD_OBJECT    = 6
protocol.MSG_REMOVE_OBJECT = 7
protocol.MSG_SUBSCRIBE     = 8
protocol.MSG_UNSUBSCRIBE   = 9
protocol.MSG_NOTIFY        = 10
protocol.MSG_MONITOR       = 11

-- Message attributes
protocol.ATTR_UNSPEC       = 0
protocol.ATTR_STATUS       = 1
protocol.ATTR_OBJPATH      = 2
protocol.ATTR_OBJID        = 3
protocol.ATTR_METHOD       = 4
protocol.ATTR_OBJTYPE      = 5
protocol.ATTR_SIGNATURE    = 6
protocol.ATTR_DATA         = 7
protocol.ATTR_TARGET       = 8
protocol.ATTR_ACTIVE       = 9
protocol.ATTR_NO_REPLY     = 10
protocol.ATTR_SUBSCRIBERS  = 11
protocol.ATTR_USER         = 12
protocol.ATTR_GROUP        = 13

-- Status codes
protocol.STATUS_OK                = 0
protocol.STATUS_INVALID_COMMAND   = 1
protocol.STATUS_INVALID_ARGUMENT  = 2
protocol.STATUS_METHOD_NOT_FOUND  = 3
protocol.STATUS_NOT_FOUND         = 4
protocol.STATUS_NO_DATA           = 5
protocol.STATUS_PERMISSION_DENIED = 6
protocol.STATUS_TIMEOUT           = 7
protocol.STATUS_NOT_SUPPORTED     = 8
protocol.STATUS_UNKNOWN_ERROR     = 9
protocol.STATUS_CONNECTION_FAILED = 10
protocol.STATUS_NO_MEMORY         = 11
protocol.STATUS_PARSE_ERROR       = 12
protocol.STATUS_SYSTEM_ERROR      = 13

--- Encode message header (8 bytes)
-- struct ubus_msghdr: version(1) type(1) seq(2 BE) peer(4 BE)
-- @tparam number msgtype Message type
-- @tparam number seq Sequence number (0-65535)
-- @tparam number peer Peer ID
-- @treturn string 8-byte header
function protocol.encode_header(msgtype, seq, peer)
	return string.pack(">I1I1I2I4", 0, msgtype, seq, peer)
end

--- Decode message header
-- @tparam string data 8-byte header
-- @treturn table {version, type, seq, peer}
function protocol.decode_header(data)
	local version, msgtype, seq, peer = string.unpack(">I1I1I2I4", data)
	return { version = version, type = msgtype, seq = seq, peer = peer }
end

--- Encode UBUS attributes as blob_attr TLV
-- Format per attribute: type(2 BE) + len(2 BE) + data (4-byte aligned)
-- @tparam table attrs {attr_type = value, ...}
-- @treturn string Encoded TLV data
function protocol.encode_attrs(attrs)
	local parts = {}

	for attr_type, value in pairs(attrs) do
		local data
		local vtype = type(value)

		if vtype == "number" then
			data = string.pack(">I4", value)
		elseif vtype == "string" then
			data = value .. "\0"
		else
			error("unsupported attr type: " .. vtype)
		end

		-- Pad to 4-byte boundary
		local pad = (4 - (#data % 4)) % 4
		data = data .. string.rep("\0", pad)

		local len = 4 + #data
		table.insert(parts, string.pack(">I2I2", attr_type, len) .. data)
	end

	return table.concat(parts)
end

--- Decode UBUS attributes from blob_attr TLV
-- @tparam string data TLV-encoded data
-- @treturn table {attr_type = value, ...}
function protocol.decode_attrs(data)
	local attrs = {}
	local pos = 1

	while pos + 3 <= #data do
		local attr_type, len = string.unpack(">I2I2", data, pos)
		if len < 4 or pos + len - 1 > #data then
			break
		end

		local vdata = data:sub(pos + 4, pos + len - 1)
		pos = pos + len

		if #vdata == 4 then
			attrs[attr_type] = string.unpack(">I4", vdata)
		elseif vdata:find("\0") then
			attrs[attr_type] = vdata:match("^([^\0]*)")
		else
			attrs[attr_type] = vdata
		end
	end

	return attrs
end

return protocol
