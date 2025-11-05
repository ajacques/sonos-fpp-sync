-- https://github.com/FalconChristmas/fpp/blob/54735847589700ab8404c1a4045f41154b00c5bc/src/channeloutput/DDP.cpp
ddp_protocol = Proto("DDP_LIGHTS", "DDP MultiSync Protocol")

local field_protocol_version = ProtoField.uint8("ddp.protocol_version", "Protocol Version", base.HEX, nil, 0x03 << 6)
local field_timecode_added = ProtoField.bool("ddp.timecode_added", "Timecode Added", 8, nil, 0x01 << 4)
local field_storage = ProtoField.bool("ddp.storage", "Data From Storage", 8, nil, 0x01 << 3)
local field_reply_flag = ProtoField.bool("ddp.reply_flag", "Reply Flag", 8, nil, 0x01 << 2)
local field_query_flag = ProtoField.bool("ddp.query_flag", "Query Flag", 8, nil, 0x01 << 1)
local field_push_flag = ProtoField.bool("ddp.push_flag", "Push Flag", 8, nil, 0x01)
local field_sequence_num = ProtoField.uint8("ddp.sequence_number", "Sequence Number", base.HEX, nil, 0x0F)

local color_types = {
  [0] = "Greyscale",
  [1] = "RGB",
  [2] = "HSL?"
}

local bpp_vals = {
  [0] = "undefined",
  [1] = "1b",
  [2] = "4b",
  [3] = "8b",
  [4] = "16b",
  [5] = "24b",
  [6] = "32b"
}

local field_color_type = ProtoField.uint8("ddp.color_type", "Color Type", base.HEX, color_types, 0x07 << 3)
local field_bpp = ProtoField.uint8("ddp.bits_per_pixel", "Bits Per Pixel", base.DEC, bpp_vals, 0x07)

local field_data_offset = ProtoField.uint32("dpp.data_offset", "Data Offset")
local field_data_length = ProtoField.uint16("ddp.data_length", "Data Length")

ddp_protocol.fields = {
  field_protocol_version,
  field_timecode_added,
  field_storage,
  field_reply_flag,
  field_query_flag,
  field_push_flag,
  field_sequence_num,
  field_color_type,
  field_data_offset,
  field_data_length,
  field_bpp
}
ddp_protocol.experts = {  }


function ddp_protocol.dissector(buffer, pinfo, tree)
  length = buffer:len()
  if length == 0 then return end

  pinfo.cols.protocol = ddp_protocol.name

  local subtree = tree:add(ddp_protocol, buffer(), "DDP Light Control Protocol")

  subtree:add(field_protocol_version, buffer(0, 1))
  subtree:add(field_timecode_added, buffer(0, 1))
  subtree:add(field_storage, buffer(0, 1))
  subtree:add(field_reply_flag, buffer(0, 1))
  subtree:add(field_query_flag, buffer(0, 1))
  subtree:add(field_push_flag, buffer(0, 1))

  subtree:add(field_sequence_num, buffer(1, 1))

  subtree:add(field_color_type, buffer(2, 1))
  subtree:add(field_bpp, buffer(2, 1))

  subtree:add(field_data_offset, buffer(4, 4))
  subtree:add(field_data_length, buffer(8, 2))
end

local udp_port = DissectorTable.get("udp.port")
udp_port:add(4048, ddp_protocol)
