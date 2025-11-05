-- https://github.com/FalconChristmas/fpp/blob/master/docs/ControlProtocol.txt
fpp_protocol = Proto("FPP_MULTISYNC", "FPP MultiSync Protocol")

local operating_modes = {
  [0] = "Unknown",
  [1] = "Bridge",
  [2] = "Player",
  [4] = "Sending Multisync",
  [6] = "Master",
  [8] = "Remote"
}

local multisync_actions = {
  [0] = "Start",
  [1] = "Stop",
  [2] = "Sync",
  [3] = "Open"
}

local multisync_types = {
  [0] = "FSEQ",
  [1] = "Media"
}

header = ProtoField.string("fpp.header", "Header")
message_type = ProtoField.uint8("fpp.message_type", "Message Type")
extra_data_len = ProtoField.int16("fpp.extra_data_len", "Extra Data Length", base.DEC)
command = ProtoField.string("fpp.command", "Command to Run")
local ef_data_len = ProtoExpert.new("fpp.extra_data_len.expert", "Extra Data Length is invalid", expert.group.MALFORMED, expert.severity.ERROR)
local ping_type = ProtoField.uint8("fpp.ping.subtype", "Ping Subtype")
local ping_hardware_type = ProtoField.uint8("fpp.ping.hardware_type", "App/Hardware Type", base.HEX)
local major_version = ProtoField.uint16("fpp.ping.major_version", "Major Version", base.DEC)
local minor_version = ProtoField.uint16("fpp.ping.minor_version", "Minor Version")
local version_str = ProtoField.string("fpp.ping.version", "Version")
local operating_mode_field = ProtoField.uint8("fpp.ping.operating_mode", "Operating Mode", base.HEX, operating_modes)
local ip_address_field = ProtoField.ipv4("fpp.ping.ip_address", "IP Address")
local hostname_field = ProtoField.stringz("fpp.ping.hostname", "Hostname")
local version_field = ProtoField.stringz("fpp.ping.version", "Version")
local hardware_type_field = ProtoField.stringz("fpp.ping.hardware_type_string", "Hardware Type String")
local channel_ranges_field = ProtoField.stringz( "fpp.ping.channel_ranges", "Channel Ranges")

local f_sync_action = ProtoField.uint8("fpp.multisync.action", "MultiSync Action", base.DEC, multisync_actions)
local f_sync_type = ProtoField.uint8("fpp.multisync.type", "Sync Type", base.HEX, multisync_types)
local f_sync_filename = ProtoField.stringz("fpp.multisync.file", "File Name")
local f_frame_number = ProtoField.uint32("fpp.multisync.frame_number", "Frame Number")
local f_seconds = ProtoField.float("fpp.multisync.seconds", "Seconds Elapsed")

fpp_protocol.fields = {
  header,
  message_type,
  extra_data_len,
  command,
  ping_type,
  ping_hardware_type,
  version_str,
  major_version,
  minor_version,
  operating_mode_field,
  ip_address_field,
  hostname_field,
  version_field,
  hardware_type_field,
  channel_ranges_field,
  f_sync_action,
  f_sync_filename,
  f_frame_number,
  f_seconds,
  f_sync_type
}
fpp_protocol.experts = { ef_data_len }

local deviceCodes = {
  [0x01] = "FPP (undetermined hardware)",
  [0x02] = "Pi A",
  [0x03] = "Pi B",
  [0x04] = "Pi A+",
  [0x05] = "Pi B+",
  [0x06] = "Pi 2 B",
  [0x07] = "Pi 2 BNew",
  [0x08] = "Pi 3 B",
  [0x09] = "Pi 3 B+",
  [0x10] = "Pi Zero",
  [0x11] = "Pi ZeroW",
  [0x12] = "Pi 3 A+",
  [0x13] = "Pi 4",
  [0x14] = "Pi 5",
  [0x15] = "Pi Zero 2W",
  [0x40] = "BeagleBone Black Rev B",
  [0x41] = "BeagleBone Black Rev C",
  [0x42] = "BeagleBone Black Wireless",
  [0x43] = "BeagleBone Green",
  [0x44] = "BeagleBone Green Wireless",
  [0x45] = "PocketBeagle",
  [0x46] = "SanCloud Beaglebone Enhanced",
  [0x47] = "PocketBeagle2/BeaglePlay",
  [0x60] = "Armbian",
  [0x70] = "MacOS",
  [0x80] = "Unknown Falcon Controller",
  [0x81] = "F16v2-B",
  [0x82] = "F4v2-64M",
  [0x83] = "F16v2 (Red)",
  [0x84] = "F4v2 (Red)",
  [0x85] = "F16v3",
  [0x86] = "F4v3",
  [0x87] = "F48",
  [0x88] = "F16v4",
  [0x89] = "F48v4",
  [0x8A] = "F16v5",
  [0x8B] = "F32v5",
  [0x8C] = "F48v5",
  [0xA0] = "Genius Pixel 16",
  [0xA1] = "Genius Pixel 8",
  [0xA2] = "Genius Long Range",
  [0xC1] = "xSchedule",
  [0xC2] = "ESPixelStick - ESP8266",
  [0xC3] = "ESPixelStick - ESP32",
  [0xFB] = "WLED",
  [0xFC] = "DIYLEDExpress",
  [0xFD] = "HinksPix",
  [0xFE] = "AlphaPix",
  [0xFF] = "SanDevices"
}

function get_message_type(msg_type)
  local opcode_name = "Unknown"

      if msg_type ==    0 then opcode_name = "Legacy Command"
  elseif msg_type == 1 then opcode_name = "MultiSync"
  elseif msg_type == 2 then opcode_name = "Event"
  elseif msg_type == 3 then opcode_name = "Send Blanking Data"
  elseif msg_type == 4 then opcode_name = "Ping"
  elseif msg_type == 5 then opcode_name = "Plugin"
  elseif msg_type == 6 then opcode_name = "FPP Command"
  end

  return opcode_name
end

function fpp_protocol.dissector(buffer, pinfo, tree)
  length = buffer:len()
  if length == 0 then return end

  pinfo.cols.protocol = fpp_protocol.name

  local subtree = tree:add(fpp_protocol, buffer(), "FPP MultiSync Protocol")

  local headerVal = buffer(0, 4):string()
  local headerField = subtree:add(header, buffer(0, 4))
  if headerVal == "FPPD" then
    headerField:append_text(" (GOOD)")
  else
    headerField:append_text(" (BAD)")
  end

  local message_type_number = buffer(4, 1):le_uint()
  local message_type_name = get_message_type(message_type_number)
  subtree:add_le(message_type, buffer(4, 1)):append_text( " (" .. message_type_name .. ")")

  local extra_data_len_value_b = buffer(5, 2)
  local extra_data_len_value = extra_data_len_value_b:le_uint()
  local extra_data_len_field = subtree:add_le(extra_data_len, extra_data_len_value_b)

  if message_type_number == 0 then -- Command Packet
    subtree:add_le(command, buffer(7, extra_data_len_value))
  elseif message_type_number == 1 then -- MultiSync Control Packet
    subtree:add_le(f_sync_action, buffer(7, 1))
    subtree:add_le(f_sync_type, buffer(8, 1))
    subtree:add_le(f_frame_number, buffer(9, 4))
    subtree:add_le(f_seconds, buffer(13, 4))
    subtree:add(f_sync_filename, buffer(17, buffer:len() - 17))
  elseif message_type_number == 4 then -- Ping
    if extra_data_len_value == 98 then
      extra_data_len_field:append_text(" (v1 ping packet)")
    elseif extra_data_len_value == 294 then
      extra_data_len_field:append_text(" (v3 ping packet)")
    else
      subtree:add_proto_expert_info(ef_data_len)
    end
    local ping_version = buffer(8, 1):le_uint()
    local ping_version_tree = subtree:add_le(ping_type, buffer(8, 1), ping_version)
    if ping_version == 0 then
      ping_version_tree:append_text(" (Unsolicited Ping or Response)")
    elseif ping_version == 1 then
      ping_version_tree:append_text(" (Discover)")
    end
    
    local hardware_type_f = subtree:add_le(ping_hardware_type, buffer(9, 1))
    local hardware_type_s = deviceCodes[buffer(9, 1):le_uint()]
    if hardware_type_s ~= nil then
      hardware_type_f:append_text(" (" .. hardware_type_s .. ")")
    else
      hardware_type_f:append_text(" (Unknown Type)")
    end

    local maj_version_b = buffer(10, 2)
    local min_version_b = buffer(12, 2)
    local version_tree = subtree:add(version_str, buffer(10, 4), "Version: v" .. maj_version_b:uint() .. "." .. min_version_b:uint())
    version_tree:add(major_version, maj_version_b)
    version_tree:add(minor_version, min_version_b)

    local operating_mode_b = buffer(14, 1):le_uint()
    subtree:add(operating_mode_field, buffer(14, 1), operating_mode_b)

    subtree:add(ip_address_field, buffer(15, 4))

    subtree:add(hostname_field, buffer(19, 64))
    subtree:add(version_field, buffer(84, 40))

    if extra_data_len_value == 294 then -- v3 ping
      subtree:add(hardware_type_field, buffer(125, 40))
      subtree:add(channel_ranges_field, buffer(166, 120))
    end
  end
end

local udp_port = DissectorTable.get("udp.port")
udp_port:add(32320, fpp_protocol)
