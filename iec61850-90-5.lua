-- declare the protocol
-- the name is from Figure 23 of the IEC 61850-90-5 standard
local iec61850_90_5 = Proto("iec61850_90_5", "IEC 61850-90-5 Protocol for sending GOOSE and SV over ITU X.234");

-- declare the fields of the header

-- Session Type Marker (Tunneled = 0xA0, GOOSE = 0xA1, Sampled Value = 0xA2)
-- declare the value strings for the field SPDU_ID
local session_type_markers = {  [160] = "Tunneled",
                                [161] = "GOOSE",
                                [162] = "Sampled Values"
}
local f_SI = ProtoField.uint8("iec61850_90_5.SI", "SPDU ID", base.DEC, session_type_markers)
local f_LI = ProtoField.uint8("iec61850_90_5.LI", "Session header length", base.DEC)
local common_header = ProtoField.uint8("iec61850_90_5.CH", "Header content indicator", base.DEC)
local f_LI2 = ProtoField.uint8("iec61850_90_5.LI2", "Length", base.DEC)
local SPDU_length = ProtoField.uint32("iec61850_90_5.SPDU_length", "SPDU Length", base.DEC)
local SPDU_number = ProtoField.uint32("iec61850_90_5.SPDU_number", "SPDU Number", base.DEC)
local version = ProtoField.uint16("iec61850_90_5.version", "Version", base.DEC)
local time_of_current_key = ProtoField.uint32("iec61850_90_5.time_of_current_key", "Time of Current Key", base.DEC)
local time_to_next_key = ProtoField.uint16("iec61850_90_5.time_to_next_key", "Time to Next Key", base.DEC)
-- Security Algorithm type marker (None = 0x00, AES128 = 0x01, AES256 = 0x02)
local security_algorithm_type_markers = { [0] = "None",
                                          [1] = "AES128",
                                          [2] = "AES256"
}
local securtiy_algorithms = ProtoField.uint8("iec61850_90_5.securtiy_algorithms", "Security Algorithms", base.DEC, security_algorithm_type_markers)
-- Signature Algorithm Type Marker (None = 0x00, SHA80 = 0x01, SHA128 = 0x02, SHA256 = 0x03, AES64 = 0x04, AES128 = 0x05)
local signature_algorithm_type_markers = {[0] = "None",
                                          [1] = "SHA80",
                                          [2] = "SHA128",
                                          [3] = "SHA256",
                                          [4] = "AES64",
                                          [5] = "AES128"
}
local signature_algorithms = ProtoField.uint8("iec61850_90_5.signature_algorithms", "Signature Algorithms", base.DEC, signature_algorithm_type_markers)

local key_ID = ProtoField.uint32("iec61850_90_5.key_ID", "Key ID", base.DEC)
local payload_length = ProtoField.uint32("iec61850_90_5.payload_length", "Length of the payload (PDU)", base.DEC)

-- declare the value strings for the field 'Payload type'
local payload_types = { [129] = "GOOSE",
                        [130] = "Sampled Values"
}
-- declare the field 'Payload type' (APDU Tag, which will use the values defined in 'payload_types'
local payload_type = ProtoField.uint8("iec61850_90_5.payload_type", "Payload Type (APDU Tag)", base.DEC, payload_types)

local simulation = ProtoField.uint8("iec61850_90_5.simulation", "Simulation flag", base.DEC)


-- define the field structure
iec61850_90_5.fields = { f_SI, f_LI, common_header, f_LI2,
                         SPDU_length, SPDU_number,
                         version,
                         time_of_current_key, time_to_next_key,
                         securtiy_algorithms, signature_algorithms, key_ID,
                         payload_length, payload_type,
                         simulation
}

local data_dis = Dissector.get("data")

-- dissector function
function iec61850_90_5.dissector(buf, pkt, tree)

        -- get the length: it is the value of the first byte
        -- reduce it by 1 because LI itself is excluded from the value of the length
        -- 'buf(0,1)' means 'take 1 character from position 0'
        local length = buf(0, 1):uint() - 1

        -- set the protocol column (it will appear in the packet list part of Wireshark window)
        pkt.cols['protocol'] = "IEC61850-90-5"

        -- this variable stores the offset (number of positions I have read)
        local offset = 0

        -- create the RFC1240 protocol tree item
        local subtree = tree:add(iec61850_90_5, buf(offset,14))

        -- first byte: SI
        subtree:add(f_SI, buf(offset,1))
        offset = offset + 1

        -- second byte: LI
        subtree:add(f_LI, buf(offset,1))
        offset = offset + 1
        
        -- third byte: common header
        subtree:add(common_header, buf(offset,1))
        offset = offset + 1
 
        -- fourth byte: length identifier
        subtree:add(f_LI2, buf(offset,1))
        offset = offset + 1

        -- SPDU length: 4 bytes
        subtree:add(SPDU_length, buf(offset,4))
        offset = offset + 4        

        -- SPDU number: 4 bytes
        subtree:add(SPDU_number, buf(offset,4))
        offset = offset + 4  

        -- Version: 2 bytes
        subtree:add(version, buf(offset,2))
        offset = offset + 2  

        -- Time of Current Key: 4 bytes
        subtree:add(time_of_current_key, buf(offset,4))
        offset = offset + 4  

        -- Time to Next Key: 2 bytes
        subtree:add(time_to_next_key, buf(offset,2))
        offset = offset + 2

        -- Security Algorithms: 1 byte
        subtree:add(securtiy_algorithms, buf(offset,1))
        offset = offset + 1

        -- Signature Algorithms: 1 byte
        subtree:add(signature_algorithms, buf(offset,1))
        offset = offset + 1

        -- Key ID: 4 bytes
        subtree:add(key_ID, buf(offset,4))
        offset = offset + 4  

        -- Length of the payload: 4 bytes
        subtree:add(payload_length, buf(offset,4))
        offset = offset + 4  

        -- now it comes a byte indicating the type of APDU: 'payload type'
        local type_of_APDU = buf(offset,1):uint()
        subtree:add(payload_type, buf(offset,1))
        offset = offset + 1

        -- simulation
        subtree:add(simulation, buf(offset,1))
        offset = offset + 1

        -- Sampled Values 0x82 (130)
        if type_of_APDU == 130 then
            -- https://github.com/wireshark/wireshark/blob/5f36e597a0e23b205397742570b102206574b70f/epan/dissectors/packet-sv.c#L36
            Dissector.get("sv"):call(buf(offset):tvb(), pkt, tree)

        -- GOOSE 0x81 (129)
        else
            if type_of_APDU == 129 then
                -- https://github.com/wireshark/wireshark/blob/master/epan/dissectors/packet-goose.c#L37
                -- call the goose dissector for the next header
                Dissector.get("goose"):call(buf(offset):tvb(), pkt, tree)
            else
                -- fallback dissector that just shows the raw data
                data_dis:call(buf(offset):tvb(), pkt, tree)
            end
        end

end

-- you don't need to register this protocol anywhere. It will be called by RFC1240

-- if you register it as a postdissector, the postdissector will be used for every packet
--register_postdissector(iec61850_90_5)