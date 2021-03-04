-- declare the protocol
-- https://tools.ietf.org/html/rfc1240
local rfc1240 = Proto("RFC1240", "RFC 1240 OSI Connectionless Transport Services on top of UDP + ITU X.234");

-- https://www.itu.int/rec/T-REC-X.234/en goes on RFC1240

-- declare the fields of the header
local f_LI = ProtoField.uint8("RFC1240.LI", "LI (Length of the header)", base.DEC)
local f_UD = ProtoField.uint8("RFC1240.UD", "UD", base.HEX)
local variable_Part = ProtoField.string("RFC1240.data.string", "Variable Part")

rfc1240.fields = { f_LI, f_UD, variable_Part }

local data_dis = Dissector.get("data")

-- dissector function
function rfc1240.dissector(buf, pkt, tree)

        -- get the length: it is the value of the first byte
        -- reduce it by 1 because LI itself is excluded from the value of the length
        -- 'buf(0,1)' means 'take 1 character from position 0'
        local length = buf(0, 1):uint() - 1

        -- set the protocol column (it will appear in the packet list part of Wireshark window)
        pkt.cols['protocol'] = "RFC1240"

        -- this variable stores the offset (number of positions I have read)
        local offset = 0

        -- create the RFC1240 protocol tree item
        local subtree = tree:add(rfc1240, buf(offset,2))

        -- first byte: LI
        subtree:add(f_LI, buf(offset,1))
        offset = offset + 1

        -- second byte: UD (always 0x40)
        local UD_value = buf(offset,1):uint()
        subtree:add(f_UD, buf(offset,1))
        offset = offset + 1
        
        -- UD MUST be 0x40 (64)
        if UD_value == 64 then
            -- third and subsequent bytes: variable part. It may have 0 size if LI is 1
            if length > 1 then
                subtree:add(variable_Part, buf(offset,length))
            end

             -- move the offset to the end of the data
            offset = offset + length 
            
            -- call the IEC 61850-90-5 dissector for the next header
            Dissector.get("iec61850_90_5"):call(buf(offset):tvb(), pkt, tree)

            -- this does not work:
            -- https://github.com/wireshark/wireshark/blob/master/epan/dissectors/packet-goose.c#L37
            -- Dissector.get("R-GOOSE"):call(buf(offset):tvb(), pkt, tree)

        else
                -- fallback dissector that just shows the raw data
                data_dis:call(buf(offset):tvb(), pkt, tree)
        end
end

-- load the UDP port table
local udp_encap_table = DissectorTable.get("udp.port")

-- register the protocol to port 102
udp_encap_table:add(102, rfc1240)