# Wireshark .lua filters for dissecting IEC61850-90-5

These two `.lua` files allow you to dissect IEC61850-90-5 traffic.

[IEC TR 61850-90-5:2012 Communication networks and systems for power utility automation - Part 90-5: Use of IEC 61850 to transmit synchrophasor information according to IEEE C37.118](https://webstore.iec.ch/publication/6026)

Only **R-Goose** and **R-SV** APDUs can be dissected so far (**Tunnelled** and **MGMT** APDUs are work in progress).


## rfc1240.lua

It dissects the first bytes, corresponding to [RFC 1240 OSI Connectionless Transport Services on top of UDP](https://tools.ietf.org/html/rfc1240)

At the end of the script, this dissector is registered in Wireshark in order to decode UDP port 102. Therefore, Wireshark will decode all UDP packets coming to this port as "RFC 1240" traffic.

The name assigned to the dissector in Wireshark is `RFC1240`.


## iec61850-90-5.lua

It dissects the bytes, starting from the `SPDU ID`, until the `Simulation` field (included). After that, it calls one of these dissectors, depending on the value of `Payload Type`:

- "goose"
- "sv"

The name assigned to the dissector in Wireshark is `iec61850_90_5`.


## How to make the scripts work

Just place them in your Wireshark directory, inside the `plugins` folder, i.e.: 

```
C:\Program Files\Wireshark\plugins
```

You don't need to compile anything. Wireshark will read them when it starts.

## Some references

Information about how to dissect **Goose** can be found here: https://github.com/wireshark/wireshark/blob/master/epan/dissectors/packet-goose.c#L893
https://github.com/wireshark/wireshark/blob/master/epan/dissectors/packet-goose.c#L37


Some information about dissecting **Sampled Values**:
https://github.com/wireshark/wireshark/blob/5f36e597a0e23b205397742570b102206574b70f/epan/dissectors/packet-sv.c#L36


### Information about `.lua` scripts:

The Wireshark Lua wiki page:
https://wiki.wireshark.org/Lua

Kinds of dissectors for Wireshark:
https://stackoverflow.com/questions/49568418/compiling-wireshark-packet-dissector

For an introduction to all 3 methods of building dissectors, you may wish to review Graham Bloice's presentation from Sharkfest '15 titled, ["Wireshark Dissectors - 3 ways to eat bytes"](https://sharkfestus.wireshark.org/assets/presentations15/03.pptx)

Example: Dissector written in Lua:
https://www.wireshark.org/docs/wsdg_html_chunked/wslua_dissector_example.html

A very detailed example:
https://wiki.wireshark.org/Lua/Examples?action=AttachFile&do=get&target=pcap_file.lua

[List of Wireshark dissectors](https://github.com/wireshark/wireshark/tree/master/epan/dissectors). If you want to know the name of one of them, look inside the corresponding `.c` file. For example, inside `packet-goose.c` you have a line saying `#define GOOSE_PFNAME "goose"`, which means that `goose` is the name of the dissector you have to call from your `.lua` script.


## Author

The author of these scripts is Jose Saldana, from [CIRCE Foundation](https://www.fcirce.es/en/), as a part of the [H2020 FARCROSS project](https://cordis.europa.eu/project/id/864274), see [farcross.eu/](https://farcross.eu/). This project has received funding from the European Union’s Horizon 2020 research and innovation programme under grant agreement No 864274.