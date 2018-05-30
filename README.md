NAME
----

`je2e` - Juniper .pcap file convertor.

SYNOPSIS
--------

```
    je2e [-f] [-v] infile.pcap outfile.pcap
```

DESCRIPTION
-----------

.pcap files collected on Juniper routers written in a bit special format,
(datalink type: Juniper Ethernet, not standard Ethernet) with packets
entering RE missing layer2 headers and thus these packets can be read by
`tcpdump` but will not be fully decoded by `wireshark`.

This utility was written to overcome `wireshark` limitation and what
it does is just:
- opens `infile` and checks that is was collected on Juniper (has datalink
type of Juniper Ethernet)
- reads `infile` packet by packet
- check if input packet has layer2 header.
- if it does - just writes packet with existing header.
- if it does not - `je2e` writes packet with prepended simulated ethernet header

Simulated header is constructed as follows:
- all-zero addresses are used for both source and destination mac-address
- ethertype is guessed from the first nibble of data: 4 means IPv4 and 6 IPv6.

The options are as follows:

#### -f

Allow outfile overwriting. Without this option `je2e` will refuse to overwrite
existing output file.

#### -v

Be a bit more verbose about processing.

DIAGNOSTICS
-----------

When everything is ok, `je2e` returns with exit code of 0 and without
any output.

When error happens it will be written to stdout and exit-code will be non-zero.

Edge cases: too short packets, or packets without both l2 headers correct
first nibble: in this case warning message written on stderr, however,
processing continues.

AUTHOR
------

Alexandre Snarskii [snar@snar.spb.ru](mailto:snar@snar.spb.ru)

