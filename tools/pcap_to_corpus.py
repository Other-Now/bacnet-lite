"""Extract UDP payloads from a pcap (LINKTYPE_RAW or Ethernet) into a fuzz corpus dir.

    python3 tools/pcap_to_corpus.py session.pcap corpus/device [--client]

--client keeps only responses (ComplexACK, I-Am, COV notifications) and prefixes the
selector byte fuzz_client.cpp expects.
"""
import hashlib
import os
import struct
import sys


def packets(path):
    with open(path, "rb") as f:
        hdr = f.read(24)
        linktype = struct.unpack("<I", hdr[20:24])[0]
        while True:
            rec = f.read(16)
            if len(rec) < 16:
                return
            incl = struct.unpack("<I", rec[8:12])[0]
            data = f.read(incl)
            if linktype == 1:  # Ethernet
                data = data[14:]
            elif linktype == 113:  # Linux cooked
                data = data[16:]
            ihl = (data[0] & 0x0F) * 4
            if data[9] != 17:
                continue
            yield data[ihl + 8:]


def main():
    pcap, out = sys.argv[1], sys.argv[2]
    client = "--client" in sys.argv
    os.makedirs(out, exist_ok=True)
    n = 0
    for p in packets(pcap):
        if client:
            # BVLC(4) + NPDU(2, no routing) then the APDU
            if len(p) < 8 or p[4] != 1 or p[5] & 0x28:
                continue
            apdu = p[6:]
            t = apdu[0] >> 4
            if t == 3 and apdu[2] == 12: sel, body = 0, apdu[3:]
            elif t == 3 and apdu[2] == 14: sel, body = 1, apdu[3:]
            elif t == 1 and apdu[1] == 2: sel, body = 2, apdu[2:]
            elif t == 0 and apdu[3] == 1: sel, body = 2, apdu[4:]
            elif t == 1 and apdu[1] == 0: sel, body = 3, apdu[2:]
            else:
                continue
            p = bytes([sel]) + body
        name = hashlib.sha1(p).hexdigest()
        with open(os.path.join(out, name), "wb") as f:
            f.write(p)
        n += 1
    print(f"{n} inputs -> {out}")


main()
