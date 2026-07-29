"""Minimal authoritative DNS server that answers from an openspf.org zonedata block.

Exists so the RFC 7208 conformance suite can be driven against securespf without
touching the real internet and without changing a line of production code: the
suite's `zonedata` is served here, and `securespf-check -n 127.0.0.1 -p <port>`
points the daemon's own resolver at it. That means the resolver under test is the
real one, so record joining, negative answers and timeouts are exercised too --
not just the evaluation logic sitting above them.
"""

import socket
import struct
import threading

# Query/answer types we need to serve. The suite's zonedata uses exactly these.
TYPE = {"A": 1, "NS": 2, "CNAME": 5, "SOA": 6, "PTR": 12, "MX": 15, "TXT": 16,
        "AAAA": 28, "SPF": 99}
TYPE_NAME = {v: k for k, v in TYPE.items()}

RCODE_NOERROR = 0
RCODE_NXDOMAIN = 3


class Zone:
    """A parsed `zonedata` block, indexed by lowercase owner name."""

    def __init__(self, zonedata, duplicate_spf_to_txt):
        # name -> list of (type_name, value)
        self.records = {}
        # Names carrying a bare TIMEOUT entry.
        self.timeout_names = set()
        # name -> set of record types the zone asserts are absent via `TYPE: NONE`.
        self.absent = {}

        for owner, entries in (zonedata or {}).items():
            owner_l = str(owner).lower().rstrip(".")
            rrs = []
            absent = set()
            for entry in entries or []:
                if entry is None:
                    continue
                # A bare string entry (rather than a mapping) is the suite's way
                # of writing TIMEOUT.
                if isinstance(entry, str):
                    if entry.upper() == "TIMEOUT":
                        self.timeout_names.add(owner_l)
                    continue
                for rtype, value in entry.items():
                    rtype_u = str(rtype).upper()
                    # `TXT: NONE` is a sentinel meaning the type is explicitly
                    # absent -- not a record whose value is the string "NONE".
                    # The suite uses it to say "this name has an SPF record but no
                    # TXT record", which combined with TIMEOUT is how it expresses
                    # "the TXT query hangs".
                    if isinstance(value, str) and value == "NONE":
                        absent.add(rtype_u)
                        continue
                    rrs.append((rtype_u, value))
            self.records[owner_l] = rrs
            if absent:
                self.absent[owner_l] = absent

        if duplicate_spf_to_txt:
            self._duplicate_spf_to_txt()

    def _duplicate_spf_to_txt(self):
        """Serve every type-99 SPF record as a TXT record as well.

        The suite header states this is the driver's job: the tests were written
        when both types were legal, and every section except "Selecting records"
        relies on the driver duplicating them so one specification exercises both
        TXT-only and SPF-aware implementations. RFC 7208 §3.1 removed type SPF,
        so securespf queries TXT only and would otherwise see empty zones.
        """
        for owner, rrs in self.records.items():
            # A zone asserting `TXT: NONE` is stating there is no TXT record, so
            # synthesising one would contradict the very thing under test.
            if "TXT" in self.absent.get(owner, ()):
                continue
            has_txt = any(t == "TXT" for t, _ in rrs)
            if has_txt:
                # Where the suite gives both, it is deliberately testing which
                # one wins. Never synthesise over an explicit TXT.
                continue
            for rtype, value in list(rrs):
                if rtype == "SPF":
                    rrs.append(("TXT", value))

    def lookup(self, name, qtype_name):
        """Return (rrs, timeout, exists) for a name/type."""
        key = name.lower().rstrip(".")
        rrs = self.records.get(key)
        if rrs is None:
            return [], False, False

        matching = [v for t, v in rrs if t == qtype_name]
        if matching:
            return matching, False, True

        # A bare TIMEOUT covers only the types the zone does not answer. That is
        # how the suite writes "the TXT record is returned but the type-99 query
        # hangs" (spftimeout, expecting fail) as against "the SPF record exists but
        # the TXT query hangs" (txttimeout, expecting temperror). Timing out every
        # type for such a name makes the first of those unreachable.
        if key in self.timeout_names:
            return [], True, True
        return [], False, True

    def cname(self, name):
        key = name.lower().rstrip(".")
        for rtype, value in self.records.get(key, []):
            if rtype == "CNAME":
                return str(value)
        return None


def encode_name(name):
    out = b""
    for label in name.rstrip(".").split("."):
        if not label:
            continue
        raw = label.encode("latin-1", "replace")
        out += bytes([len(raw)]) + raw
    return out + b"\x00"


def decode_name(data, offset):
    labels = []
    seen = set()
    while True:
        if offset >= len(data):
            raise ValueError("truncated name")
        length = data[offset]
        if length == 0:
            offset += 1
            break
        if length & 0xC0 == 0xC0:
            # Compression pointer. Follow it, guarding against loops.
            pointer = struct.unpack("!H", data[offset:offset + 2])[0] & 0x3FFF
            if pointer in seen:
                raise ValueError("compression loop")
            seen.add(pointer)
            suffix, _ = decode_name(data, pointer)
            labels.append(suffix)
            offset += 2
            return ".".join(l for l in labels if l), offset
        offset += 1
        labels.append(data[offset:offset + length].decode("latin-1"))
        offset += length
    return ".".join(labels), offset


def txt_rdata(value):
    """Encode a TXT rdata as one or more character-strings.

    A list in the zonedata means the record is deliberately split into several
    character-strings, which RFC 7208 §3.3 says a verifier must join with no
    separator. Serving that faithfully is the only way to test that we do.
    """
    parts = value if isinstance(value, list) else [value]
    out = b""
    for part in parts:
        raw = str(part).encode("latin-1", "replace")
        # A single character-string cannot exceed 255 octets.
        while len(raw) > 255:
            out += bytes([255]) + raw[:255]
            raw = raw[255:]
        out += bytes([len(raw)]) + raw
    if out == b"":
        out = b"\x00"
    return out


def rdata_for(rtype, value):
    if rtype in ("TXT", "SPF"):
        return txt_rdata(value)
    if rtype == "A":
        return socket.inet_pton(socket.AF_INET, str(value))
    if rtype == "AAAA":
        return socket.inet_pton(socket.AF_INET6, str(value))
    if rtype == "MX":
        pref, host = value
        return struct.pack("!H", int(pref)) + encode_name(str(host))
    if rtype in ("PTR", "CNAME", "NS"):
        return encode_name(str(value))
    raise ValueError("unsupported record type %s" % rtype)


class MockDns(threading.Thread):
    daemon = True

    def __init__(self, host="127.0.0.1", port=0):
        super().__init__()
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.bind((host, port))
        self.port = self.sock.getsockname()[1]
        self.zone = Zone({}, False)
        self._stop = False
        self.queries = 0

    def set_zone(self, zone):
        self.zone = zone
        self.queries = 0

    def stop(self):
        self._stop = True
        try:
            self.sock.close()
        except OSError:
            pass

    def run(self):
        while not self._stop:
            try:
                data, addr = self.sock.recvfrom(4096)
            except OSError:
                return
            try:
                reply = self.handle(data)
            except Exception:
                reply = None
            if reply is not None:
                try:
                    self.sock.sendto(reply, addr)
                except OSError:
                    return

    def handle(self, data):
        if len(data) < 12:
            return None
        txid = data[:2]
        qdcount = struct.unpack("!H", data[4:6])[0]
        if qdcount < 1:
            return None
        qname, offset = decode_name(data, 12)
        qtype, _qclass = struct.unpack("!HH", data[offset:offset + 4])
        offset += 4
        question = data[12:offset]
        self.queries += 1

        qtype_name = TYPE_NAME.get(qtype)
        if qtype_name is None:
            return self.reply(txid, question, RCODE_NOERROR, b"", 0)

        answers = b""
        count = 0
        name = qname

        # Follow a CNAME chain before answering, which is what a real recursive
        # resolver hands back. Bounded, so a deliberately looping zone cannot
        # hang the harness.
        for _ in range(8):
            target = self.zone.cname(name)
            if target is None or qtype_name == "CNAME":
                break
            answers += self.rr(name, "CNAME", target)
            count += 1
            name = target

        rrs, timeout, exists = self.zone.lookup(name, qtype_name)
        if timeout:
            # Answer nothing at all: the point of a TIMEOUT entry is to make the
            # resolver's own timeout path run.
            return None
        if not exists:
            return self.reply(txid, question, RCODE_NXDOMAIN, answers, count)
        for value in rrs:
            try:
                answers += self.rr(name, qtype_name, value)
                count += 1
            except ValueError:
                continue
        return self.reply(txid, question, RCODE_NOERROR, answers, count)

    def rr(self, name, rtype, value):
        rdata = rdata_for(rtype, value)
        return (encode_name(name) + struct.pack("!HHIH", TYPE[rtype], 1, 60, len(rdata)) + rdata)

    def reply(self, txid, question, rcode, answers, ancount):
        # QR=1, AA=1 (we are authoritative for the suite's zones), RA=1.
        flags = 0x8580 | rcode
        header = txid + struct.pack("!HHHHH", flags, 1, ancount, 0, 0)
        return header + question + answers
