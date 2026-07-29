"""Drive the openspf.org RFC 7208 test suite against securespf-check.

Usage: runsuite.py [-v] [--section SUBSTRING] [--test NAME]

Each test names a client IP, a HELO and a MAIL FROM, and expects one of a set of
results -- which is exactly the check_host() interface `securespf-check` exposes.
The suite's zonedata is served by mockdns.py, so no production code is modified
and the daemon's real resolver is the one under test.
"""

import argparse
import os
import re
import subprocess
import sys

import yaml

from mockdns import MockDns, Zone

# Resolve the checker from this file's location -- test/rfc7208/ -> repo root --
# so the suite runs from a fresh clone with no editing. SECURESPF_CHECK
# overrides it, which is what a package build or a CI runner will use when the
# binary is not in the tree.
_REPO_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
CHECK = os.environ.get(
    "SECURESPF_CHECK", os.path.join(_REPO_ROOT, "zig-out", "bin", "securespf-check")
)

# The suite predates RFC 7208 removing the type-99 SPF record, and its header
# makes duplicating SPF to TXT the driver's job so that one specification can
# exercise both TXT-only and SPF-aware implementations.
#
# The rule is narrower than "duplicate everywhere" or "never duplicate in the
# Selecting records section", and getting it wrong shows up as five phantom
# failures: `example1.com` publishes only a type-99 record and the suite still
# expects `neutral`, so duplication is needed even there, while `example4.com`
# publishes SPF `+all` alongside TXT `-all` and expects `fail`, which only holds
# if type SPF never overrides a TXT that exists. Both are satisfied by
# duplicating only into zones that have no TXT record at all, which is what
# Zone._duplicate_spf_to_txt does.

RESULTS = {"pass", "fail", "softfail", "neutral", "none", "permerror", "temperror"}


def parse_result(stdout):
    """Pull the SPF result out of securespf-check's output."""
    text = stdout.strip()
    if not text:
        return None
    # Anchored on the tool's own first line rather than scanning for any known
    # word, so a domain or sender that happens to contain "fail" cannot be
    # mistaken for the verdict, and a change to the output format shows up as an
    # error instead of a silent pass.
    match = re.match(r"^securespf-check:\s*([a-z]+)\s*$", text.splitlines()[0].strip())
    if not match:
        return None
    result = match.group(1).lower()
    return result if result in RESULTS else None


def run_check(host, mailfrom, helo, port, timeout):
    argv = [CHECK, "-i", host, "-s", mailfrom or "", "-n", "127.0.0.1", "-p", str(port)]
    if helo:
        argv += ["-e", helo]
    try:
        proc = subprocess.run(argv, capture_output=True, text=True, timeout=timeout)
    except subprocess.TimeoutExpired:
        return None, "harness timeout"
    got = parse_result(proc.stdout)
    if got is None:
        detail = (proc.stdout.strip() + " " + proc.stderr.strip()).strip()
        return None, "unparseable output: %r (rc=%d)" % (detail[:160], proc.returncode)
    return got, None


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("-v", "--verbose", action="store_true")
    ap.add_argument("--section")
    ap.add_argument("--test")
    ap.add_argument("--timeout", type=float, default=30.0)
    ap.add_argument("--yaml", default="rfc7208-tests.yml")
    args = ap.parse_args()

    with open(args.yaml, "r", encoding="latin-1") as fh:
        docs = [d for d in yaml.safe_load_all(fh) if d]

    server = MockDns()
    server.start()

    # The suite is a stream of documents; a document carries tests, zonedata or
    # both, and zonedata applies to the tests in the same document.
    sections = []
    pending_tests = None
    pending_desc = None
    for doc in docs:
        if "tests" in doc:
            pending_tests = doc["tests"]
            pending_desc = doc.get("description", "?")
        if "zonedata" in doc:
            sections.append((pending_desc, pending_tests or {}, doc["zonedata"]))
            pending_tests, pending_desc = None, None

    total = passed = failed = errored = skipped = 0
    failures = []

    for desc, tests, zonedata in sections:
        if args.section and args.section.lower() not in (desc or "").lower():
            continue
        zone = Zone(zonedata, duplicate_spf_to_txt=True)
        server.set_zone(zone)

        for name, spec in sorted(tests.items()):
            if args.test and args.test != name:
                continue
            expected = spec.get("result")
            if expected is None:
                skipped += 1
                continue
            accepted = {str(r).lower() for r in (expected if isinstance(expected, list) else [expected])}
            host = str(spec.get("host", ""))
            mailfrom = spec.get("mailfrom", "")
            helo = spec.get("helo")

            total += 1
            got, err = run_check(host, mailfrom, helo, server.port, args.timeout)
            if err:
                errored += 1
                failures.append((desc, name, spec.get("spec", "?"), sorted(accepted), err))
                if args.verbose:
                    print("ERROR %-22s %s" % (name, err))
                continue
            if got in accepted:
                passed += 1
                if args.verbose:
                    print("ok    %-22s %s" % (name, got))
            else:
                failed += 1
                failures.append((desc, name, spec.get("spec", "?"), sorted(accepted), got))
                if args.verbose:
                    print("FAIL  %-22s want %s got %s" % (name, sorted(accepted), got))

    server.stop()

    if failures:
        print("\n=== failures grouped by section ===")
        current = None
        for desc, name, rfc, accepted, got in failures:
            if desc != current:
                print("\n%s" % desc)
                current = desc
            print("  %-24s spec %-10s want %-28s got %s"
                  % (name, rfc, ",".join(accepted), got))

    print("\ntotal=%d passed=%d failed=%d errored=%d skipped=%d" %
          (total, passed, failed, errored, skipped))
    return 1 if (failed or errored) else 0


if __name__ == "__main__":
    sys.exit(main())
