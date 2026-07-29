# RFC 7208 conformance suite

Drives the **openspf.org SPF test suite** against `securespf-check`, which exposes
`check_host()` directly — the same interface the suite is written against.

Current result: **203 / 203.**

```
$ python3 -m venv .venv && .venv/bin/pip install -r requirements.txt
$ cd ../.. && zig build          # produces zig-out/bin/securespf-check
$ cd test/rfc7208 && ../../.venv/bin/python runsuite.py

total=203 passed=203 failed=0 errored=0 skipped=0
```

Useful flags: `-v` lists every case, `--section SUBSTRING` restricts to one
section of the suite, `--test NAME` runs a single case. `SECURESPF_CHECK=/path/to/binary`
overrides the checker location, which is what a package build or CI runner wants
when the binary is not in the tree.

## What it actually tests, and why it is set up this way

`mockdns.py` is a minimal authoritative DNS server that answers from the suite's
own `zonedata` blocks. `securespf-check -n 127.0.0.1 -p <port>` then points the
daemon's **real** resolver at it.

That choice is the point of the harness. The alternative — stubbing DNS inside
the Zig code — would test the evaluation logic while replacing the component most
likely to be wrong. Serving real DNS on a loopback port means record joining,
`NXDOMAIN` versus empty answers, CNAME chasing, the type-99 `SPF` record and
timeout handling are all exercised as shipped. **No production code is modified
or conditionally compiled to run this suite.**

## The type-99 duplication rule, which is easy to get wrong

The suite predates RFC 7208 removing the type-99 `SPF` record, and its header
makes duplicating `SPF` records into `TXT` the *driver's* responsibility, so that
one specification can exercise both TXT-only and SPF-aware implementations.

The correct rule is narrower than either "duplicate everywhere" or "never
duplicate", and getting it wrong produces five phantom failures that look like
implementation bugs:

- `example1.com` publishes only a type-99 record, and the suite still expects
  `neutral` — so duplication is required even there.
- `example4.com` publishes `SPF +all` alongside `TXT -all` and expects `fail` —
  which only holds if a type-99 record never overrides a `TXT` that exists.

Both hold if, and only if, duplication happens into zones that have **no** `TXT`
record at all. That is what `Zone._duplicate_spf_to_txt` does, and the reason it
is documented here is that a future reader who "simplifies" it will see five
failures and go looking in `evaluate.zig`.

## Provenance

`rfc7208-tests.yml` is the openspf.org test suite, **release 2014.04**, vendored
verbatim with its contributor list intact — see the header of that file. It is
committed rather than downloaded so a conformance run is reproducible from a
clone and pinned to a known suite version.

> This suite was previously run from a scratch directory outside the repository.
> That made the 203/203 result unreproducible by anyone else and unusable as a
> regression check, which is most of what a conformance result is for. Vendored
> 2026-07-29.

## Scope

Passing this suite is a statement about **SPF evaluation** — `check_host()`,
macro expansion, the processing limits of §4.6.4, and the DNS behaviour beneath
them. It says nothing about the milter protocol layer, the `Authentication-Results`
stamp, or the other three daemons, none of which have an equivalent oracle yet.
