# Installing Azzurra Bahamut

This document describes how to build and deploy `ircd` from source on a
Debian/Ubuntu system.  Other distros work too — only the package names
change.

Bahamut now builds and runs as a native 64-bit binary (as of commit
`c9ded13`); no multilib toolchain is required.

## 1. Build dependencies

On Debian/Ubuntu:

    sudo apt update
    sudo apt install \
        autoconf \
        build-essential \
        libssl-dev \
        zlib1g-dev \
        libcrypt-dev

Only `libssl-dev` is strictly required for TLS support; build without
it if you pass `--disable-encryption` to `configure`.

## 2. Configure

From the repository root:

    autoconf       # regenerate configure from configure.in
    ./configure

`autoconf` is only needed after changes to `configure.in` (or if the
shipped `configure` is stale after a checkout).

`configure` flags of note:

    --disable-encryption    skip OpenSSL (no TLS listener, no link encryption)
    --prefix=DIR            install prefix

## 3. Select hub / leaf / custom build

`configure` invokes the interactive `./config` script unless
`include/options.h` already exists.  For unattended builds, seed it
from one of the canned profiles before running `configure`:

    cp buildbot/options.h_leaf include/options.h    # standard leaf
    # or
    cp buildbot/options.h_hub  include/options.h    # hub build (HUB defined, smaller fd limits)

For interactive customization just run `./config` and answer the
prompts — it walks through every `#define` in `include/options.h`
(`DPATH`, `SPATH`, `HARD_FDLIMIT`, `INIT_MAXCLIENTS`, `SERVICES_NAME`,
cloaking, etc.).  Review the resulting `include/options.h` and
`include/config.h` by hand before building.

## 4. Build

    make

Produces `src/ircd`.  Parallel builds (`make -j`) work.

## 5. Install

    make install

Installs into `DPATH` (the path set in `options.h`, default
`/home/ircd`).  Creates the bin/, etc/, log/ directory layout expected
at runtime.

## 6. TLS certificates

See [`SSL`](./SSL) for the full FAQ.  Short version: if you enabled
encryption at configure time, drop a PEM certificate and private key
into `DPATH` and add a `P:` line with the `S` flag (SSL listener) on
the desired port (commonly 9999) in `ircd.conf`:

    P:*:<bind-ip>:S:9999

See the `P:` line header comment in `doc/example.conf` for the full
flag set (`S` = SSL, `H` = HAProxy PROXY, both = cleartext behind a
TLS-terminating proxy).

A self-signed cert is enough for testing; production should use a CA
signed cert (Let's Encrypt works fine).

## 7. Runtime configuration

Edit `ircd.conf` in `DPATH`.  See `doc/example.conf` for a fully
commented template, and `doc/Configure.doc` for per-directive
reference.  Minimum set of lines:

    M:<server name>:*:<description>:
    A:<description>:<admin nick>:<contact>:
    Y:<class>:<pingfreq>:<connfreq>:<maxlinks>:<sendq>
    I:<client mask>:<password>:<host mask>:<port>:<class>     # client auth
    O:<user@host>:<pass>:<nick>:<flags>:<class>
    P:<allowed addr>:<bind addr>:<flags>:<port>

Field counts and field meanings are pinned by `doc/example.conf` —
keep that as the canonical reference, not this list.

For details of cloaking (`+x`), vhosts, spamfilters, kline/akill, see
`doc/Configure.doc`.

## 8. Running

    cd <DPATH>
    ./ircd

Common flags:

    -s                  send errors to stderr instead of syslog (debug)
    -f <conf>           use a non-default ircd.conf path
    -t                  do not fork; run in foreground
    -v                  print version and exit

Logs land in `log/ircd.log` (path set at compile time via `LPATH` in
`include/config.h`, default `ircd.log` — there is no runtime `L:`
config line).

## 9. Upgrading

1. Stop ircd.
2. `git pull` (or swap in the new source tree).
3. `autoconf && ./configure`.
4. Copy the canned `buildbot/options.h_{leaf,hub}` back into
   `include/options.h` if you weren't using a hand-edited one.
5. `make && make install`.
6. Start ircd.

The on-disk state (kline/akill DBs) is stable across minor versions.
Across majors, consult `CHANGES`.

## Troubleshooting

* `configure` fails with "openssl not found" — install `libssl-dev` or
  pass `--disable-encryption`.
* `make` succeeds but `./ircd` exits immediately — check `log/` and
  try `./ircd -s -t` to get errors on stderr.
* `./config` hangs in CI — pre-seed `include/options.h` from
  `buildbot/options.h_leaf` or `buildbot/options.h_hub` before running
  `configure`.

See also [`SSL`](./SSL) and [`README.small_nets`](./README.small_nets)
for topic-specific notes, and [`CHANGES`](./CHANGES) for the version
history.
