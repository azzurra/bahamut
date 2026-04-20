FROM debian:trixie

RUN apt-get update && apt-get install -y --no-install-recommends \
        autoconf \
        build-essential \
        libssl-dev \
        zlib1g-dev \
        libcrypt-dev \
        ca-certificates \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /build
COPY . .

# Seed options.h with the leaf profile so configure does not invoke the
# interactive ./config script (which would hang with no stdin).
RUN cp buildbot/options.h_leaf include/options.h

# Regenerate configure from configure.in (in case it's stale).
RUN autoconf

RUN ./configure

RUN make
