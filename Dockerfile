FROM debian:trixie

# Enable i386 architecture for 32-bit build support
RUN dpkg --add-architecture i386

RUN apt-get update && apt-get install -y \
    autoconf \
    build-essential \
    gcc-multilib \
    libc6-dev:i386 \
    zlib1g-dev:i386 \
    libssl-dev:i386 \
    libcrypt-dev:i386 \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /build
COPY . .

# Regenerate configure from configure.in (in case it's stale)
RUN autoconf

# Configure for 32-bit: pass CFLAGS/LDFLAGS so configure's own test
# programs are also compiled as 32-bit, matching the final binary.
RUN CFLAGS="-m32" LDFLAGS="-m32" ./configure

RUN make
