# Compilation Instructions for Bahamut IRCd

This document outlines the steps required to compile the Bahamut IRC daemon on a Debian or Ubuntu 64-bit system, targeting a 32-bit binary.

## Prerequisites

Before compiling, ensure your system has the necessary multi-architecture support and development libraries installed.

1.  **Enable Multi-Architecture Support:**
    On your 64-bit Debian/Ubuntu system, enable the `i386` architecture for 32-bit package compatibility:

    ```bash
    sudo dpkg --add-architecture i386
    sudo apt update
    ```

2.  **Install Build Dependencies:**
    Install the required 32-bit development libraries for OpenSSL, zlib, and crypt functions:

    ```bash
    sudo apt install build-essential gcc-multilib libssl-dev:i386 libcrypt-dev:i386 lib32z1-dev
    ```

## Compilation Steps

Once all prerequisites are installed and you've navigated to the Bahamut source directory, follow these commands:

1.  **Run `configure`:**
    This command prepares the project for compilation. The `CFLAGS="-m32"` flag tells the `configure` script to specifically prepare for a 32-bit build.

    ```bash
    CFLAGS="-m32" ./configure
    ```
    During this step, the `configure` script may ask you a series of questions (e.g., about maximum file descriptors, users, or enabling SSL/HUB mode). Answer these prompts as desired for your server setup.

2.  **Build the Project:**
    This command compiles the source code into executable binaries.

    ```bash
    make
    ```

3.  **Install Binaries (Optional):**
    If the compilation is successful, you can install the compiled binaries (the `ircd` executable and various tools) to their system-wide default locations:

    ```bash
    make install
    ```

---

Upon successful completion of these steps, your Bahamut IRCd should be compiled and ready for further configuration and deployment.
