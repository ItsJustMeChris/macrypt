# macrypt

**macrypt** is a Mach-O encrypter that includes a two-step integrity check process, supporting both dylib and executable (console) applications. It supports arm64 and x86_64 architectures and running under Rosetta(2). 

## Overview

This project consists of two components:

1. **hash_embedder**: This applet encrypts the `__TEXT.__text` section (code) of a Mach-O binary using a pseudorandom number generator (PRNG). It also embeds the expected FNV-1a hash into the program. **macrypt** supports both dylib and executable (console) applications.

2. **integrity_check**: This main runner decrypts itself at runtime and performs an FNV-1a hash over the runtime binary. It then compares this hash against both the embedded hash and the computed runtime hash. If there is any mismatch, the program will terminate.

### High-Level Overview of the macrypt Components

**macrypt** consists of two main components: `hash_embedder` and `integrity_check`. These components work together to provide encryption and runtime integrity verification for Mach-O binaries on macOS.

#### 1. **hash_embedder**
The `hash_embedder` is responsible for preparing the Mach-O binary for secure execution. It performs the following steps:

- **FNV-1a Hash Calculation**: It calculates an FNV-1a hash of the `__TEXT.__text` section (code section) of the binary. This hash is used later for integrity verification.
  
- **PRNG Encryption**: The `__TEXT.__text` section is encrypted using a simple pseudorandom number generator (PRNG) that rotates a small, static key. This adds a layer of obfuscation to the binary code, making it harder to reverse engineer.
  
- **Hash Embedding**: The computed hash is embedded into a specific section of the binary (`__DATA.__hash`). This embedded hash is used during runtime to verify the integrity of the binary.
  
- **Reordering Initialization Functions**: It also reorders certain initialization functions in the binary to ensure that the decryption logic runs as intended when the program starts.

#### 2. **integrity_check**
The `integrity_check` component is the runtime counterpart to `hash_embedder`. It handles the following tasks:

- **Self-Decryption**: Upon execution, the binary decrypts its `__TEXT.__text` section using the same PRNG key. This restores the original code, allowing the program to run as intended.
  
- **Runtime Hash Verification**: It calculates the FNV-1a hash of the runtime binary's `__TEXT.__text` section and compares it against the embedded hash. If the hashes match, it indicates that the binary has not been tampered with. If they do not match, the program terminates to prevent execution of potentially malicious code.
  
- **Ongoing Integrity Check**: The program continuously checks the integrity of its memory during execution to detect any tampering or modifications. If a mismatch is detected at any point, the program will terminate.

Together, these components provide a mechanism to protect Mach-O binaries by encrypting critical sections and verifying their integrity at runtime. This approach helps safeguard against unauthorized modifications or reverse engineering attempts.

## Caveats

- The embedded hash is easily detectable by a reverse engineer.
- The PRNG key is short and static.
- The binary must be codesigned after running `hash_embedder`.

## Areas for Improvement

- **Complexity of Embedded Hash**: Enhance the complexity of the embedded hash by incorporating a shuffle mechanism. This will make it more challenging for a reverse engineer to identify and alter the hash in memory, preventing them from simply modifying both the embedded and runtime hashes.

- **Obfuscation Techniques**: Implement opaque predicates and other obfuscation techniques to further complicate the decryption process. This will increase the difficulty of reverse engineering the binary.

- **Random Key Generation**: Introduce random key generation when running `hash_embedder` over the binary. For example, you could use a known terminator byte or embed the PRNG key length within the key itself, allocating a block of memory for an entirely random key. This approach would reduce predictability and enhance security.
