# shake-stream-cipher

A pure-Java cryptographic library built on the SHA-3/SHAKE (Keccak) sponge construction, as specified in [FIPS 202](https://doi.org/10.6028/NIST.FIPS.202). No external cryptographic libraries — everything is implemented from scratch on top of the Keccak-f[1600] permutation.

## Services

| Command    | Description |
|------------|-------------|
| `hash`     | SHA-3-256 and SHA-3-512 digest of a file |
| `mac`      | SHAKE-128 and SHAKE-256 authentication tag (MAC) |
| `encrypt`  | SHAKE-128 stream cipher encryption |
| `decrypt`  | SHAKE-128 stream cipher decryption |

## Build & Run

```bash
cd src/
javac SHA3SHAKE.java Main.java
```

```
java Main <command> [arguments...]
```

### Hash a file

```bash
java Main hash <file>
```

### Generate a MAC

```bash
java Main mac <file> <passphrase> <tagLengthBytes>
```

### Encrypt / Decrypt

```bash
java Main encrypt <inputFile> <outputFile> <passphrase>
java Main decrypt <inputFile> <outputFile> <passphrase>
```

## How it works

- **Sponge core** — `SHA3SHAKE.java` implements a plain non-duplexing sponge over Keccak-f[1600]. Rate and capacity are set by the mode (SHAKE-128: 168/32 bytes, SHA-3-256: 136/64 bytes, SHA-3-512: 72/128 bytes, etc.).
- **Stream cipher** — encryption derives a 128-bit key from the passphrase via SHAKE-128, generates a random 128-bit nonce, then XORs a SHAKE-128 keystream (seeded with nonce ∥ key) against the plaintext. The cryptogram format is `nonce ∥ ciphertext`.
- **MAC** — the sponge absorbs `passphrase ∥ file` and squeezes the requested number of bytes.

## Attribution

The Keccak-f[1600] permutation constants (round-constant table, rho offsets, pi lane permutation) are ported from Markku-Juhani O. Saarinen's public-domain C implementation [tiny_sha3](https://github.com/mjosaarinen/tiny_sha3). All sponge wrappers, padding logic, and the Java interface are original work.
