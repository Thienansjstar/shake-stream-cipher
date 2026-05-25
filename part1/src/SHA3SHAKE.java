/*
 * TCSS 487 Cryptography - Practical Project Part 1
 * Author: Thienan Tran
 *
 * SHA3SHAKE: a plain (non-duplexing) sponge implementation of the SHA-3 family
 * of hash functions and the SHAKE extendable-output functions, as specified in
 * FIPS 202 (https://doi.org/10.6028/NIST.FIPS.202).
 *
 * the Keccak-f[1600] permutation, round-constant table, rho
 * rotation offsets, and pi lane-permutation table below are ported, with
 * minor adaptations, from Markku-Juhani O. Saarinen's public-domain C
 * reference implementation "tiny_sha3":
 *   https://github.com/mjosaarinen/tiny_sha3/blob/master/sha3.c
 /// (The tiny_sha3 code is also available in the project repo for reference.)
 */
public class SHA3SHAKE {

    /** 25 lanes of 64 bits = 1600-bit Keccak state. */
    private final long[] st = new long[25];
    /** Sponge rate, in bytes (0 means "uninitialized"). */
    private int rateBytes;
    /** Configured suffix (128, 224, 256, 384, 512); 0 means "uninitialized". */
    private int suffix;
    /** Byte position within the current rate block during absorb/squeeze. */
    private int pt;
    /** false during absorb phase, true once finalized and squeezing. */
    private boolean squeezing;
    /** Cached digest bytes for repeated digest() calls within one epoch. */
    private byte[] digestCache;

    public SHA3SHAKE() {  }

    // Constants

    private static final long[] RC = {
        0x0000000000000001L, 0x0000000000008082L, 0x800000000000808aL,
        0x8000000080008000L, 0x000000000000808bL, 0x0000000080000001L,
        0x8000000080008081L, 0x8000000000008009L, 0x000000000000008aL,
        0x0000000000000088L, 0x0000000080008009L, 0x000000008000000aL,
        0x000000008000808bL, 0x800000000000008bL, 0x8000000000008089L,
        0x8000000000008003L, 0x8000000000008002L, 0x8000000000000080L,
        0x000000000000800aL, 0x800000008000000aL, 0x8000000080008081L,
        0x8000000000008080L, 0x0000000080000001L, 0x8000000080008008L
    };


    private static final int[] ROTC = {
         1,  3,  6, 10, 15, 21, 28, 36, 45, 55,  2, 14,
        27, 41, 56,  8, 25, 43, 62, 18, 39, 61, 20, 44
    };

    private static final int[] PILN = {
        10,  7, 11, 17, 18,  3,  5, 16,  8, 21, 24,  4,
        15, 23, 19, 13, 12,  2, 20, 14, 22,  9,  6,  1
    };

    /** 64-bit left-rotate. */
    private static long rotl64(long x, int n) {
        return (x << n) | (x >>> (64 - n));
    }

    /**
     * The 24-round Keccak-f[1600] permutation. Theta, Rho+Pi, Chi, Iota.
     * (Adapted from tiny_sha3.)
     */
    private static void keccakF(long[] s) {
        long[] bc = new long[5];
        for (int r = 0; r < 24; r++) {
            // Theta
            for (int i = 0; i < 5; i++) {
                bc[i] = s[i] ^ s[i + 5] ^ s[i + 10] ^ s[i + 15] ^ s[i + 20];
            }
            for (int i = 0; i < 5; i++) {
                long t = bc[(i + 4) % 5] ^ rotl64(bc[(i + 1) % 5], 1);
                for (int j = 0; j < 25; j += 5) {
                    s[j + i] ^= t;
                }
            }
            // Rho + Pi
            long t = s[1];
            for (int i = 0; i < 24; i++) {
                int j = PILN[i];
                long tmp = s[j];
                s[j] = rotl64(t, ROTC[i]);
                t = tmp;
            }
            // Chi
            for (int j = 0; j < 25; j += 5) {
                for (int i = 0; i < 5; i++) bc[i] = s[j + i];
                for (int i = 0; i < 5; i++) {
                    s[j + i] ^= (~bc[(i + 1) % 5]) & bc[(i + 2) % 5];
                }
            }
            // Iota
            s[0] ^= RC[r];
        }
    }

    //helpers
    /**
     * XOR a single byte into the Keccak state at the given byte index. The
     * state is treated as 25 little-endian 64-bit lanes (FIPS 202 §3.1.2).
     */
    private void xorByteIntoState(int byteIndex, byte b) {
        int lane = byteIndex >>> 3;
        int shift = (byteIndex & 7) << 3;
        st[lane] ^= (((long) b) & 0xFFL) << shift;
    }

    /** Read a byte out of the Keccak state at the given byte index. */
    private byte readByteFromState(int byteIndex) {
        int lane = byteIndex >>> 3;
        int shift = (byteIndex & 7) << 3;
        return (byte) ((st[lane] >>> shift) & 0xFFL);
    }

    /**
     * Switch the sponge into squeezing mode by applying the appropriate
     * pad10*1 padding for either SHA-3 (domByte=0x06) or SHAKE
     * (domByte=0x1F), permuting once, and resetting the read pointer.
     */
    private void finalizePadding(byte domByte) {
        if (suffix == 0) {
            throw new IllegalStateException("init() must be called first.");
        }
        // pad10*1: append domain bits at position pt, set top bit of last
        // rate byte.
        xorByteIntoState(pt, domByte);
        xorByteIntoState(rateBytes - 1, (byte) 0x80);
        keccakF(st);
        pt = 0;
        squeezing = true;
    }

   /**
* Initialize the SHA-3/SHAKE sponge.
* The suffix must be one of 224, 256, 384, or 512 for SHA-3, or one of 128 or 256 for SHAKE.
* @param suffix SHA-3/SHAKE suffix (SHA-3 digest bitlength = suffix, SHAKE sec level =
suffix)
*/
    public void init(int suffix) {
        // Capacity c = 2 * suffix bits; rate r = 1600 - c bits.
        switch (suffix) {
            case 128: this.rateBytes = (1600 - 256) / 8; break; // 168
            case 224: this.rateBytes = (1600 - 448) / 8; break; // 144
            case 256: this.rateBytes = (1600 - 512) / 8; break; // 136
            case 384: this.rateBytes = (1600 - 768) / 8; break; // 104
            case 512: this.rateBytes = (1600 -1024) / 8; break; // 72
            default:
                throw new IllegalArgumentException(
                    "suffix must be one of 128, 224, 256, 384, 512; got " + suffix);
        }
        this.suffix = suffix;
        this.pt = 0;
        this.squeezing = false;
        this.digestCache = null;
        for (int i = 0; i < 25; i++) st[i] = 0L;
    }

    /**
     * Update the SHAKE sponge with a byte-oriented data chunk.
     * @param data byte-oriented data buffer
     * @param pos initial index to hash from
     * @param len byte count on the buffer
     */
    public void absorb(byte[] data, int pos, int len) {
        if (suffix == 0) {
            throw new IllegalStateException("init() must be called first.");
        }
        if (squeezing) {
            throw new IllegalStateException(
                "absorb() not allowed after squeeze()/digest(); call init() first.");
        }
        if (data == null) throw new NullPointerException("data");
        if (pos < 0 || len < 0 || pos + len > data.length) {
            throw new IndexOutOfBoundsException(
                "pos=" + pos + ", len=" + len + ", data.length=" + data.length);
        }
        for (int i = 0; i < len; i++) {
            xorByteIntoState(pt, data[pos + i]);
            pt++;
            if (pt == rateBytes) {
                keccakF(st);
                pt = 0;
            }
        }
    }

    /**
     * Update the SHAKE sponge with a byte-oriented data chunk.
     * @param data byte-oriented data buffer
     * @param len byte count on the buffer (starting at index 0)
     */
    public void absorb(byte[] data, int len) {
        absorb(data, 0, len);
    }

    /**
     * Update the SHAKE sponge with a byte-oriented data chunk.
     * @param data byte-oriented data buffer
     */
    public void absorb(byte[] data) {
        absorb(data, 0, data.length);
    }

    /**
     *  Squeeze a chunk of hashed bytes from the sponge.
     * Call this method as many times as needed to extract the total desired number of bytes.    
     *
     * @param out hash value buffer
     * @param len desired number of squeezed bytes
     * @return the val buffer containing the desired hash value
     */
    public byte[] squeeze(byte[] out, int len) {
        if (suffix == 0) {
            throw new IllegalStateException("init() must be called first.");
        }
        if (out == null) throw new NullPointerException("out");
        if (len < 0 || len > out.length) {
            throw new IndexOutOfBoundsException(
                "len=" + len + ", out.length=" + out.length);
        }
        if (!squeezing) {
            // First squeeze: apply SHAKE padding (0x1F) and permute.
            finalizePadding((byte) 0x1F);
        }
        for (int i = 0; i < len; i++) {
            if (pt == rateBytes) {
                keccakF(st);
                pt = 0;
            }
            out[i] = readByteFromState(pt);
            pt++;
        }
        return out;
    }

    /**
     * Squeeze a chunk of hashed bytes from the sponge.
     * Call this method as many times as needed to extract the total desired number of bytes.
     * @param len desired number of squeezed bytes
     * @return newly allocated buffer containing the desired hash value
     */
    public byte[] squeeze(int len) {
        return squeeze(new byte[len], len);
    }

    /**
     * Squeeze a whole SHA-3 digest of hashed bytes from the sponge.
     * @param out hash value buffer
     * @return the val buffer containing the desired hash value      
     */
    public byte[] digest(byte[] out) {
        if (suffix == 0) {
            throw new IllegalStateException("init() must be called first.");
        }
        if (suffix == 128) {
            throw new IllegalStateException(
                "digest() is not defined for SHAKE-128; use squeeze() instead.");
        }
        int dlen = suffix / 8;
        if (out == null) throw new NullPointerException("out");
        if (out.length < dlen) {
            throw new IndexOutOfBoundsException(
                "out.length=" + out.length + " < required " + dlen);
        }
        if (digestCache == null) {
            // First digest in this epoch: finalize with SHA-3 padding.
            if (squeezing) {
                throw new IllegalStateException(
                    "digest() not allowed after squeeze() in same epoch; call init() first.");
            }
            finalizePadding((byte) 0x06);
            digestCache = new byte[dlen];
            for (int i = 0; i < dlen; i++) {
                digestCache[i] = readByteFromState(i);
            }
    
        }
        System.arraycopy(digestCache, 0, out, 0, dlen);
        return out;
    }

    /**
     * Squeeze a whole SHA-3 digest of hashed bytes from the sponge.
     * @return the desired hash value on a newly allocated byte array
     */
    public byte[] digest() {
        if (suffix == 0) {
            throw new IllegalStateException("init() must be called first.");
        }
        if (suffix == 128) {
            throw new IllegalStateException(
                "digest() is not defined for SHAKE-128; use squeeze() instead.");
        }
        return digest(new byte[suffix / 8]);
    }

    // static helpers

    /**
     * Compute the streamlined SHA-3-<224,256,384,512> on input X.
     *
     * @param suffix desired output length in bits (one of 224, 256, 384, 512)
     * @param X data to be hashed
     * @param out hash value buffer (if null, this method allocates it with the required size)
     * @return the out buffer containing the desired hash value.
     */
    public static byte[] SHA3(int suffix, byte[] X, byte[] out) {
        if (suffix != 224 && suffix != 256 && suffix != 384 && suffix != 512) {
            throw new IllegalArgumentException(
                "SHA3 suffix must be 224, 256, 384, or 512; got " + suffix);
        }
        int dlen = suffix / 8;
        if (out == null) out = new byte[dlen];
        SHA3SHAKE s = new SHA3SHAKE();
        s.init(suffix);
        if (X != null && X.length > 0) s.absorb(X);
        return s.digest(out);
    }

    /**
     * Compute the streamlined SHAKE-<128,256> on input X with output bitlength L.
     * @param suffix desired output length in bits (one of 224, 256, 384, 512)
     * @param X data to be hashed
     * @param L desired output length in bits (must be a multiple of 8)
     * @param out hash value buffer (if null, this method allocates it with the required size)
     * @return the out buffer containing the desired hash value.
     */
    public static byte[] SHAKE(int suffix, byte[] X, int L, byte[] out) {
        if (suffix != 128 && suffix != 256) {
            throw new IllegalArgumentException(
                "SHAKE suffix must be 128 or 256; got " + suffix);
        }
        if (L < 0 || (L & 7) != 0) {
            throw new IllegalArgumentException(
                "L must be a non-negative multiple of 8; got " + L);
        }
        int outLen = L / 8;
        if (out == null) out = new byte[outLen];
        SHA3SHAKE s = new SHA3SHAKE();
        s.init(suffix);
        if (X != null && X.length > 0) s.absorb(X);
        return s.squeeze(out, outLen);
    }
}
