import java.io.*;
import java.nio.file.*;
import java.security.SecureRandom;
import java.util.Arrays;

public class Main {

    public static void main(String[] args) throws Exception {
        if (args.length < 1) { printUsage(); return; }
        switch (args[0].toLowerCase()) {
            case "hash":    hash(args);    break;
            case "mac":     mac(args);     break;
            case "encrypt": encrypt(args); break;
            case "decrypt": decrypt(args); break;
            default:
                System.err.println("Unknown command: " + args[0]);
                printUsage();
        }
    }

    // Usage: Main hash <file>
    private static void hash(String[] args) throws Exception {
        if (args.length < 2) {
            System.err.println("Usage: Main hash <file>");
            return;
        }
        byte[] data = Files.readAllBytes(Paths.get(args[1]));
        System.out.println("SHA-3-256: " + hex(SHA3SHAKE.SHA3(256, data, null)));
        System.out.println("SHA-3-512: " + hex(SHA3SHAKE.SHA3(512, data, null)));
    }

    // Usage: Main mac <file> <passphrase> <tagLengthBytes>
    private static void mac(String[] args) throws Exception {
        if (args.length < 4) {
            System.err.println("Usage: Main mac <file> <passphrase> <tagLengthBytes>");
            return;
        }
        byte[] data = Files.readAllBytes(Paths.get(args[1]));
        byte[] pass = args[2].getBytes("UTF-8");
        int tagLen = Integer.parseInt(args[3]);

        SHA3SHAKE s = new SHA3SHAKE();

        s.init(128);
        s.absorb(pass);
        s.absorb(data);
        System.out.println("SHAKE-128 MAC (" + tagLen + " bytes): " + hex(s.squeeze(tagLen)));

        s.init(256);
        s.absorb(pass);
        s.absorb(data);
        System.out.println("SHAKE-256 MAC (" + tagLen + " bytes): " + hex(s.squeeze(tagLen)));
    }

    // Usage: Main encrypt <inputFile> <outputFile> <passphrase>
    private static void encrypt(String[] args) throws Exception {
        if (args.length < 4) {
            System.err.println("Usage: Main encrypt <inputFile> <outputFile> <passphrase>");
            return;
        }
        byte[] plaintext = Files.readAllBytes(Paths.get(args[1]));
        byte[] pass = args[3].getBytes("UTF-8");

        // Derive 128-bit symmetric key from passphrase
        byte[] key = SHA3SHAKE.SHAKE(128, pass, 128, null);

        // Sample a random 128-bit nonce
        byte[] nonce = new byte[16];
        new SecureRandom().nextBytes(nonce);

        // Build keystream via SHAKE-128(nonce || key) and XOR with plaintext
        SHA3SHAKE sponge = new SHA3SHAKE();
        sponge.init(128);
        sponge.absorb(nonce);
        sponge.absorb(key);
        byte[] keystream = sponge.squeeze(plaintext.length);

        byte[] ciphertext = new byte[plaintext.length];
        for (int i = 0; i < plaintext.length; i++)
            ciphertext[i] = (byte) (plaintext[i] ^ keystream[i]);

        // Cryptogram layout: nonce (16 bytes) || ciphertext
        try (FileOutputStream fos = new FileOutputStream(args[2])) {
            fos.write(nonce);
            fos.write(ciphertext);
        }
        System.out.println("Encrypted: " + args[1] + " -> " + args[2]);
    }

    // Usage: Main decrypt <inputFile> <outputFile> <passphrase>
    private static void decrypt(String[] args) throws Exception {
        if (args.length < 4) {
            System.err.println("Usage: Main decrypt <inputFile> <outputFile> <passphrase>");
            return;
        }
        byte[] cryptogram = Files.readAllBytes(Paths.get(args[1]));
        byte[] pass = args[3].getBytes("UTF-8");

        if (cryptogram.length < 16) {
            System.err.println("Error: cryptogram too short to contain a nonce.");
            return;
        }

        // Derive 128-bit symmetric key from passphrase
        byte[] key = SHA3SHAKE.SHAKE(128, pass, 128, null);

        // Extract nonce and ciphertext from cryptogram
        byte[] nonce = Arrays.copyOfRange(cryptogram, 0, 16);
        byte[] ciphertext = Arrays.copyOfRange(cryptogram, 16, cryptogram.length);

        // Rebuild the same keystream and XOR to recover plaintext
        SHA3SHAKE sponge = new SHA3SHAKE();
        sponge.init(128);
        sponge.absorb(nonce);
        sponge.absorb(key);
        byte[] keystream = sponge.squeeze(ciphertext.length);

        byte[] plaintext = new byte[ciphertext.length];
        for (int i = 0; i < ciphertext.length; i++)
            plaintext[i] = (byte) (ciphertext[i] ^ keystream[i]);

        Files.write(Paths.get(args[2]), plaintext);
        System.out.println("Decrypted: " + args[1] + " -> " + args[2]);
    }

    private static String hex(byte[] b) {
        StringBuilder sb = new StringBuilder(b.length * 2);
        for (byte x : b) sb.append(String.format("%02x", x));
        return sb.toString();
    }

    private static void printUsage() {
        System.out.println("Usage:");
        System.out.println("  Main hash    <file>");
        System.out.println("  Main mac     <file> <passphrase> <tagLengthBytes>");
        System.out.println("  Main encrypt <inputFile> <outputFile> <passphrase>");
        System.out.println("  Main decrypt <inputFile> <outputFile> <passphrase>");
    }
}
