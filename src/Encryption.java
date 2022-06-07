import org.bouncycastle.util.Strings;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.util.Arrays;

public class Encryption {
    /**
     * Generates a key using AES with 256 key size.
     * @return An AES key with 256 key size.
     * @throws GeneralSecurityException in case of security errors.
     */
    public static SecretKey generateKey()
            throws GeneralSecurityException
    {
        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES", "BCFIPS");
        keyGenerator.init(256);
        return keyGenerator.generateKey();
    }

    /**
     * Encrypts a byte array using Cipher Block Chaining mode.
     * @param key The key to be used for the encryption.
     * @param data The data you want to encrypt.
     * @return A 2D array with the first element being the IV and the second the encrypted data.
     * @throws GeneralSecurityException in case of security errors.
     */
    public static byte[][] cbcEncrypt(SecretKey key, byte[] data)
            throws GeneralSecurityException {
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS7Padding", "BCFIPS");
        cipher.init(Cipher.ENCRYPT_MODE, key);
        return new byte[][]{cipher.getIV(), cipher.doFinal(data)};
    }

    /**
     * Decrypts a byte array using Cipher Block Chaining mode.
     * @param key The key to be used for the decryption.
     * @param iv The initialisation vector to be used.
     * @param cipherText The data you want to decrypt.
     * @return A byte array containing the decrypted data.
     * @throws GeneralSecurityException in case of security errors.
     */
    public static byte[] cbcDecrypt(SecretKey key, byte[] iv, byte[] cipherText)
            throws GeneralSecurityException {
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS7Padding", "BCFIPS");
        cipher.init(Cipher.DECRYPT_MODE, key, new IvParameterSpec(iv));
        return cipher.doFinal(cipherText);
    }

    /**
     * Converts a key's bytes to a SecurityKey.
     * @param keyBytes The encoded key you want to convert.
     * @return A SecretKey from the encoded key provided.
     */
    public static SecretKey defineKey(byte[] keyBytes) {
        if (keyBytes.length != 16 && keyBytes.length != 24 && keyBytes.length != 32) {
            throw new IllegalArgumentException("keyBytes wrong length for AES key");
        }
        return new SecretKeySpec(keyBytes, "AES");
    }


    /**
     * Main method for testing the encryption flow.
     * @param args Command line arguments.
     * @throws GeneralSecurityException Security errors.
     */
    public static void main(String[] args) throws GeneralSecurityException {
        Utils.installProvider();

        // Initialise and generate a key.
        defineKey(new byte[128 / 8]);
        defineKey(new byte[192 / 8]);
        defineKey(new byte[256 / 8]);
        SecretKey secretKey = generateKey();

        System.out.println("Secret key - " + secretKey.toString());

        // The below represents encryption. This provides us with message authentication.
        // Generate Bob's message.
        byte[] bobMsg = Strings.toByteArray("Houston, we have a landing");
        System.out.println("Bob's plaintext message - " + Arrays.toString(bobMsg));

        // Encrypt Bob's message with secret key.
        byte[][] bobEncryptedMsg = cbcEncrypt(secretKey, bobMsg);
        System.out.println("Bob's encrypted message - " + Arrays.toString(bobEncryptedMsg[1]));

        // Imagine that it's been securely sent to Anne.

        // Decrypt Bob's message with secret key.
        byte[] bobDecryptedMsg = cbcDecrypt(secretKey, bobEncryptedMsg[0], bobEncryptedMsg[1]);
        System.out.println("Bob's decrypted message - " + Arrays.toString(bobDecryptedMsg));
    }
}
