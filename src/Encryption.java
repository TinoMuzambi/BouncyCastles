import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.Strings;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import java.security.GeneralSecurityException;
import java.security.Security;
import java.util.Arrays;

public class Encryption {
    public static SecretKey generateKey()
            throws GeneralSecurityException
    {
        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES", "BC");
        keyGenerator.init(256);
        return keyGenerator.generateKey();
    }

    public static byte[][] cbcEncrypt(SecretKey key, byte[] data)
            throws GeneralSecurityException {
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS7Padding", "BC");
        cipher.init(Cipher.ENCRYPT_MODE, key);
        return new byte[][]{cipher.getIV(), cipher.doFinal(data)};
    }

    public static byte[] cbcDecrypt(SecretKey key, byte[] iv, byte[] cipherText)
            throws GeneralSecurityException {
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS7Padding", "BC");
        cipher.init(Cipher.DECRYPT_MODE, key, new IvParameterSpec(iv));
        return cipher.doFinal(cipherText);
    }

    public static SecretKey defineKey(byte[] keyBytes) {
        if (keyBytes.length != 16 && keyBytes.length != 24 && keyBytes.length != 32) {
            throw new IllegalArgumentException("keyBytes wrong length for AES key");
        }
        return new SecretKeySpec(keyBytes, "AES");
    }

    /**
     * Install BC Fips provider.
     */
    public static void installProvider()
    {
        Security.addProvider(new BouncyCastleProvider());
    }

    public static void main(String[] args) throws GeneralSecurityException {
        installProvider();

        // Initialise and generation of key.
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

        // Decrypt Bob's message with secret key.
        byte[] bobDecryptedMsg = cbcDecrypt(secretKey, bobEncryptedMsg[0], bobEncryptedMsg[1]);
        System.out.println("Bob's decrypted message - " + Arrays.toString(bobDecryptedMsg));
    }
}
