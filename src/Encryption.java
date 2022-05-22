import org.bouncycastle.jce.provider.BouncyCastleProvider;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Security;
import java.security.spec.RSAKeyGenParameterSpec;
import java.util.Arrays;

public class Encryption {
    public static KeyPair generateKeyPair() throws GeneralSecurityException {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA", "BC");
        keyPairGenerator.initialize(new RSAKeyGenParameterSpec(20, RSAKeyGenParameterSpec.F4));
        return keyPairGenerator.generateKeyPair();
    }

    public static byte[][] cbcEncrypt(SecretKey key, byte[] data)
            throws GeneralSecurityException {
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding", "BC");
        cipher.init(Cipher.ENCRYPT_MODE, key);
        return new byte[][]{cipher.getIV(), cipher.doFinal(data)};
    }

    public static byte[] cbcDecrypt(SecretKey key, byte[] iv, byte[] cipherText)
            throws GeneralSecurityException {
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding", "BC");
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
     * Flattens a uniform 2D array into a 1D array
     *
     * @param array The uniform 2D array to flatten
     * @return The flattened 1D array
     */
    public static byte[] flatten2DArray(byte[][] array) {

        byte[] flattenedArray = new byte[array.length * array[0].length];
        for (int i = 0; i < array.length; i++) {
            System.arraycopy(array[i], 0, flattenedArray, i * array[0].length, array[0].length);
        }
        return flattenedArray;

    }

    public static void main(String[] args) throws GeneralSecurityException {
        // Add BouncyCastleProvider.
        Security.addProvider(new BouncyCastleProvider());

        // Initialise sender/receiver keys.
        KeyPair anneKeys;
        KeyPair bobKeys;

        // Generation of sender/receiver public and private keys.
        anneKeys = generateKeyPair();
        System.out.println("Anne's public key - " + anneKeys.getPublic());
        System.out.println("Anne's private key - " + anneKeys.getPrivate());

        bobKeys = generateKeyPair();
        System.out.println("Bob's public key - " + bobKeys.getPublic());
        System.out.println("Bob's private key - " + bobKeys.getPrivate());

        // The below represents encryption. This provides us with message authentication.
        // Generate Bob's message.
        byte[] bobMsg = new byte[4];
        bobMsg[0] = 4;
        bobMsg[1] = 16;
        bobMsg[2] = 8;
        bobMsg[3] = 0;
        System.out.println("Bob's unencrypted message - " + Arrays.toString(bobMsg));

        // Encrypt Bob's message with Anne's public key.
        byte[][] bobEncryptedMsg = cbcEncrypt(defineKey(anneKeys.getPublic().getEncoded()), bobMsg);
        System.out.println("Bob's encrypted message - " + Arrays.toString(flatten2DArray(bobEncryptedMsg)));

        // Decrypt Bob's message with Anne's private key.
        byte[] iv = new byte[2];
        iv[0] = 20;
        iv[1] = 4;
        byte[] bobDecryptedMsg = cbcDecrypt(defineKey(anneKeys.getPrivate().getEncoded()), iv, flatten2DArray(bobEncryptedMsg));
        System.out.println("Bob's decrypted message - " + Arrays.toString(bobDecryptedMsg));
    }
}
