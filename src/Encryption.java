import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.GeneralSecurityException;
import java.util.Arrays;

public class Encryption {
    public static byte[][] cbcEncrypt(SecretKey key, byte[] data)
            throws GeneralSecurityException
    {
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding", "BC");
        cipher.init(Cipher.ENCRYPT_MODE, key);
        return new byte[][] { cipher.getIV(), cipher.doFinal(data) };}

    public static byte[] cbcDecrypt(SecretKey key, byte[] iv, byte[] cipherText)
            throws GeneralSecurityException
    {
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding", "BC");
        cipher.init(Cipher.DECRYPT_MODE, key, new IvParameterSpec(iv));
        return cipher.doFinal(cipherText);
    }

    public static SecretKey defineKey(byte[] keyBytes)
    {
        System.out.println("Length - " + keyBytes.length);
        if (keyBytes.length != 16 && keyBytes.length != 24 && keyBytes.length != 32)
        {
            throw new IllegalArgumentException("keyBytes wrong length for AES key");
        }
        return new SecretKeySpec(keyBytes, "AES");
    }

    public static void main(String[] args) {
        try {
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
            System.out.println("Bob's encrypted message - " + Arrays.toString(bobEncryptedMsg));
        } catch (GeneralSecurityException e) {
            System.out.println(e);
        }
    }
}
