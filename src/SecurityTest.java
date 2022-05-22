import org.bouncycastle.jce.provider.BouncyCastleProvider;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.security.*;
import java.security.spec.RSAKeyGenParameterSpec;
import java.util.Arrays;

public class SecurityTest {
    public static KeyPair generateKeyPair() throws GeneralSecurityException {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA", "BC");
        keyPairGenerator.initialize(new RSAKeyGenParameterSpec(3072, RSAKeyGenParameterSpec.F4));
        return keyPairGenerator.generateKeyPair();
    }

    public static byte[] generateX931Signature(PrivateKey rsaPrivate, byte[] input)
            throws GeneralSecurityException
    {
        Signature signature = Signature.getInstance("SHA384withRSA/X9.31", "BC");
        signature.initSign(rsaPrivate);
        signature.update(input);
        return signature.sign();
    }
    public static boolean verifyX931Signature(PublicKey rsaPublic, byte[] input, byte[] encSignature)
            throws GeneralSecurityException
    {
        Signature signature = Signature.getInstance("SHA384withRSA/X9.31", "BC");
        signature.initVerify(rsaPublic);
        signature.update(input);
        return signature.verify(encSignature);
    }

    public static byte[] ecbEncrypt(SecretKey key, byte[] data)
            throws GeneralSecurityException
    {
        Cipher cipher = Cipher.getInstance("AES/ECB/PKCS1Padding", "BC");
        cipher.init(Cipher.ENCRYPT_MODE, key);
        return cipher.doFinal(data);
    }
    public static byte[] ecbDecrypt(SecretKey key, byte[] cipherText)
            throws GeneralSecurityException
    {
        Cipher cipher = Cipher.getInstance("AES/ECB/PKCS1Padding", "BC");
        cipher.init(Cipher.DECRYPT_MODE, key);
        return cipher.doFinal(cipherText);
    }

    public static SecretKey defineKey(byte[] keyBytes)
    {
        if (keyBytes.length != 16 && keyBytes.length != 24 && keyBytes.length != 32)
        {
            throw new IllegalArgumentException("keyBytes wrong length for AES key");
        }
        return new SecretKeySpec(keyBytes, "AES");
    }

    public static void main(String[] args) {
        // Add BouncyCastleProvider.
        Security.addProvider(new BouncyCastleProvider());

        // Initialise sender/receiver keys.
        KeyPair anneKeys;
        KeyPair bobKeys;
        try {
            // Generation of sender/receiver public and private keys.
            anneKeys = generateKeyPair();
            System.out.println("Anne's public key - " + anneKeys.getPublic());
            System.out.println("Anne's private key - " + anneKeys.getPrivate());

            bobKeys = generateKeyPair();
            System.out.println("Bob's public key - " + bobKeys.getPublic());
            System.out.println("Bob's private key - " + bobKeys.getPrivate());

            // The below represents hashing. This provides us with message integrity
            // Generate Anne's message.
            byte[] anneMsg = new byte[4];
            anneMsg[0]=20;
            anneMsg[1]=10;
            anneMsg[2]=5;
            anneMsg[3]=30;
            System.out.println("Anne's unsigned message - " + Arrays.toString(anneMsg));

            // Sign Anne's message with Anne's private key.
            byte[] anneSignedMsg = generateX931Signature(anneKeys.getPrivate(), anneMsg);
            System.out.println("Anne's signed message - " + Arrays.toString(anneSignedMsg));

            // Verify Anne's message with Anne's public key.
            boolean bobReceivesAnneMsg = verifyX931Signature(anneKeys.getPublic(), anneMsg, anneSignedMsg);
            System.out.println("Bob successfully verified Anne's message - " + bobReceivesAnneMsg);

            // The below represents encryption. This provides us with message authentication.
            // Generate Bob's message.
            byte[] bobMsg = new byte[4];
            bobMsg[0] = 4;
            bobMsg[1] = 16;
            bobMsg[2] = 8;
            bobMsg[3] = 0;
            System.out.println("Bob's unencrypted message - " + Arrays.toString(bobMsg));

            // Encrypt Bob's message with Anne's public key.
            byte[] bobEncryptedMsg = ecbEncrypt(defineKey(anneKeys.getPublic().getEncoded()), bobMsg);
            System.out.println("Bob's encrypted message - " + Arrays.toString(bobEncryptedMsg));
        } catch (GeneralSecurityException e) {
            System.out.println(e);
        }
    }
}
