import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.Strings;

import java.security.*;
import java.security.spec.RSAKeyGenParameterSpec;
import java.util.Arrays;

public class Hashing {
    /**
     * Generates a private/public key pair using RSA and a key size of 3072.
     * @return A private/public key pair.
     * @throws GeneralSecurityException in case of security errors.
     */
    public static KeyPair generateKeyPair() throws GeneralSecurityException {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA", "BC");
        keyPairGenerator.initialize(new RSAKeyGenParameterSpec(3072, RSAKeyGenParameterSpec.F4));
        return keyPairGenerator.generateKeyPair();
    }

    /**
     * Generate a signature using the PKCS#1.5 Signature Format.
     * @param rsaPrivate The private key to sign with.
     * @param input The data you want to sign.
     * @return A byte array containing the signed data.
     * @throws GeneralSecurityException in case of security errors.
     */
    public static byte[] generatePkcs1Signature(PrivateKey rsaPrivate, byte[] input)
            throws GeneralSecurityException
    {
        Signature signature = Signature.getInstance("SHA384withRSA", "BC");

        signature.initSign(rsaPrivate);

        signature.update(input);

        return signature.sign();
    }

    /**
     * Verify a signature using the PKCS#1.5 Signature Format.
     * @param rsaPublic The public key to verify with.
     * @param input The data you want to verify.
     * @return True if the data is valid, false otherwise.
     * @throws GeneralSecurityException in case of security errors.
     */
    public static boolean verifyPkcs1Signature(PublicKey rsaPublic, byte[] input, byte[] encSignature)
            throws GeneralSecurityException
    {
        Signature signature = Signature.getInstance("SHA384withRSA", "BC");

        signature.initVerify(rsaPublic);

        signature.update(input);

        return signature.verify(encSignature);
    }

    /**
     * Compute and return a hash of a message using the SHA-3 algorithm.
     * @param data The data we want to hash.
     * @return The hashed data.
     * @throws GeneralSecurityException in case of security errors.
     */
    public static byte[] calculateSha3Digest(byte[] data)
            throws GeneralSecurityException
    {
        MessageDigest hash = MessageDigest.getInstance("SHA3-512", "BC");

        return hash.digest(data);
    }

    /**
     * Install Bouncy Castle provider.
     */
    public static void installProvider()
    {
        Security.addProvider(new BouncyCastleProvider());
    }

    public static void main(String[] args) throws GeneralSecurityException {
        installProvider();

        // Initialise and generate sender/receiver keys.
        KeyPair anneKeys = generateKeyPair();
        System.out.println("Anne's public key - " + anneKeys.getPublic());
        System.out.println("Anne's private key - " + anneKeys.getPrivate());

        KeyPair bobKeys = generateKeyPair();
        System.out.println("Bob's public key - " + bobKeys.getPublic());
        System.out.println("Bob's private key - " + bobKeys.getPrivate());

        // The below represents hashing. This provides us with message integrity
        // Generate Anne's message.
        byte[] anneMsg = Strings.toByteArray("Houston, we are hidden.");
        System.out.println("Anne's unsigned message - " + Arrays.toString(anneMsg));

        // Hash Anne's message.
        byte[] anneMsgHashed = calculateSha3Digest(anneMsg);
        System.out.println("Anne's unsigned hashed message - " + Arrays.toString(anneMsgHashed));

        // Sign Anne's message with Anne's private key.
        byte[] anneSignedMsg = generatePkcs1Signature(anneKeys.getPrivate(), anneMsgHashed);
        System.out.println("Anne's signed message - " + Arrays.toString(anneSignedMsg));

        // Verify Anne's message with Anne's public key.
        boolean bobReceivesAnneMsg = verifyPkcs1Signature(anneKeys.getPublic(), anneMsg, anneSignedMsg);
        System.out.println("Bob successfully verified Anne's message - " + bobReceivesAnneMsg);
    }
}
