import org.bouncycastle.util.Strings;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.security.*;
import java.security.spec.RSAKeyGenParameterSpec;
import java.util.Arrays;
import java.util.zip.DeflaterOutputStream;
import java.util.zip.InflaterOutputStream;

/**
 * A class for testing the hashing and signing flow.
 */
public class Hashing {
    /**
     * Generates a private/public key pair using RSA and a key size of 3072.
     * @return A private/public key pair.
     * @throws GeneralSecurityException in case of security errors.
     */
    public static KeyPair generateKeyPair() throws GeneralSecurityException {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA", "BCFIPS");
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
        Signature signature = Signature.getInstance("SHA384withRSA", "BCFIPS");

        signature.initSign(rsaPrivate);

        signature.update(input);

        return signature.sign();
    }

    /**
     * Verify a signature using the PKCS#1.5 Signature Format.
     * @param rsaPublic The public key to verify with.
     * @param input The data you want to verify.
     * @param encSignature The data you're verifying against.
     * @return True if the data is valid, false otherwise.
     * @throws GeneralSecurityException in case of security errors.
     */
    public static boolean verifyPkcs1Signature(PublicKey rsaPublic, byte[] input, byte[] encSignature)
            throws GeneralSecurityException
    {
        Signature signature = Signature.getInstance("SHA384withRSA", "BCFIPS");

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
        MessageDigest hash = MessageDigest.getInstance("SHA3-512", "BCFIPS");

        return hash.digest(data);
    }

    /**
     * Compresses data using ZIP.
     * @param data The data you want to compress.
     * @return The compressed data.
     * @throws IOException In case of errors in compression.
     */
    public static byte[] compressData(byte[] data) throws IOException {
            ByteArrayOutputStream out = new ByteArrayOutputStream();
            DeflaterOutputStream defl = new DeflaterOutputStream(out);
            defl.write(data);
            defl.flush();
            defl.close();

            return out.toByteArray();
    }

    /**
     * Main method for testing the hashing and signing flow.
     * @param args Command line arguments.
     * @throws IOException Input output exceptions.
     * @throws GeneralSecurityException Security errors.
     */
    public static void main(String[] args) throws GeneralSecurityException, IOException {
        Utils.installProvider();

        // Initialise and generate sender/receiver keys.
        KeyPair anneKeys = generateKeyPair();
        System.out.println("Anne's public key - " + anneKeys.getPublic());
        System.out.println("Anne's private key - " + anneKeys.getPrivate());

        KeyPair bobKeys = generateKeyPair();
        System.out.println("Bob's public key - " + bobKeys.getPublic());
        System.out.println("Bob's private key - " + bobKeys.getPrivate());

        // Generate Anne's message.
        byte[] anneMsg = Strings.toByteArray("Houston, we are hidden.");
        System.out.println("Anne's unsigned message - " + Arrays.toString(anneMsg));

        // 3. Compress Anne's message.
        byte[] anneMsgCompressed = compressData(anneMsg);
        System.out.println("Anne's unsigned compressed message - " + Arrays.toString(anneMsgCompressed));

        // 3. Hash Anne's compressed message.
        byte[] anneMsgHashedCompressed = calculateSha3Digest(anneMsgCompressed);
        System.out.println("Anne's unsigned hashed compressed message - " + Arrays.toString(anneMsgHashedCompressed));

        // 4. Sign Anne's message with Anne's private key.
        byte[] anneSignedMsg = generatePkcs1Signature(anneKeys.getPrivate(), anneMsgHashedCompressed);
        System.out.println("Anne's signed message - " + Arrays.toString(anneSignedMsg));

        // 5. Combine Anne's signed message with the original message.
        byte[][] anneSignedMsgDigest = {anneSignedMsg, anneMsg};
        System.out.println("Anne's signed message digest - " + Arrays.toString(anneSignedMsgDigest));

        // Imagine message has been sent securely to Bob.

        // 15. Compress message portion.
        byte[] anneComparisonCompressed = compressData(anneSignedMsgDigest[1]);
        System.out.println("Anne's received message compressed - " + Arrays.toString(anneComparisonCompressed));

        // 15. Hash compressed message.
        byte[] anneComparisonHash = calculateSha3Digest(anneComparisonCompressed);
        System.out.println("Anne's received message hashed - " + Arrays.toString(anneComparisonHash));

        // 16. Verify Anne's message with Anne's public key.
        boolean bobReceivesAnneMsg = verifyPkcs1Signature(anneKeys.getPublic(), anneComparisonHash, anneSignedMsgDigest[0]);
        System.out.println("Bob successfully verified Anne's message - " + bobReceivesAnneMsg);
    }
}
