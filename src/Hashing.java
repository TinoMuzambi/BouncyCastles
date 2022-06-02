import org.bouncycastle.jcajce.provider.BouncyCastleFipsProvider;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.Strings;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.security.*;
import java.security.spec.RSAKeyGenParameterSpec;
import java.util.Arrays;
import java.util.zip.DeflaterOutputStream;
import java.util.zip.InflaterOutputStream;

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
     * Deompresses data using ZIP.
     * @param data The data you want to decompress.
     * @return The decompressed data.
     * @throws IOException In case of errors in compression.
     */
    public static byte[] decompressData(byte[] data) throws IOException {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        InflaterOutputStream infl = new InflaterOutputStream(out);
        infl.write(data);
        infl.flush();
        infl.close();

        return out.toByteArray();
    }

    /**
     * Install Bouncy Castle provider.
     */
    public static void installProvider()
    {
        Security.addProvider(new BouncyCastleProvider());
        Security.addProvider(new BouncyCastleFipsProvider());
    }

    public static void main(String[] args) throws GeneralSecurityException, IOException {
        installProvider();

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

        // 16. Compress message portion.
        byte[] anneComparisonCompressed = compressData(anneSignedMsgDigest[1]);
        System.out.println("Anne's received message compressed - " + Arrays.toString(anneComparisonCompressed));

        // 16. Hash compressed message.
        byte[] anneComparisonHash = calculateSha3Digest(anneComparisonCompressed);
        System.out.println("Anne's received message hashed - " + Arrays.toString(anneComparisonHash));

        // 17. Verify Anne's message with Anne's public key.
        boolean bobReceivesAnneMsg = verifyPkcs1Signature(anneKeys.getPublic(), anneComparisonHash, anneSignedMsgDigest[0]);
        System.out.println("Bob successfully verified Anne's message - " + bobReceivesAnneMsg);
    }
}
