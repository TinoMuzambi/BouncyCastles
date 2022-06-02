import org.bouncycastle.asn1.nist.NISTObjectIdentifiers;
import org.bouncycastle.jcajce.spec.KTSParameterSpec;
import org.bouncycastle.util.Strings;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import java.io.IOException;
import java.security.*;
import java.util.Arrays;

public class HashingAndEncryption {

    /**
     * Wrap a secret key with a public key.
     * @param rsaPublic The public key of the receiver.
     * @param secretKey The secret key you want to wrap.
     * @return The wrapped key.
     * @throws GeneralSecurityException In case of any security errors.
     */
    public static byte[] kemKeyWrap(PublicKey rsaPublic, SecretKey secretKey)
            throws GeneralSecurityException
    {
        Cipher c = Cipher.getInstance("RSA-KTS-KEM-KWS", "BCFIPS");
        c.init(Cipher.WRAP_MODE, rsaPublic,
                new KTSParameterSpec.Builder(
                        NISTObjectIdentifiers.id_aes256_wrap.getId(), 256).build());
        return c.wrap(secretKey);
    }

    /**
     * Unwrap a secret key with a private key.
     * @param rsaPrivate The private key of the receiver.
     * @param wrappedKey The bytes of the secret key you want to unwrap.
     * @return The unwrapped key's bytes.
     * @throws GeneralSecurityException In case of any security errors.
     */
    public static Key kemKeyUnwrap(PrivateKey rsaPrivate, byte[] wrappedKey)
            throws GeneralSecurityException
    {
        Cipher c = Cipher.getInstance("RSA-KTS-KEM-KWS", "BCFIPS");
        c.init(Cipher.UNWRAP_MODE, rsaPrivate,
                new KTSParameterSpec.Builder(
                        NISTObjectIdentifiers.id_aes256_wrap.getId(), 256).build());
        return c.unwrap(wrappedKey, "AES", Cipher.SECRET_KEY);
    }

    public static void main(String[] args) throws GeneralSecurityException, IOException {
        Hashing.installProvider();

        // 1.1. Initialise and generate sender/receiver keys.
        KeyPair anneKeys = Hashing.generateKeyPair();
        System.out.println("Anne's public key - " + anneKeys.getPublic());
        System.out.println("Anne's private key - " + anneKeys.getPrivate());

        KeyPair bobKeys = Hashing.generateKeyPair();
        System.out.println("Bob's public key - " + bobKeys.getPublic());
        System.out.println("Bob's private key - " + bobKeys.getPrivate());

        // 1.2. Initialise server keys.
        KeyPair serverKeys = Hashing.generateKeyPair();
        System.out.println("Server's public key - " + serverKeys.getPublic());
        System.out.println("Server's private key - " + serverKeys.getPrivate());

        // Generate Anne's message.
        byte[] anneMsg = Strings.toByteArray("Houston, we are hidden.");
        System.out.println("Anne's unsigned message - " + Arrays.toString(anneMsg));

        // 3. Compress Anne's message.
        byte[] anneMsgCompressed = Hashing.compressData(anneMsg);
        System.out.println("Anne's unsigned compressed message - " + Arrays.toString(anneMsgCompressed));

        // 3. Hash Anne's compressed message.
        byte[] anneMsgHashedCompressed = Hashing.calculateSha3Digest(anneMsgCompressed);
        System.out.println("Anne's unsigned hashed compressed message - " + Arrays.toString(anneMsgHashedCompressed));

        // 4. Sign Anne's message with Anne's private key.
        byte[] anneSignedMsg = Hashing.generatePkcs1Signature(anneKeys.getPrivate(), anneMsgHashedCompressed);
        System.out.println("Anne's signed message - " + Arrays.toString(anneSignedMsg));

        // 6. Initialise and generate one-time secret key.
        Encryption.defineKey(new byte[128 / 8]);
        Encryption.defineKey(new byte[192 / 8]);
        Encryption.defineKey(new byte[256 / 8]);
        SecretKey oneTimeKey = Encryption.generateKey();

        // 7. Encrypt messages with one time key.
        byte[][] anneSignedMsgEncrypted = Encryption.cbcEncrypt(oneTimeKey, anneSignedMsg);
        byte[][] anneMsgEncrypted = Encryption.cbcEncrypt(oneTimeKey, anneMsg);

        // 5. Combine Anne's signed message with the original message.
        byte[][][] anneSignedMsgDigest = {anneSignedMsgEncrypted, anneMsgEncrypted};
        System.out.println("Anne's signed message digest - " + Arrays.toString(anneSignedMsgDigest));

        // 8. Sign the one-time key with server's public key.
        byte[][] signedOneTimeKey = Encryption.cbcEncrypt(Encryption.defineKey(serverKeys.getPublic().getEncoded()), oneTimeKey.getEncoded());

        // 9. Combine signed one time key with signed message digest.
        KeyWithMessageDigest keyWithMessageDigest = new KeyWithMessageDigest(signedOneTimeKey, anneSignedMsgDigest);
        System.out.println(keyWithMessageDigest);

        // 10. Decrypt one time key.
        byte[] decryptedKeyContents = Encryption.cbcDecrypt()

        // Imagine message has been sent securely to Bob.

        // 16. Compress message portion.
        byte[] anneComparisonCompressed = Hashing.compressData(anneSignedMsgDigest[1]);
        System.out.println("Anne's received message compressed - " + Arrays.toString(anneComparisonCompressed));

        // 16. Hash compressed message.
        byte[] anneComparisonHash = Hashing.calculateSha3Digest(anneComparisonCompressed);
        System.out.println("Anne's received message hashed - " + Arrays.toString(anneComparisonHash));

        // 17. Verify Anne's message with Anne's public key.
        boolean bobReceivesAnneMsg = Hashing.verifyPkcs1Signature(anneKeys.getPublic(), anneComparisonHash, anneSignedMsgDigest[0]);
        System.out.println("Bob successfully verified Anne's message - " + bobReceivesAnneMsg);
    }
}
