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
        System.out.println("1.1) Anne's public key - " + anneKeys.getPublic());
        System.out.println("1.1) Anne's private key - " + anneKeys.getPrivate());

        KeyPair bobKeys = Hashing.generateKeyPair();
        System.out.println("1.1) Bob's public key - " + bobKeys.getPublic());
        System.out.println("1.1) Bob's private key - " + bobKeys.getPrivate());

        // 1.2. Initialise server keys.
        KeyPair serverKeys = Hashing.generateKeyPair();
        System.out.println("1.2) Server's public key - " + serverKeys.getPublic());
        System.out.println("1.2) Server's private key - " + serverKeys.getPrivate());

        // Generate Anne's message.
        byte[] anneMsg = Strings.toByteArray("Houston, we are hidden.");
        System.out.println("Anne's unsigned message - " + Arrays.toString(anneMsg));

        // 3. Compress Anne's message.
        byte[] anneMsgCompressed = Hashing.compressData(anneMsg);
        System.out.println("3) Anne's unsigned compressed message - " + Arrays.toString(anneMsgCompressed));

        // 3. Hash Anne's compressed message.
        byte[] anneMsgHashedCompressed = Hashing.calculateSha3Digest(anneMsgCompressed);
        System.out.println("3) Anne's unsigned hashed compressed message - " + Arrays.toString(anneMsgHashedCompressed));

        // 4. Sign Anne's message with Anne's private key.
        byte[] anneSignedMsg = Hashing.generatePkcs1Signature(anneKeys.getPrivate(), anneMsgHashedCompressed);
        System.out.println("4) Anne's signed message - " + Arrays.toString(anneSignedMsg));

        // 6. Initialise and generate one-time secret key.
        Encryption.defineKey(new byte[128 / 8]);
        Encryption.defineKey(new byte[192 / 8]);
        Encryption.defineKey(new byte[256 / 8]);
        SecretKey oneTimeKey = Encryption.generateKey();
        System.out.println("6) One time key - " + oneTimeKey.toString());

        // 7. Encrypt messages with one time key.
        byte[][] anneSignedMsgEncrypted = Encryption.cbcEncrypt(oneTimeKey, anneSignedMsg);
        byte[][] anneMsgEncrypted = Encryption.cbcEncrypt(oneTimeKey, anneMsg);
        System.out.println("7) Anne's signed message encrypted - " + Arrays.toString(anneSignedMsgEncrypted));
        System.out.println("7) Anne's message encrypted - " + Arrays.toString(anneMsgEncrypted));

        // 5. Combine Anne's signed message with the original message.
        byte[][][] anneSignedMsgDigest = {anneSignedMsgEncrypted, anneMsgEncrypted};
        System.out.println("5) Anne's signed message digest - " + Arrays.toString(anneSignedMsgDigest));

        // 8. Encrypt the one-time key with server's public key.
        byte[] signedOneTimeKey = kemKeyWrap(serverKeys.getPublic(), oneTimeKey);
        System.out.println("8) Encrypted one-time key with server's public key - " + Arrays.toString(signedOneTimeKey));

        // 9. Combine signed one time key with signed message digest.
        KeyWithMessageDigest keyWithMessageDigest = new KeyWithMessageDigest(signedOneTimeKey, anneSignedMsgDigest);
        System.out.println("9) Signed one-time key with message digest - " + keyWithMessageDigest);

        // 10. Decrypt one time key with server's private key.
        SecretKey decryptedOneTimeKey = (SecretKey) kemKeyUnwrap(serverKeys.getPrivate(), keyWithMessageDigest.getOneTimeKey());
        System.out.println("10) Decrypted one time key - " + decryptedOneTimeKey.toString());


        // 11. Decrypt messages with decrypted one time key. Yeah you were capping Tumo.
//        byte[] anneSignedMsgDecrypted = Encryption.cbcDecrypt(decryptedOneTimeKey, keyWithMessageDigest.getMessageDigest()[0][0], keyWithMessageDigest.getMessageDigest()[0][1]);
//        byte[] anneMsgDecrypted = Encryption.cbcDecrypt(decryptedOneTimeKey, keyWithMessageDigest.getMessageDigest()[1][0], keyWithMessageDigest.getMessageDigest()[1][1]);
//        System.out.println("11) Anne's signed message decrypted - " + Arrays.toString(anneSignedMsgDecrypted));
//        System.out.println("11) Anne's message decrypted - " + Arrays.toString(anneMsgDecrypted));

        // 12.1.  Encrypt the decrypted one-time key with receiver's public key.
        byte[] signedReceiverOneTimeKey = kemKeyWrap(bobKeys.getPublic(), decryptedOneTimeKey);
        System.out.println("12.1) Encrypted decrypted one-time key with receiver's public key - " + Arrays.toString(signedReceiverOneTimeKey));

        // 12.2 Send key with message digest to receiver.
        KeyWithMessageDigest bobKeyWithMessageDigest = new KeyWithMessageDigest(signedReceiverOneTimeKey, anneSignedMsgDigest);
        System.out.println("12.2) Bob's signed one-time key with message digest - " + bobKeyWithMessageDigest);

        // 13. Decrypt signed one time key with receiver's private key.
        SecretKey bobOneTimeKey = (SecretKey) kemKeyUnwrap(bobKeys.getPrivate(), bobKeyWithMessageDigest.getOneTimeKey());
        System.out.println("13) Bob's one time key decrypted - " + bobOneTimeKey.toString());

        // 14. Decrypt messages with decrypted one time key.
        byte[] anneSignedMsgDecrypted = Encryption.cbcDecrypt(bobOneTimeKey, bobKeyWithMessageDigest.getMessageDigest()[0][0], bobKeyWithMessageDigest.getMessageDigest()[0][1]);
        byte[] anneMsgDecrypted = Encryption.cbcDecrypt(bobOneTimeKey, bobKeyWithMessageDigest.getMessageDigest()[1][0], bobKeyWithMessageDigest.getMessageDigest()[1][1]);
        System.out.println("14) Anne's signed message decrypted - " + Arrays.toString(anneSignedMsgDecrypted));
        System.out.println("14) Anne's message decrypted - " + Arrays.toString(anneMsgDecrypted));

        // 16. Compress message portion.
        byte[] anneComparisonCompressed = Hashing.compressData(anneMsgDecrypted);
        System.out.println("16) Anne's received message compressed - " + Arrays.toString(anneComparisonCompressed));

        // 16. Hash compressed message.
        byte[] anneComparisonHash = Hashing.calculateSha3Digest(anneComparisonCompressed);
        System.out.println("16) Anne's received message hashed - " + Arrays.toString(anneComparisonHash));

        // 15./17. Verify Anne's message with Anne's public key.
        boolean bobReceivesAnneMsg = Hashing.verifyPkcs1Signature(anneKeys.getPublic(), anneComparisonHash, anneSignedMsgDecrypted);
        System.out.println("15/17) Bob successfully verified Anne's message - " + bobReceivesAnneMsg);
    }
}
