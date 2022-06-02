import org.bouncycastle.util.Strings;

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.util.Arrays;

public class HashingAndEncryption {

    public static void main(String[] args) throws GeneralSecurityException, IOException {
        Hashing.installProvider();

        // Initialise and generate sender/receiver keys.
        KeyPair anneKeys = Hashing.generateKeyPair();
        System.out.println("Anne's public key - " + anneKeys.getPublic());
        System.out.println("Anne's private key - " + anneKeys.getPrivate());

        KeyPair bobKeys = Hashing.generateKeyPair();
        System.out.println("Bob's public key - " + bobKeys.getPublic());
        System.out.println("Bob's private key - " + bobKeys.getPrivate());

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

        // 5. Combine Anne's signed message with the original message.
        byte[][] anneSignedMsgDigest = {anneSignedMsg, anneMsg};
        System.out.println("Anne's signed message digest - " + Arrays.toString(anneSignedMsgDigest));

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
