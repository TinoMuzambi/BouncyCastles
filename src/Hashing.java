import org.bouncycastle.jce.provider.BouncyCastleProvider;

import java.security.*;
import java.security.spec.RSAKeyGenParameterSpec;
import java.util.Arrays;

public class Hashing {
    public static KeyPair generateKeyPair() throws GeneralSecurityException {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA", "BC");
        keyPairGenerator.initialize(new RSAKeyGenParameterSpec(3072, RSAKeyGenParameterSpec.F4));
        return keyPairGenerator.generateKeyPair();
    }

    public static byte[] generatePkcs1Signature(PrivateKey rsaPrivate, byte[] input)
            throws GeneralSecurityException
    {
        Signature signature = Signature.getInstance("SHA384withRSA", "BCFIPS");

        signature.initSign(rsaPrivate);

        signature.update(input);

        return signature.sign();
    }

    public static boolean verifyPkcs1Signature(PublicKey rsaPublic, byte[] input, byte[] encSignature)
            throws GeneralSecurityException
    {
        Signature signature = Signature.getInstance("SHA384withRSA", "BCFIPS");

        signature.initVerify(rsaPublic);

        signature.update(input);

        return signature.verify(encSignature);
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

        // The below represents hashing. This provides us with message integrity
        // Generate Anne's message.
        byte[] anneMsg = new byte[4];
        anneMsg[0] = 20;
        anneMsg[1] = 10;
        anneMsg[2] = 5;
        anneMsg[3] = 30;
        System.out.println("Anne's unsigned message - " + Arrays.toString(anneMsg));

        // Sign Anne's message with Anne's private key.
        byte[] anneSignedMsg = generatePkcs1Signature(anneKeys.getPrivate(), anneMsg);
        System.out.println("Anne's signed message - " + Arrays.toString(anneSignedMsg));

        // Verify Anne's message with Anne's public key.
        boolean bobReceivesAnneMsg = verifyPkcs1Signature(anneKeys.getPublic(), anneMsg, anneSignedMsg);
        System.out.println("Bob successfully verified Anne's message - " + bobReceivesAnneMsg);

    }
}
