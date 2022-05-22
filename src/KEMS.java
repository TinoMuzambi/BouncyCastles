import java.security.*;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import org.bouncycastle.jcajce.spec.KTSParameterSpec;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.Strings;
import org.bouncycastle.util.encoders.Hex;

/**
 * Simple example showing secret key wrapping and unwrapping based on RSA-KEMS.
 */
public class KEMS
{
    /**
     * Generate a wrapped key using the RSA-KTS-KEM-KWS algorithm,
     * returning the resulting encryption.
     *
     * @param rsaPublic the public key to base the wrapping on.
     * @param ktsSpec key transport parameters.
     * @param secretKey the secret key to be encrypted/wrapped.
     * @return true if the signature verifies, false otherwise.
     */
    public static byte[] keyWrapKEMS(
            PublicKey rsaPublic, KTSParameterSpec ktsSpec, SecretKey secretKey)
            throws GeneralSecurityException
    {
        Cipher cipher = Cipher.getInstance("RSA-KTS-KEM-KWS", "BCFIPS");

        cipher.init(Cipher.WRAP_MODE, rsaPublic, ktsSpec);

        return cipher.wrap(secretKey);
    }
    /**
     * Return the secret key that is encrypted in wrappedKey.
     *
     * @param rsaPrivate the private key to use for the unwrap.
     * @param ktsSpec key transport parameters.
     * @param wrappedKey the encrypted secret key.
     * @param keyAlgorithm the algorithm that the encrypted key is for.
     * @return the unwrapped SecretKey.
     */
    public static SecretKey keyUnwrapKEMS(
            PrivateKey rsaPrivate, KTSParameterSpec ktsSpec,
            byte[] wrappedKey, String keyAlgorithm)
            throws GeneralSecurityException
    {
        Cipher cipher = Cipher.getInstance("RSA-KTS-KEM-KWS", "BCFIPS");

        cipher.init(Cipher.UNWRAP_MODE, rsaPrivate, ktsSpec);

        return (SecretKey)cipher.unwrap(
                wrappedKey, keyAlgorithm, Cipher.SECRET_KEY);
    }

    public static void main(String[] args)
            throws GeneralSecurityException
    {
        SecretKey aesKey = new SecretKeySpec(
                Hex.decode("000102030405060708090a0b0c0d0e0f"),
                "AES");

        KeyPairGenerator keyPair = KeyPairGenerator.getInstance("RSA", "BCFIPS");

        keyPair.initialize(2048);

        KeyPair kp = keyPair.generateKeyPair();

        KTSParameterSpec ktsSpec =
                new KTSParameterSpec.Builder(
                        "AESKWP", 256,
                        Strings.toByteArray("OtherInfo Data")).build();

        byte[] wrappedKey = keyWrapKEMS(kp.getPublic(), ktsSpec, aesKey);

        SecretKey recoveredKey = keyUnwrapKEMS(
                kp.getPrivate(), ktsSpec,
                wrappedKey, aesKey.getAlgorithm());

        System.out.println(
                Arrays.areEqual(aesKey.getEncoded(), recoveredKey.getEncoded()));
    }
}
