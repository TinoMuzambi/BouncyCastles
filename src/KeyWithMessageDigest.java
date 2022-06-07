import java.util.Arrays;

/**
 * A class for wrapping a signed one time key with a signed message digest.
 */
public class KeyWithMessageDigest {
    /**
     * The one time key.
     */
    private final byte[] oneTimeKey;

    /**
     * A multidimensional array representing the message digest.
     */
    private final byte[][][] messageDigest;

    /**
     * Instanstiates a KeyWithMessageDigest object.
     * @param oneTimeKey The one time key.
     * @param messageDigest A multidimensional array representing the message digest.
     */
    public KeyWithMessageDigest(byte[] oneTimeKey, byte[][][] messageDigest) {
        this.oneTimeKey = oneTimeKey;
        this.messageDigest = messageDigest;
    }

    /**
     * Getter for the one time key.
     * @return The one time key as a byte array.
     */
    public byte[] getOneTimeKey() {
        return oneTimeKey;
    }

    /**
     * Getter for the message digest.
     * @return The message digest as a multidimensional byte array.
     */
    public byte[][][] getMessageDigest() {
        return messageDigest;
    }

    /**
     * A to string method for this object.
     * @return A string representation of this object.
     */
    @Override
    public String toString() {
        return "KeyWithMessageDigest{" +
                "oneTimeKey=" + Arrays.toString(oneTimeKey) +
                ", messageDigest=" + Arrays.toString(messageDigest) +
                '}';
    }
}
