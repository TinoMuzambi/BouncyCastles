import java.util.Base64;

public class Utils {
    /**
     * Decode a string message into a byte array.
     * @param data The data to be decoded.
     * @return The data decoded into a byte array.
     */
    public static byte[] decode(String data){return Base64.getDecoder().decode(data);}

    /**
     * Encode a byte array into a string.
     * @param data The data to be encoded.
     * @return The data encoded into a string.
     */
    public static String encode(byte[] data){ return Base64.getEncoder().encodeToString(data); }
}
