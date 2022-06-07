import org.bouncycastle.util.Strings;

import javax.crypto.SecretKey;
import java.io.*;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;
import java.util.Base64;
import java.util.Scanner;

/**
 * This class represents the client in a client-server network.
 */
public class Client {
    /**
     * The socket the client will run on.
     */
    private Socket socket;
    /**
     * The reader used to read messages from the server.
     */
    private BufferedReader bufferedReader;
    /**
     * The writer used to write messages to the server.
     */
    private BufferedWriter bufferedWriter;
    /**
     * The name of this client.
     */
    private String name;
    /**
     * The client's private key.
     */
    private PrivateKey privateKey;
    /**
     * The client's public key.
     */
    private PublicKey publicKey;
    /**
     * The server's public key.
     */
    private PublicKey serverPublicKey;

    /**
     * Instantiate a Client object.
     * @param socket The socket which this client will run on.
     * @param name The name of this client.
     */
    public Client(Socket socket, String name) {
        try {
            this.socket = socket;
            this.bufferedWriter = new BufferedWriter(new OutputStreamWriter(socket.getOutputStream()));
            this.bufferedReader = new BufferedReader(new InputStreamReader(socket.getInputStream()));
            this.name = name;
        } catch (IOException e) {
            closeEverything(socket, bufferedReader, bufferedWriter);
        }
    }

    /**
     * Instantiate the client's key pair from encoded strings of the keys.
     * @param privateKeyBytes The encoded private key of the client.
     * @param publicKeyBytes The encoded public key of the client.
     */
    public void initFromStrings(String privateKeyBytes, String publicKeyBytes) {
        try {
            X509EncodedKeySpec keySpecPublic = new X509EncodedKeySpec(Utils.decode(publicKeyBytes));
            PKCS8EncodedKeySpec keySpecPrivate = new PKCS8EncodedKeySpec(Utils.decode(privateKeyBytes));

            KeyFactory keyFactory = KeyFactory.getInstance("RSA");

            publicKey = keyFactory.generatePublic(keySpecPublic);
            logger("public key", Utils.encode(publicKey.getEncoded()));
            privateKey = keyFactory.generatePrivate(keySpecPrivate);
            logger("private key", Utils.encode(privateKey.getEncoded()));
        } catch (Exception ignored) {
        }
    }

    /**
     * Uses System.err.println to log info.
     * @param descriptor The tag for the log.
     * @param data The data to be logged.
     */
    private void logger(String descriptor, String data) {
        System.err.println("Client [" + name + "]: " + descriptor + " - " + data);
    }

    /**
     * Send a message to the client.
     * @throws GeneralSecurityException Security errors.
     */
    public void sendMessage() throws GeneralSecurityException {
        try {
            String UKString = name + " - " + Base64.getEncoder().encodeToString(publicKey.getEncoded());
            logger("public key being sent to server", UKString);
            bufferedWriter.write(UKString);
            bufferedWriter.newLine();
            bufferedWriter.flush();

            Scanner scanner = new Scanner(System.in);
            while (socket.isConnected()) {
                String messageToSend = scanner.nextLine();
                logger("message to send", messageToSend);

                byte[] messageToSendBytes = Strings.toByteArray(messageToSend);
                logger("message to send bytes", Utils.encode(messageToSendBytes));

                // 3. Compress message.
                byte[] messageToSendBytesCompressed = Hashing.compressData(messageToSendBytes);
                logger("message to send bytes compressed", Utils.encode(messageToSendBytesCompressed));

                // 3. Hash compressed message.
                byte[] messageToSendBytesCompressedHashed = Hashing.calculateSha3Digest(messageToSendBytesCompressed);
                logger("message to send bytes compressed hashed", Utils.encode(messageToSendBytesCompressedHashed));

                // 4. Sign message with private key.
                byte[] signedMessage = Hashing.generatePkcs1Signature(privateKey, messageToSendBytesCompressedHashed);
                logger("signed message", Utils.encode(signedMessage));

                // 6. Initialise and generate one-time secret key.
                Encryption.defineKey(new byte[128 / 8]);
                Encryption.defineKey(new byte[192 / 8]);
                Encryption.defineKey(new byte[256 / 8]);
                SecretKey oneTimeKey = Encryption.generateKey();
                logger("one-time secret key", Utils.encode(oneTimeKey.getEncoded()));

                // 7. Encrypt messages with one time key.
                byte[][] signedMessageEncryptedRes = Encryption.cbcEncrypt(oneTimeKey, signedMessage);
                byte[] signedMessageEncryptedIV = signedMessageEncryptedRes[0];
                logger("signed message initialisation vector", Utils.encode(signedMessageEncryptedIV));
                byte[] signedMessageEncrypted = signedMessageEncryptedRes[1];
                logger("signed message encrypted", Utils.encode(signedMessageEncrypted));
                byte[][] messageToSendBytesEncryptedRes = Encryption.cbcEncrypt(oneTimeKey, messageToSendBytes);
                byte[] messageToSendBytesEncryptedIV = messageToSendBytesEncryptedRes[0];
                logger("original message initialisation vector", Utils.encode(messageToSendBytesEncryptedIV));
                byte[] messageToSendBytesEncrypted = messageToSendBytesEncryptedRes[1];
                logger("original message encrypted", Utils.encode(messageToSendBytesEncrypted));

                // 8. Encrypt the one-time key with server's public key.
                byte[] signedOneTimeKey = HashingAndEncryption.kemKeyWrap(serverPublicKey, oneTimeKey);
                logger("one time key wrapped with server's public key", Utils.encode(signedOneTimeKey));

                // 5./9. Combine signed one time key with signed message digest and send to server.
                logger("message being sent to server", name + ": " + Utils.encode(signedOneTimeKey) + " - " + Utils.encode(signedMessageEncryptedIV) + " - " + Utils.encode(signedMessageEncrypted) + " - " + Utils.encode(messageToSendBytesEncryptedIV) + " - " + Utils.encode(messageToSendBytesEncrypted));
                bufferedWriter.write(name + ": " + Utils.encode(signedOneTimeKey) + " - " + Utils.encode(signedMessageEncryptedIV) + " - " + Utils.encode(signedMessageEncrypted) + " - " + Utils.encode(messageToSendBytesEncryptedIV) + " - " + Utils.encode(messageToSendBytesEncrypted));
                bufferedWriter.newLine();
                bufferedWriter.flush();
            }
        } catch (IOException e) {
            closeEverything(socket, bufferedReader, bufferedWriter);
        }
    }

    /**
     * Listen for messages from the server.
     */
    public void listenForMessage() {
        new Thread(new Runnable() {
            @Override
            public void run() {
                String msgFromGroupChat;

                while (socket.isConnected()) {
                    try {
                        msgFromGroupChat = bufferedReader.readLine();
                        logger("message from group chat", msgFromGroupChat);

                        if (msgFromGroupChat.contains("SERVER: ")) {
                            System.out.println(msgFromGroupChat);
                        } else if (!msgFromGroupChat.contains("UK:SVR")) {
                            // 13. Decrypt signed one time key with receiver's private key.
                            String[] rawData = msgFromGroupChat.split(": ");
                            logger("raw data", Arrays.toString(rawData));
                            String[] data = rawData[1].split(" - ");
                            logger("data", Arrays.toString(data));
                            SecretKey oneTimeKey = (SecretKey) HashingAndEncryption.kemKeyUnwrap(privateKey, Utils.decode(data[0]));
                            logger("unwrapped one time secret key", Utils.encode(oneTimeKey.getEncoded()));

                            // 14. Decrypt messages with decrypted one time key.
                            byte[] signedMessageEncryptedIV = Utils.decode(data[1]);
                            logger("signed message initialisation vector", Utils.encode(signedMessageEncryptedIV));
                            byte[] signedMessageEncrypted = Utils.decode(data[2]);
                            logger("signed message encrypted", Utils.encode(signedMessageEncrypted));
                            byte[] messageBytesEncryptedIV = Utils.decode(data[3]);
                            logger("original message initialisation vector", Utils.encode(messageBytesEncryptedIV));
                            byte[] messageBytesEncrypted = Utils.decode(data[4]);
                            logger("original message encrypted", Utils.encode(messageBytesEncrypted));

                            byte[] signedMessageDecrypted = Encryption.cbcDecrypt(oneTimeKey, signedMessageEncryptedIV, signedMessageEncrypted);
                            logger("signed message decrypted with one time key", Utils.encode(signedMessageDecrypted));
                            byte[] messageDecrypted = Encryption.cbcDecrypt(oneTimeKey, messageBytesEncryptedIV, messageBytesEncrypted);
                            logger("original message decrypted with one time key", Utils.encode(messageDecrypted));

                            // 16. Compress message portion.
                            byte[] messageCompressed = Hashing.compressData(messageDecrypted);
                            logger("original message compressed", Utils.encode(messageCompressed));

                            // 16. Hash compressed message.
                            byte[] messageHashed = Hashing.calculateSha3Digest(messageCompressed);
                            logger("original message compressed and hashed", Utils.encode(messageHashed));

                            // 15./17. Verify message with public key.
                            X509EncodedKeySpec keySpecPublic = new X509EncodedKeySpec(Utils.decode(data[5]));
                            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
                            boolean messageHashMatch = Hashing.verifyPkcs1Signature(keyFactory.generatePublic(keySpecPublic), messageHashed, signedMessageDecrypted);
                            logger("verification of signatures", String.valueOf(messageHashMatch));
                            if (messageHashMatch) {
                                System.out.println("Verified");
                            }

                            logger("message received from server", rawData[0] + ": " + new String(messageDecrypted, StandardCharsets.UTF_8));
                            System.out.println(rawData[0] + ": " + new String(messageDecrypted, StandardCharsets.UTF_8));
                        } else {
                            X509EncodedKeySpec keySpecPublic = new X509EncodedKeySpec(Utils.decode(msgFromGroupChat.substring(8)));
                            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
                            serverPublicKey = keyFactory.generatePublic(keySpecPublic);
                            logger("public key received from server", Utils.encode(serverPublicKey.getEncoded()));
                        }
                    } catch (IOException | GeneralSecurityException e) {
                        closeEverything(socket, bufferedReader, bufferedWriter);
                    }
                }
            }
        }).start();
    }

    /**
     * Tear down the client.
     * @param socket The socket the client was running on.
     * @param bufferedReader The reader for the client.
     * @param bufferedWriter The writer for the client.
     */
    public void closeEverything(Socket socket, BufferedReader bufferedReader, BufferedWriter bufferedWriter) {
        try {
            if (bufferedReader != null) {
                bufferedReader.close();
            }
            if (bufferedWriter != null) {
                bufferedWriter.close();
            }
            if (socket != null) {
                socket.close();
            }
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    public static void main(String[] args) {
        try {
            Scanner scanner = new Scanner(System.in);

            System.out.println("Enter your name");
            String name = scanner.nextLine();

            Socket socket = new Socket("localhost", 1235);

            Client client = new Client(socket, name);
            client.initFromStrings(args[0], args[1]);

            client.listenForMessage();
            client.sendMessage();

        } catch (Exception ignored) {
        }
    }
}
