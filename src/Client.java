import org.bouncycastle.util.Strings;

import javax.crypto.SecretKey;
import java.io.*;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.Scanner;

public class Client {

    private Socket socket;
    private BufferedReader bufferedReader;
    private BufferedWriter bufferedWriter;
    private String name;
    private PrivateKey privateKey;
    private PublicKey publicKey;
    private PublicKey serverPublicKey;


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

    public void initFromStrings(String privateKeyBytes, String publicKeyBytes) {
        try {
            X509EncodedKeySpec keySpecPublic = new X509EncodedKeySpec(decode(publicKeyBytes));
            PKCS8EncodedKeySpec keySpecPrivate = new PKCS8EncodedKeySpec(decode(privateKeyBytes));

            KeyFactory keyFactory = KeyFactory.getInstance("RSA");

            publicKey = keyFactory.generatePublic(keySpecPublic);
            privateKey = keyFactory.generatePrivate(keySpecPrivate);
        } catch (Exception ignored) {
        }
    }

    private String encode(byte[] data){ return Base64.getEncoder().encodeToString(data); }

    private byte[] decode(String data) {
        return Base64.getDecoder().decode(data);
    }

    private static void logger(String name, String descriptor, String data) {
        System.err.println("Client " + name + ": " + descriptor + " - " + data);
    }

    public void sendMessage() throws GeneralSecurityException {
        try {
            bufferedWriter.write(name + " - " + Base64.getEncoder().encodeToString(publicKey.getEncoded()));
            bufferedWriter.newLine();
            bufferedWriter.flush();

            Scanner scanner = new Scanner(System.in);
            while (socket.isConnected()) {
                String messageToSend = scanner.nextLine();


                byte[] messageToSendBytes = Strings.toByteArray(messageToSend);

                // 3. Compress message.
                byte[] messageToSendBytesCompressed = Hashing.compressData(messageToSendBytes);

                // 3. Hash compressed message.
                byte[] messageToSendBytesCompressedHashed = Hashing.calculateSha3Digest(messageToSendBytesCompressed);

                // 4. Sign message with private key.
                byte[] signedMessage = Hashing.generatePkcs1Signature(privateKey, messageToSendBytesCompressedHashed);

                // 6. Initialise and generate one-time secret key.
                Encryption.defineKey(new byte[128 / 8]);
                Encryption.defineKey(new byte[192 / 8]);
                Encryption.defineKey(new byte[256 / 8]);
                SecretKey oneTimeKey = Encryption.generateKey();

                // 7. Encrypt messages with one time key.
                byte[][] signedMessageEncryptedRes = Encryption.cbcEncrypt(oneTimeKey, signedMessage);
                byte[] signedMessageEncryptedIV = signedMessageEncryptedRes[0];
                byte[] signedMessageEncrypted = signedMessageEncryptedRes[1];
                byte[][] messageToSendBytesEncryptedRes = Encryption.cbcEncrypt(oneTimeKey, messageToSendBytes);
                byte[] messageToSendBytesEncryptedIV = messageToSendBytesEncryptedRes[0];
                byte[] messageToSendBytesEncrypted = messageToSendBytesEncryptedRes[1];

                // 8. Encrypt the one-time key with server's public key.
                byte[] signedOneTimeKey = HashingAndEncryption.kemKeyWrap(serverPublicKey, oneTimeKey);

                // 5./9. Combine signed one time key with signed message digest and send to server.
                bufferedWriter.write(name + ": " + encode(signedOneTimeKey) + " - " + encode(signedMessageEncryptedIV) + " - " + encode(signedMessageEncrypted) + " - " + encode(messageToSendBytesEncryptedIV) + " - " + encode(messageToSendBytesEncrypted));
                bufferedWriter.newLine();
                bufferedWriter.flush();
            }
        } catch (IOException e) {
            closeEverything(socket, bufferedReader, bufferedWriter);
        }
    }

    public void listenForMessage() {
        new Thread(new Runnable() {
            @Override
            public void run() {
                String msgFromGroupChat;

                while (socket.isConnected()) {
                    try {
                        msgFromGroupChat = bufferedReader.readLine();

                        // 13. Decrypt signed one time key with receiver's private key.
                        String[] rawData = msgFromGroupChat.split(": ");
                        String[] data = rawData[1].split(" - ");
                        SecretKey oneTimeKey = (SecretKey) HashingAndEncryption.kemKeyUnwrap(privateKey, decode(data[0]));

                        // 14. Decrypt messages with decrypted one time key.
                        byte[] signedMessageEncryptedIV = decode(data[1]);
                        byte[] signedMessageEncrypted = decode(data[2]);
                        byte[] messageBytesEncryptedIV = decode(data[3]);
                        byte[] messageBytesEncrypted = decode(data[4]);

                        byte[] signedMessageDecrypted = Encryption.cbcDecrypt(oneTimeKey, signedMessageEncryptedIV, signedMessageEncrypted);
                        byte[] messageDecrypted = Encryption.cbcDecrypt(oneTimeKey, messageBytesEncryptedIV, messageBytesEncrypted);

                        // 16. Compress message portion.
                        byte[] messageCompressed = Hashing.compressData(messageDecrypted);

                        // 16. Hash compressed message.
                        byte[] messageHashed = Hashing.calculateSha3Digest(messageCompressed);

                        // 15./17. Verify message with public key.
                        boolean messageHashMatch = Hashing.verifyPkcs1Signature(publicKey, messageHashed, signedMessageDecrypted);
                        if (messageHashMatch) {
                            System.out.println("Verified");
                        }

                        if (!msgFromGroupChat.contains("UK:SERVER")) {
                            System.out.println(rawData[0] + ": " + new String(messageDecrypted, StandardCharsets.UTF_8));
                        } else {
                            X509EncodedKeySpec keySpecPublic = new X509EncodedKeySpec(decode(msgFromGroupChat.substring(11)));
                            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
                            serverPublicKey = keyFactory.generatePublic(keySpecPublic);
                        }
                    } catch (IOException | GeneralSecurityException e) {
                        closeEverything(socket, bufferedReader, bufferedWriter);
                    }
                }
            }
        }).start();
    }

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
