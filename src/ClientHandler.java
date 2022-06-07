import javax.crypto.SecretKey;
import java.io.*;
import java.net.Socket;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.ArrayList;
import java.util.Arrays;

/**
 * This class helps the server keep track of all connected clients.
 */
public class ClientHandler implements Runnable{
    /**
     * A list of all the clients connected to the server.
     */
    public static ArrayList<ClientHandler> clientHandlers = new ArrayList<>();
    /**
     * The socket that this client handler will run on.
     */
    private Socket socket;
    /**
     * The reader used to read messages from clients.
     */
    private BufferedReader bufferedReader;
    /**
     * The writer used to write messages to clients.
     */
    private BufferedWriter bufferedWriter;
    /**
     * The name of the client this client handler belongs to.
     */
    private String name;
    /**
     * The public key of the client this client handler belongs to.
     */
    private PublicKey publicKey;
    /**
     * The server's public key.
     */
    private PublicKey serverPublicKey;
    /**
     * The server's private key.
     */
    private PrivateKey serverPrivateKey;

    /**
     * Instantiate a ClientHandler object.
     * @param socket The socket that this client handler will run on.
     * @param serverPublicKey The public key of the server.
     * @param serverPrivateKey The private key of the server.
     * @throws NoSuchAlgorithmException No such algorithm in BCFIPS.
     * @throws InvalidKeySpecException Invalid key specification.
     */
    public ClientHandler(Socket socket, PublicKey serverPublicKey, PrivateKey serverPrivateKey) throws NoSuchAlgorithmException, InvalidKeySpecException {
        try {
            this.socket = socket;
            this.bufferedWriter = new BufferedWriter(new OutputStreamWriter(socket.getOutputStream()));
            this.bufferedReader = new BufferedReader(new InputStreamReader(socket.getInputStream()));
            String nameWithPublicKey = bufferedReader.readLine();

            this.name = nameWithPublicKey.split(" - ")[0];
            X509EncodedKeySpec keySpecPublic = new X509EncodedKeySpec(Utils.decode(nameWithPublicKey.split(" - ")[1]));
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            this.publicKey = keyFactory.generatePublic(keySpecPublic);

            this.serverPublicKey = serverPublicKey;
            this.serverPrivateKey = serverPrivateKey;

            clientHandlers.add(this);
            broadcastMessage("SERVER: " + name + " has joined the group chat");
            broadcastUK();
        } catch (IOException e){
            closeEverything(socket, bufferedReader, bufferedWriter);
        }
    }

    /**
     * Uses System.err.println to log info.
     * @param descriptor The tag for the log.
     * @param data The data to be logged.
     */
    private void logger(String descriptor, String data) {
        System.err.println("Client handler [" + name + "]: " + descriptor + " - " + data);
    }

    /**
     * Handle receiving messages from clients.
     */
    @Override
    public void run() {
        String messageFromClient;

        while (socket.isConnected()){
            try {
                messageFromClient = bufferedReader.readLine();
                logger("message from client", messageFromClient);

                String[] rawData = messageFromClient.split(": ");
                logger("raw data", Arrays.toString(rawData));
                String[] data = rawData[1].split(" - ");
                logger("data", Arrays.toString(data));

                // 10. Decrypt one time key with server's private key.
                byte[] signedOneTimeKey = Utils.decode(data[0]);
                SecretKey decryptedOneTimeKey = (SecretKey) HashingAndEncryption.kemKeyUnwrap(serverPrivateKey, signedOneTimeKey);
                logger("decrypted one time key", Utils.encode(decryptedOneTimeKey.getEncoded()));

                // 12.2 Send key with message digest to receiver.
                logger("message to broadcast to receiver", rawData[0] + ": " + Utils.encode(decryptedOneTimeKey.getEncoded()) + " - " + data[1] + " - " + data[2] + " - " + data[3] + " - " + data[4]);
                broadcastMessage(rawData[0] + ": " + Utils.encode(decryptedOneTimeKey.getEncoded()) + " - " + data[1] + " - " + data[2] + " - " + data[3] + " - " + data[4]);
            } catch (IOException | GeneralSecurityException e) {
                closeEverything(socket, bufferedReader, bufferedWriter);
            }
        }
    }

    /**
     * Broadcast a message to all clients connected.
     * @param messageToSend The message to be broadcasted.
     */
    public void broadcastMessage(String messageToSend){
        for (ClientHandler clientHandler : clientHandlers){
            try{
                if (!clientHandler.name.equals(name)){
                    if (messageToSend.contains("SERVER: ")) {
                        logger("message to broadcast to [" + clientHandler.name + "]", messageToSend);
                        clientHandler.bufferedWriter.write(messageToSend);
                    } else {
                        String[] rawData = messageToSend.split(": ");
                        logger("raw data", Arrays.toString(rawData));
                        String[] data = rawData[1].split(" - ");
                        logger("data", Arrays.toString(data));

                        byte[] signedOneTimeKey = Utils.decode(data[0]);

                        // 12.1.  Encrypt the decrypted one-time key with receiver's public key.
                        byte[] signedReceiverOneTimeKey = HashingAndEncryption.kemKeyWrap(clientHandler.publicKey, Encryption.defineKey(signedOneTimeKey));
                        logger("one time key wrapped with receiver's public key", Utils.encode(signedReceiverOneTimeKey));

                        logger("message to broadcast to [" + clientHandler.name + "]", rawData[0] + ": " + Utils.encode(signedReceiverOneTimeKey) + " - " + data[1] + " - " + data[2] + " - " + data[3] + " - " + data[4] + " - " + Utils.encode(publicKey.getEncoded()));
                        clientHandler.bufferedWriter.write(rawData[0] + ": " + Utils.encode(signedReceiverOneTimeKey) + " - " + data[1] + " - " + data[2] + " - " + data[3] + " - " + data[4] + " - " + Utils.encode(publicKey.getEncoded()));
                    }
                    clientHandler.bufferedWriter.newLine();
                    clientHandler.bufferedWriter.flush();
                }
            } catch (IOException | GeneralSecurityException e){
                closeEverything(socket, bufferedReader, bufferedWriter);
            }
        }
    }

    /**
     * Broadcast the server's public key to new clients.
     */
    public void broadcastUK(){
        for (ClientHandler clientHandler : clientHandlers){
            try{
                if (clientHandler.name.equals(name)) {
                    String UKString = "UK:SVR: " + Utils.encode(serverPublicKey.getEncoded());
                    logger("public key being broadcast to [" + clientHandler.name + "]", UKString);
                    clientHandler.bufferedWriter.write(UKString);
                    clientHandler.bufferedWriter.newLine();
                    clientHandler.bufferedWriter.flush();
                }
            } catch (IOException e){
                closeEverything(socket, bufferedReader, bufferedWriter);
            }
        }
    }

    /**
     * Remove a client handler when the associated client leaves the chat.
     */
    public void removeClientHandler(){
        clientHandlers.remove(this);
        broadcastMessage("SERVER: " + name + " has left the chat!");
    }

    /**
     * Tear down the client handler.
     * @param socket The socket the client handler was running on.
     * @param bufferedReader The reader for the client handler.
     * @param bufferedWriter The writer for the client handler.
     */
    public void closeEverything(Socket socket, BufferedReader bufferedReader, BufferedWriter bufferedWriter){
        removeClientHandler();
        try {
            if (bufferedReader != null){
                bufferedReader.close();
            }
            if (bufferedWriter != null){
                bufferedWriter.close();
            }
            if (socket != null){
                socket.close();
            }
        } catch (IOException e){
            e.printStackTrace();
        }
    }
}
