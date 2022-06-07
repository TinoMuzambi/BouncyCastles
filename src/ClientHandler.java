import javax.crypto.SecretKey;
import java.io.*;
import java.net.Socket;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.ArrayList;
import java.util.Base64;

public class ClientHandler implements Runnable{

    public static ArrayList<ClientHandler> clientHandlers = new ArrayList<>();
    private Socket socket;
    private BufferedReader bufferedReader;
    private BufferedWriter bufferedWriter;
    private String name;
    private PublicKey publicKey;
    private PublicKey serverPublicKey;
    private PrivateKey serverPrivateKey;

    public ClientHandler(Socket socket, PublicKey serverPublicKey, PrivateKey serverPrivateKey) throws NoSuchAlgorithmException, InvalidKeySpecException {
        try {
            this.socket = socket;
            this.bufferedWriter = new BufferedWriter(new OutputStreamWriter(socket.getOutputStream()));
            this.bufferedReader = new BufferedReader(new InputStreamReader(socket.getInputStream()));
            String nameWithPublicKey = bufferedReader.readLine();

            this.name = nameWithPublicKey.split(" - ")[0];
            X509EncodedKeySpec keySpecPublic = new X509EncodedKeySpec(decode(nameWithPublicKey.split(" - ")[1]));
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

    private byte[] decode(String data){return Base64.getDecoder().decode(data);}

    private String encode(byte[] data){ return Base64.getEncoder().encodeToString(data); }

    private void logger(String descriptor, String data) {
        System.err.println("Client handler [" + name + "]: " + descriptor + " - " + data);
    }

    @Override
    public void run() {
        String messageFromClient;

        while (socket.isConnected()){
            try {
                messageFromClient = bufferedReader.readLine();

                String[] rawData = messageFromClient.split(": ");
                String[] data = rawData[1].split(" - ");

                // 10. Decrypt one time key with server's private key.
                byte[] signedOneTimeKey = decode(data[0]);
                SecretKey decryptedOneTimeKey = (SecretKey) HashingAndEncryption.kemKeyUnwrap(serverPrivateKey, signedOneTimeKey);

                // 12.1.  Encrypt the decrypted one-time key with receiver's public key.
                byte[] signedReceiverOneTimeKey = HashingAndEncryption.kemKeyWrap(publicKey, decryptedOneTimeKey);

                // 12.2 Send key with message digest to receiver.
                broadcastMessage(rawData[0] + ": " + encode(signedReceiverOneTimeKey) + " - " + data[1] + " - " + data[2] + " - " + " - " + data[3] + " - " + data[4]);
            } catch (IOException | GeneralSecurityException e) {
                closeEverything(socket, bufferedReader, bufferedWriter);
                break;
            }
        }
    }

    public void broadcastMessage(String messageToSend){
        for (ClientHandler clientHandler : clientHandlers){
            try{
                if (!clientHandler.name.equals(name)){
                    clientHandler.bufferedWriter.write(messageToSend);
                    clientHandler.bufferedWriter.newLine();
                    clientHandler.bufferedWriter.flush();
                }
            } catch (IOException e){
                closeEverything(socket, bufferedReader, bufferedWriter);
            }
        }
    }

    public void broadcastUK(){
        for (ClientHandler clientHandler : clientHandlers){
            try{
                if (clientHandler.name.equals(name)) {
                    clientHandler.bufferedWriter.write("UK:SERVER: " + Base64.getEncoder().encodeToString(serverPublicKey.getEncoded()));
                    clientHandler.bufferedWriter.newLine();
                    clientHandler.bufferedWriter.flush();
                }
            } catch (IOException e){
                closeEverything(socket, bufferedReader, bufferedWriter);
            }
        }
    }

    public void removeClientHandler(){
        clientHandlers.remove(this);
        broadcastMessage("SERVER: " + name + " has left the chat!");
    }

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
