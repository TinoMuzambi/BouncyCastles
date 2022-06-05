import java.io.*;
import java.net.Socket;
import java.security.KeyFactory;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;

public class ClientHandler implements Runnable{

    public static ArrayList<ClientHandler> clientHandlers = new ArrayList<>();
    private Socket socket;
    private BufferedReader bufferedReader;
    private BufferedWriter bufferedWriter;
    private String name;
    private PublicKey publicKey;
    private PublicKey serverPublicKey;


    public ClientHandler(Socket socket, PublicKey serverPublicKey) throws NoSuchAlgorithmException, InvalidKeySpecException {
        try {
            this.socket = socket;
            this.bufferedWriter = new BufferedWriter(new OutputStreamWriter(socket.getOutputStream()));
            this.bufferedReader = new BufferedReader(new InputStreamReader(socket.getInputStream()));
            this.name = bufferedReader.readLine();
//            String nameWithPublicKey = bufferedReader.readLine();
//            System.out.println("ch - " + nameWithPublicKey);
//            this.name = nameWithPublicKey.split(" - ")[0];
//            byte[] publicBytes = Base64.getDecoder().decode(nameWithPublicKey.split(" - ")[1]);
//            X509EncodedKeySpec keySpec = new X509EncodedKeySpec(publicBytes);
//            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
//            publicKey = keyFactory.generatePublic(keySpec);
//            this.serverPublicKey = serverPublicKey;

            clientHandlers.add(this);
            broadcastMessage("SERVER: " + name + " has joined the group chat");
        } catch (IOException e){
            closeEverything(socket, bufferedReader, bufferedWriter);
        }
    }

    @Override
    public void run() {
        String messageFromClient;

        while (socket.isConnected()){
            try {
                messageFromClient = bufferedReader.readLine();
                broadcastMessage(messageFromClient);
            } catch (IOException e) {
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
                } else {
                    clientHandler.bufferedWriter.write("UK:SERVER: " + Arrays.toString(serverPublicKey.getEncoded()));
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
        broadcastMessage("SERVER: " + name +" " + "has left the chat!");
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
