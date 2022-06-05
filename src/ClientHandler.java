import java.io.*;
import java.net.Socket;
import java.security.PublicKey;
import java.util.ArrayList;
import java.util.logging.SocketHandler;

public class ClientHandler implements Runnable{

    public static ArrayList<ClientHandler> clientHandlers = new ArrayList<>();
    private Socket socket;
    private BufferedReader bufferedReader;
    private BufferedWriter bufferedWriter;
    private String name;
//    private PublicKey publicKey;
    private PublicKey serverPublicKey;

    public ClientHandler(Socket socket, PublicKey serverPublicKey){
        try {
            this.socket = socket;
            this.bufferedWriter = new BufferedWriter(new OutputStreamWriter(socket.getOutputStream()));
            this.bufferedReader = new BufferedReader(new InputStreamReader(socket.getInputStream()));
            this.name = bufferedReader.readLine();
            this.serverPublicKey = serverPublicKey;

            clientHandlers.add(this);
            broadcastMessage("SERVER: " + name +"" +" " + " has joined the group chat");



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

                }

            } catch (IOException e){
                closeEverything(socket, bufferedReader, bufferedWriter);
            }
        }
    }
    public void removeClientHandler(){
        clientHandlers.remove(this);
        broadcastMessage("SERVER: " + name +"" +" " + "has left the chat!");

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
