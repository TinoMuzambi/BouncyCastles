import java.io.IOException;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;

public class Server {

    private ServerSocket serverSocket;
    KeyPair pair = Hashing.generateKeyPair();
    private final PrivateKey privateKey = pair.getPrivate();
    private final PublicKey publicKey = pair.getPublic();

    public Server(ServerSocket serverSocket) throws GeneralSecurityException {
        this.serverSocket = serverSocket;
    }

    public void startServer() throws IOException {
        System.err.println("SERVER STARTED");

        while (!serverSocket.isClosed()) {
            Socket socket = serverSocket.accept();
            System.out.println("Connection established!");
            ClientHandler clientHandler = new ClientHandler(socket, publicKey);

            Thread thread = new Thread(clientHandler);
            thread.start();
        }
    }

    public void closeServerSocket() {
        try {
            if (serverSocket != null) {
                serverSocket.close();
            }
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    public static void main(String[] args) throws IOException, GeneralSecurityException {
        Hashing.installProvider();
        ServerSocket serverSocket = new ServerSocket(1235);
        Server server = new Server(serverSocket);
        server.startServer();

    }
}

