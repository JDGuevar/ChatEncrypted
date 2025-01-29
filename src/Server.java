import java.net.*;
import java.util.concurrent.ConcurrentHashMap;

public class Server {
    private static final int PORT = 5000;
    public static ConcurrentHashMap<Socket, ClientHandler> clients = new ConcurrentHashMap<>();

    public static void main(String[] args) {
        try (ServerSocket serverSocket = new ServerSocket(PORT)) {
            System.out.println("Servidor esperant connexions...");

            while (true) {
                Socket socket = serverSocket.accept();
                System.out.println("Nou client connectat.");
                ClientHandler clientHandler = new ClientHandler(socket);
                clients.put(socket, clientHandler);
                new Thread(clientHandler).start();
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}