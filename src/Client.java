import java.io.*;
import java.net.*;
import java.security.PublicKey;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

public class Client {
    private static final String HOST = "localhost";
    private static final int PORT = 5000;

    public static void main(String[] args) {
        try (Socket socket = new Socket(HOST, PORT);
             ObjectOutputStream out = new ObjectOutputStream(socket.getOutputStream());
             ObjectInputStream in = new ObjectInputStream(socket.getInputStream());
             BufferedReader reader = new BufferedReader(new InputStreamReader(System.in))) {

            // Receive server's public key
            PublicKey serverPublicKey = (PublicKey) in.readObject();

            // Generate symmetric key
            SecretKey symmetricKey = AES_Simetric.keygenKeyGeneration(128);
            byte[] symmetricKeyBytes = symmetricKey.getEncoded();

            // Generate hash of the symmetric key
            byte[] symmetricKeyHash = Hash.passwordKeyGeneration(new String(symmetricKeyBytes), 128).getEncoded();

            // Encrypt the symmetric key with the server's public key
            byte[] encryptedSymmetricKey = RSA_Asimetric.encryptData(symmetricKeyBytes, serverPublicKey);

            // Send the encrypted symmetric key
            out.writeObject(new Packet(encryptedSymmetricKey, symmetricKeyHash));

            System.out.println("Symmetric key sent.");

            // Create a thread to listen for messages from the server
            new Thread(() -> {
                try {
                    while (true) {
                        Packet receivedPacket = (Packet) in.readObject();
                        byte[] decryptedData = AES_Simetric.decryptData(symmetricKey, receivedPacket.message);
                        String message = new String(decryptedData);

                        // Verify integrity of the message
                        byte[] calculatedHash = Hash.passwordKeyGeneration(message, 128).getEncoded();
                        
                        if (Hash.compareHash(new SecretKeySpec(calculatedHash, "AES"), new SecretKeySpec(receivedPacket.hash, "AES"))) {
                            System.out.println("\rReceived: " + message);
                            //System.out.println("Enter a message: ");
                        } else {
                            System.err.println("Error: Message integrity check failed.");
                        }
                    }
                } catch (Exception e) {
                    e.printStackTrace();
                }
            }).start();

            System.out.print("Enter a message: ");
            // Send messages to the server
            while (true) {
                
                String message = reader.readLine();

                // Generate hash of the message
                byte[] messageHash = Hash.passwordKeyGeneration(message, 128).getEncoded();

                // Encrypt the message with the symmetric key
                byte[] encryptedMessage = AES_Simetric.encryptData(symmetricKey, message.getBytes());

                // Send the encrypted message
                out.writeObject(new Packet(encryptedMessage, messageHash));
                Thread.sleep(200);
            }
        } catch (Exception e) {
            if (e instanceof SocketException) {
                System.err.println("Server is down!");
            } else {
                System.err.println("Error: " + e);
            }
        }
    }
}