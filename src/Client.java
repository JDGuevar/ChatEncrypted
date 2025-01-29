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

            // Send messages to the server
            while (true) {
                System.out.print("Enter a message: ");
                String message = reader.readLine();

                // Generate hash of the message
                byte[] messageHash = Hash.passwordKeyGeneration(message, 128).getEncoded();

                // Encrypt the message with the symmetric key
                byte[] encryptedMessage = AES_Simetric.encryptData(symmetricKey, message.getBytes());

                // Send the encrypted message
                out.writeObject(new Packet(encryptedMessage, messageHash));

                // Receive acknowledgment
                Packet acknowledgmentPacket = (Packet) in.readObject();
                byte[] decryptedAck = AES_Simetric.decryptData(symmetricKey, acknowledgmentPacket.message);
                String acknowledgment = new String(decryptedAck);

                // Verify integrity of the acknowledgment
                byte[] ackHash = Hash.passwordKeyGeneration(acknowledgment, 128).getEncoded();
                Hash.compareHash(new SecretKeySpec(ackHash, "AES"), new SecretKeySpec(acknowledgmentPacket.hash, "AES"));

                System.out.println("Server response: " + acknowledgment);
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