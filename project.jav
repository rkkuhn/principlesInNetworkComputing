Copy code
import javax.crypto.*;
import java.security.*;
import java.io.*;
import java.net.*;

public class EncryptionUtils {
    // Generate an AES encryption key
    public static SecretKey generateAESKey() throws NoSuchAlgorithmException {
        KeyGenerator keyGen = KeyGenerator.getInstance("AES");
        keyGen.init(256); // Key size (128, 192, or 256 bits)
        return keyGen.generateKey();
    }
    
    // Encrypt data using AES encryption
    public static byte[] encryptAES(byte[] plaintext, SecretKey secretKey) throws Exception {
        Cipher cipher = Cipher.getInstance("AES");
        cipher.init(Cipher.ENCRYPT_MODE, secretKey);
        return cipher.doFinal(plaintext);
    }

    // Decrypt data using AES decryption
    public static byte[] decryptAES(byte[] ciphertext, SecretKey secretKey) throws Exception {
        Cipher cipher = Cipher.getInstance("AES");
        cipher.init(Cipher.DECRYPT_MODE, secretKey);
        return cipher.doFinal(ciphertext);
    }
}

public class HostServer {
    public static void main(String[] args) {
        int port = 12345;
        try {
            ServerSocket serverSocket = new ServerSocket(port);
            System.out.println("Host is waiting for connections on port " + port);
            
            while (true) {
                Socket clientSocket = serverSocket.accept();
                // Handle the client connection (e.g., start a new thread or process)
            }
        } catch (IOException e) {
            e.printStackTrace();
        }
    }
}

public class Client {
    public static void main(String[] args) {
        String hostName = "localhost"; // Replace with the host's IP address or hostname
        int port = 12345;
        
        try {
            Socket socket = new Socket(hostName, port);
            
            // Establish input and output streams for communication
            OutputStream out = socket.getOutputStream();
            InputStream in = socket.getInputStream();
            
            // Perform encryption and decryption as needed
            SecretKey secretKey = EncryptionUtils.generateAESKey();
            
            // Send and receive encrypted messages
            // Implement your message handling logic here
            
            // Close the socket when done
            socket.close();
        } catch (IOException | NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
    }
}
These comments provide explanations for the key generation, encryption, and decryption processes, as well as basic information about setting up the server and client. Remember to implement the actual messaging logic, message serialization, and any necessary error handling according to your application's requirements.




