/* Created by Mick Wiedermann on the 31st of October 2021 - Assignment 3 - SENG2250. 
 * Simulates client for ephemeral diffie-hellman over RSA key exchange.
 * Main executable for Client object.
*/
import java.net.*;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Scanner;
import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.io.*;
import java.math.BigInteger;
  
public class Client
{
    private Socket socket;
    private DataInputStream dataIn;
    private DataOutputStream dataOut;
    private String address;
    private int port;
    private int clientId;
    private boolean serverAuthenticated;
    private BigInteger sessionId;
    private BigInteger serverPubKey;
    private BigInteger sharedModulus;
  
    // Constructor taking in the ip address and port number. 
    public Client(String address, int port) {   
        this.address = address;
        this.port = port;
        this.socket = null;
        this.dataIn = null;
        this.dataOut = null;
        this.clientId = 3315;
    }

    public void connect2Server() throws NoSuchAlgorithmException, InvalidKeyException, NoSuchPaddingException, 
    BadPaddingException, IllegalBlockSizeException, InvalidAlgorithmParameterException, IOException {
        String one = "Once upon a time there was a very hard working student that although, " 
        + "didn't get it perfect, still deserved a great mark! ";
        setServerPubKey(Server.getPubKey()); // Retreives RSA PubKey from Server, "checks CA for status". 
        RSA rsa = new RSA(serverPubKey); // Initialises RSA tool kit congruent with server for decryption.
        DH dh = new DH();   // Generates new Diffie-Hellman private exponent and public key. 
        AES aes = new AES(); // Initialises AES Tool kit.
        BigInteger serverDigitalSig = BigInteger.ZERO; // Stores the digital sig for printing purposes. 
        String line = "";   // String to read message from input.

        try { 
            // Establish a connection.
            socket = new Socket(address, port);
            dataIn = new DataInputStream(new BufferedInputStream(socket.getInputStream())); // Takes input from terminal.
            dataOut = new DataOutputStream(socket.getOutputStream());   // Sends output to the socket.
            
            // Initiate Hello. 
            System.out.println("\nSETUP Request: \nSending HELLO ->->->\n");
            dataOut.writeInt(clientId); // Sends Client ID. 

            // Server Responds
            this.sharedModulus = new BigInteger(dataIn.readUTF());  // Receives the value of n - the modulus as the message.
            BigInteger digitalSig = new BigInteger(dataIn.readUTF()); // Receives the Digital Signature. 
            serverDigitalSig = digitalSig;

            // Verifying Digital Signature. 
            System.out.println("\t->->-> SERVER RSA PubKey and Digital Signature Received, Verifying... ");
            if (rsa.verifySignature(digitalSig, this.serverPubKey, this.sharedModulus, this.sharedModulus)) {
                dataOut.writeUTF("VERIFIED");
                this.serverAuthenticated = true;
                System.out.println("\tSignature VERIFIED! - Server Authenticated.\n");
            } else {
                System.out.println("\n\tSignature verification FAILED. Terminating Setup process. Not on my watch M.I.T.M.\n");
                dataOut.writeUTF("End");
                line = "End";
            }
            // If Server is authenticated, Client sends DH Public Key.
            if (serverAuthenticated) {
                System.out.println("SETUP: Sending ID & DH Public Key ->->->\n");
                dataOut.writeUTF(dh.getPubKey().toString()); // Sending DH Public Key. 

                // Server Responds with DH Public Key and Session Id. 
                BigInteger serverPubKeyDH = new BigInteger(dataIn.readUTF()); // Receives Servers DH Public Key.
                sessionId = new BigInteger(dataIn.readUTF()); // Receives Session ID. 
                System.out.println("\t\n->->-> SERVER DH PubKey & Session ID Received.\n" + "\tSession ID: " 
                + this.sessionId + "\n\tGenerating Shared DH Secret Key.");
                dh.setSharedPrivKey(serverPubKeyDH); // Sets the shared DH Secret Key.
                System.out.println("\tSecret Shared Diffie-Hellman Key Established. Sending confirmation ->->->\n");
                dataOut.writeUTF("COMPLETE");
                aes.setAuthenticationKey(dh.getSharedPrivKey());
            }
            
        } 
        catch(UnknownHostException u) {
            System.out.println(u);
        } 
        catch(IOException e) {
            System.out.println(e);
        }
        
        if (!line.equals("End")) {
            System.out.println("SETUP: Handshake Complete - Ephemeral Diffie-Hellman Key Exchange Complete.\n");
            dh.printSecureChanelEstablished();
            System.out.println("Type mesage to server to test encryption (type \"End\" to exit): \n");
            aes.setSessionKey(dh.getSharedPrivKey());
        }
        Scanner userInput = new Scanner(System.in);
        while (!line.equalsIgnoreCase("End")) { // keep reading until "End" is input
            try {
                line = userInput.nextLine();
                String cipher = aes.encrypt(aes.getAuthenticationKey(), line);
                dataOut.writeUTF(line);
                dataOut.writeUTF(cipher);
                System.out.println("");
            } 
            catch(IOException e) {
                System.out.println(e);
            }
        }
        System.out.println("Connection Closed \n");
        try { // Closing the connection. 
            dataIn.close();
            dataOut.close();
            socket.close();
            userInput.close();
        } catch(IOException e) {
            System.out.println(e);
        }   // Series of print statement for verifying values - desplayed once end is entered. 
        if (line.equalsIgnoreCase("End") && serverAuthenticated) {
            starBand();
            System.out.println(" ~~ VALUE OF RSA COMPONENTS ~~\n");
            System.out.println("Value of N (Server RSA Modulus): \n" + this.sharedModulus + "\n");
            System.out.println("Value of E (Server Public Key): \n" + this.serverPubKey + "\n");
            System.out.println("Digital Signature received from Server: \n" + serverDigitalSig + "\n");
            starBand();
            System.out.println(" ~~ VALUE OF DH COMPONENTS ~~\n");
            System.out.println("Value of Private Exponent: \n" + dh.getSecretExponent() + "\n");
            System.out.println("Value of Public Key: \n" + dh.getPubKey() + "\n");
            System.out.println("Value of Shared Key: \n" + dh.getSharedPrivKey() + "\n");
            starBand();
            System.out.println(" ~~ VALUE OF AES COMPONENTS ~~\n");
            System.out.println("Value of AES Session/Authentication Key: \n" + aes.getSAuthKey() + "\n");
            System.out.println("Value of Message before HMAC: \n" + one + "\n");
            System.out.println("Value of Message after HMAC \n" + aes.genHMAC(aes.getAuthenticationKey(), one) + "\n");
            System.out.print("Verifying HMAC... ");
            if (aes.verifyHMAC(aes.genHMAC(aes.getAuthenticationKey(), one), aes.getAuthenticationKey(), one)) {
                System.out.println("HMAC Verified!!\n");
            } else {
                System.out.println("HMAC Verification FAILED\n");
            }
            String encryptedMessage = aes.encrypt(aes.getAuthenticationKey(), one);
            System.out.println("Value of Encrypted Message: \n" + encryptedMessage + "\n");
            System.out.println("Value of Decrypted Message: \n" + aes.decrypt(aes.getAuthenticationKey(), encryptedMessage) + "\n");
        }
    }

    public void setSharedModulus(BigInteger n) {
        this.sharedModulus = n;
    }

    public void setServerPubKey(BigInteger e) {
        this.serverPubKey = e;
    }

    public BigInteger getSessionId() {
        return this.sessionId;
    }

    public static void starBand() {
        System.out.println("***********************************************************************************");
    }
  
    public static void main(String args[]) throws NoSuchAlgorithmException, InvalidKeyException, 
    NoSuchPaddingException, BadPaddingException, IllegalBlockSizeException, InvalidAlgorithmParameterException, IOException {
        starBand();
        Client client = new Client("127.0.0.1", 5000);
        client.connect2Server();
        starBand();
    }
}