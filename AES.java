/* Created by Mick Wiedermann on the 31st of October 2021 - Assignment 3 - SENG2250. 
 * Simulates Server for ephemeral diffie-hellman over RSA key exchange.
 * Class serves as the AES tool kit.
*/
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Base64;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public class AES {
    
    private IvParameterSpec initV;
    private BigInteger opad;
    private BigInteger ipad;
    private String authKey;
    private String sessionKey;

    // Constructor - Initialises the values of the Opad, Ipad, & IV. 
    public AES() {
        setOpad();
        setIpad();
        setRandomIv();
    }

    // Encrypts using AES symmetric encryption
    public String encrypt(String sKey, String message) throws NoSuchPaddingException, 
    NoSuchAlgorithmException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException, InvalidAlgorithmParameterException {
        byte[] dKey = sKey.getBytes(StandardCharsets.UTF_8);  
        SecretKeySpec key = new SecretKeySpec(dKey, 0, dKey.length, "AES");
        Cipher cipher = Cipher.getInstance("AES/CTR/NoPadding");
        cipher.init(Cipher.ENCRYPT_MODE, key, initV);
        byte[] cipherText = cipher.doFinal(message.getBytes());
        return Base64.getEncoder().encodeToString(cipherText);
    }

    // Decrypts using AES symmetric decryption
    public String decrypt(String sKey, String cipherText) throws NoSuchPaddingException, 
    NoSuchAlgorithmException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException, InvalidAlgorithmParameterException {       
        byte[] dKey = sKey.getBytes(StandardCharsets.UTF_8);
        SecretKeySpec key = new SecretKeySpec(dKey, 0, dKey.length, "AES");
        Cipher cipher = Cipher.getInstance("AES/CTR/NoPadding");
        cipher.init(Cipher.DECRYPT_MODE, key, initV);
        byte[] plainText = cipher.doFinal(Base64.getDecoder().decode(cipherText));
        return new String(plainText);
    }

    // Generates random initial vector. 
    public void setRandomIv() {
        byte[] iv = new byte[16];
        new SecureRandom().nextBytes(iv);
        this.initV = new IvParameterSpec(iv);
    }

    // Generates a HMAC from the massage passed using the sessionKey. 
    public String genHMAC(String sessionKey, String message) throws NoSuchAlgorithmException {
        BigInteger key = new BigInteger(sessionKey.getBytes(StandardCharsets.UTF_8));
        return toHexString(sha256(key.xor(opad).toString() + key.xor(ipad).toString() + message));
    }

    // Verifys the HMAC
    public boolean verifyHMAC(String hmac, String sessionKey, String message) throws NoSuchAlgorithmException {
        return hmac.equals(genHMAC(sessionKey, message));
    }

    // Creates a Hash of a String - Returns a Byte Array. 
    public byte[] sha256(String input) throws NoSuchAlgorithmException {
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        return md.digest(input.getBytes(StandardCharsets.UTF_8));
    }

    // Creates a Hash of a BigInt INPUT - Returns a Byte Array. 
    public byte[] sha256(BigInteger input) throws NoSuchAlgorithmException {
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        return md.digest(input.toByteArray());
    }

    // Converts the Message Digest Byte Array to a Hexidecimal String.  
    public String toHexString(byte[] mDigest) {
        BigInteger mHash = new BigInteger(1, mDigest);
        StringBuilder hexString = new StringBuilder(mHash.toString(16));
        while (hexString.length() < 16) {
            hexString.insert(0x0, "0");
        }
        return hexString.toString();
    }

    // Generates a string for the Opad and iPad to be Xored with the sessionKey. 
    public String genPad(String value, int itterations) {
        StringBuilder pad = new StringBuilder();
        for (int i=0; i<itterations; i++) {
            pad.append(value);
        }
        return pad.toString();
    }

    public void setOpad() {
        this.opad = new BigInteger(genPad("5c", 32), 16);
    }

    public void setIpad() {
        this.ipad = new BigInteger(genPad("36", 32), 16);
    }

    // Generates the sessionKey from the secret Symmetric Diffie-Hellman Key.
    public void setSessionKey(BigInteger dhSecretKey) throws NoSuchAlgorithmException {
        this.authKey = toHexString(sha256(dhSecretKey));
    }

    public String getSAuthKey() {
        return this.authKey;
    }

    // Generates the authKey from the secret Symmetric Diffie-Hellman Key.
    public void setAuthenticationKey(BigInteger dhSecretKey) throws NoSuchAlgorithmException {
        String hexKey = toHexString(sha256(dhSecretKey));
        //int length = (hexKey.length())/2;
        StringBuilder finalKey =  new StringBuilder();
        for (int i=0; i<32; i++) {
            finalKey.append(hexKey.charAt(i));
        }
        this.sessionKey = finalKey.toString();
    }

    public String getAuthenticationKey() {
        return this.sessionKey;
    }

}
