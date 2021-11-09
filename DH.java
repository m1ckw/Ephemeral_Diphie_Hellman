/* Created by Mick Wiedermann on the 31st of October 2021 - Assignment 3 - SENG2250. 
 * Simulates Server for ephemeral diffie-hellman over RSA key exchange.
 * Class serves as the Diffie-Hellman tool kit.
*/
import java.math.BigInteger;
import java.util.Random;

public class DH {
    // The agreed modulus p & base g between the client & server. 
    private static final BigInteger p = new BigInteger(
        "17801190547854226652823756245015999014523215636912067427327445031444"+
        "28657887370207706126952521234630795671567847784664499706507709207278"+
        "57050009668388144034129745221171818506047231150039301079959358067395"+
        "34871706631980226201971496652413506094591370759495651467285569060679"+
        "4135837542707371727429551343320695239");
    private static final BigInteger g = new BigInteger(
        "17406820753240209518581198012352343653860449079456135097849583104059"+
        "99534884558231478515974089409507253077970949157594923683005742524387"+
        "61037084473467180148876118103083043754985190983472601550494691329488"+
        "08339549231385000036164648264460849230407872181895999905649609776936"+
        "8017749273708962006689187956744210730");
    private BigInteger secretExponent;
    private BigInteger publicKey;
    private BigInteger sharedPrivKey;

    public DH () {
        setSecretExponent();
        setPubKey();
    }
     
    // Fast modula exponentiation
    public BigInteger fastModulaExpon(BigInteger base, BigInteger exponent, BigInteger modulus) {
        BigInteger result = BigInteger.ONE;
        if (modulus.equals(BigInteger.ONE)) {
            result = BigInteger.ZERO;
        }
        while(exponent.compareTo(BigInteger.ZERO) > 0) {
            if(exponent.testBit(1)) {
                result = (result.multiply(base)).mod(modulus);
            }
            exponent = exponent.shiftRight(1);
            base = (base.multiply(base)).mod(modulus);
        }
        return result;
    }

    public static BigInteger getDHp() {
        return p;
    }    

    public static BigInteger getDHg() {
        return g;
    }

    public void setSecretExponent() {
        Random privExpo = new Random();
        this.secretExponent = new BigInteger(256, privExpo);
    }

    public BigInteger getSecretExponent() {
        return this.secretExponent;
    }

    public void setPubKey() {
        this.publicKey = fastModulaExpon(g, getSecretExponent(), p);
    }

    public BigInteger getPubKey() {
        return this.publicKey;
    }

    public void setSharedPrivKey(BigInteger targetsPubKey) {
        this.sharedPrivKey = fastModulaExpon(targetsPubKey, this.secretExponent, p);
    }

    public BigInteger getSharedPrivKey() {
        return this.sharedPrivKey;
    }

    public void printSecureChanelEstablished() {
        System.out.println("***********************************************************************************");
        System.out.println("\t\t~~ SECURE COMMUNICATION CHANNEL ESTABLISHED ~~");
        System.out.println("***********************************************************************************\n");
    }

}
