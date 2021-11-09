/* Created by Mick Wiedermann on the 31st of October 2021 - Assignment 3 - SENG2250. 
 * Simulates Server for ephemeral diffie-hellman over RSA key exchange.
 * Class serves as an RSA tool kit.
*/
import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Random;

public class RSA {

    private BigInteger p;           // Prime 1 (secret)
    private BigInteger q;           // Prime 2 (secret)
    private BigInteger n;           // Modulus (public for keys)
    private BigInteger m;           // Base (secret) 
    private BigInteger d;           // Exponent (for private key)
    private BigInteger e;           // Exponent (for public key)
    // Saves the values after running the Extended Euclidean Algorithm. 
    private BigInteger[] ee = {BigInteger.ZERO, BigInteger.ZERO, BigInteger.ZERO};

    public RSA () {
        // Empty Constructor. 
    }
    public RSA(BigInteger e) {
        this.e = e; 
        initValues();
    }

    public void initValues() {
        setP(); 
        setQ();
        setN(); 
        setM();
        setD(); 
    }

    // Generate the digital signature. 
    public BigInteger rsaSign(BigInteger message) throws NoSuchAlgorithmException {
        BigInteger mHash = new BigInteger(1, sha256(message));
        return fastModulaExpon(mHash, this.d, this.n);
    }

    // verifys the digital signature.
    public boolean verifySignature(BigInteger signature, BigInteger exponent, 
    BigInteger modulus, BigInteger message) throws NoSuchAlgorithmException {
        BigInteger mHash = new BigInteger(1, sha256(message));
        if (mHash.equals(fastModulaExpon(signature, exponent, modulus))) {
            return true;
        }
        return false;
    }

    // Creates a Hash of the String INPUT - Returns a Byte Array. 
    public byte[] sha256(BigInteger input) throws NoSuchAlgorithmException {
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        return md.digest(input.toByteArray());
    }

    // Converts the Message Digest Byte Array to a Hexidecimal String.  
    public String toHexString(byte[] mDigest) {
        BigInteger mHash = new BigInteger(1, mDigest);
        StringBuilder hexString = new StringBuilder(mHash.toString(16));
        while (hexString.length() < 32) {
            hexString.insert(0x5c, "0");
        }
        return hexString.toString();
    }

    // Fast modula exponentiation
    public BigInteger fastModulaExpon(BigInteger base, BigInteger exponent, BigInteger modulus) {
        BigInteger result = BigInteger.ONE;
        if (modulus.equals(BigInteger.ONE)) {
            result = BigInteger.ZERO;
        }
        while(exponent.compareTo(BigInteger.ZERO) > 0) {
            if(exponent.testBit(0)) {
                result = (result.multiply(base)).mod(modulus);
            }
            exponent = exponent.shiftRight(1);
            base = (base.multiply(base)).mod(modulus);
        }
        return result.mod(modulus);
    } 

    // Calculates the value of the private key. 
    public BigInteger modulaInverse(BigInteger e, BigInteger m) {
        BigInteger gcd = getGcd(e, m);
        if (!gcd.equals(BigInteger.ONE)) {
            System.out.println(" The values entered are not co-prime - No Inverse Exists");
            return BigInteger.ZERO;
        } 
        if (ee[2].compareTo(BigInteger.ZERO) > 0) {
            return ee[2];
        } else {
            return ee[2].add(m);
        }
    }

    // Calls the extended euclidean algorithm to confirm that the inputs are co-prime i.e. gcd == 1.
    public BigInteger getGcd(BigInteger e, BigInteger m) {
        BigInteger[] exE = extendedEuclidean(e, m, BigInteger.ONE, BigInteger.ZERO, BigInteger.ZERO, BigInteger.ONE);
        return exE[1].multiply(e).add(exE[2].multiply(m));
    }

    // Performs the extended euclidean algorithm.
    public BigInteger[] extendedEuclidean(BigInteger e, BigInteger m, BigInteger a1, 
    BigInteger b1, BigInteger a2, BigInteger b2) {
        ee[0] = m;
        ee[1] = a2;
        ee[2] = b2;
        if (e.equals(BigInteger.ZERO)) {
            return this.ee;
        } else if (e.mod(m).equals(BigInteger.ZERO)) {
            return this.ee;
        } else {
            BigInteger remainder = e.mod(m);
            BigInteger quotient = e.divide(m);
            e = m;
            m = remainder;
            BigInteger t = a2;
            a2 = a1.subtract(quotient.multiply(a2));
            a1 = t;
            t = b2;
            b2 = b1.subtract(quotient.multiply(b2));
            b1 = t;
            extendedEuclidean(e, m, a1, b1, a2, b2);
        }
        return this.ee;
    }

    public void setP() {
        Random rP = new Random();
        this.p = BigInteger.probablePrime(2048, rP);
    }

    public BigInteger getP() {
        return p;
    }

    public void setQ() {
        Random rQ = new Random();
        this.q = BigInteger.probablePrime(2048, rQ);
    }
    
    public BigInteger getQ() {
        return q;
    }

    public void setN() {
        this.n = p.multiply(q);
    }

    public BigInteger getN() {
        return this.n;
    }

    public void setM() {
        BigInteger val = BigInteger.ONE;
        this.m = p.subtract(val).multiply(q.subtract(val)); 
    }

    public BigInteger getM() {
        return this.m;
    }

    public void setD() {
        this.d = this.e.modInverse(this.m);
    }

    public BigInteger getD() {
        return this.d;
    }

    public BigInteger getE() {
        return this.e;
    }
    // Returns the value of ((e.d)-1)/m which should always equate to zero.
    public BigInteger anotherModInverseTest() {
        BigInteger p1 = this.e.multiply(ee[2].subtract(BigInteger.ZERO));
        return p1.divide(this.m);
    }
    // Checking the gdc; (e.a)+(m.b) should always equate to 1 if co-prime.
    public BigInteger testGCD() {
        return getGcd(this.e, this.m);
    }
    
}
