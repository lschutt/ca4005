import java.io.*;
import java.math.BigInteger;
import java.util.Random;
import java.security.*;
import javax.crypto.*;

public class AssessTwo_CA4005{

  //generate random prime
  public static BigInteger generatePrime(){
    Random rnd = new Random();
    BigInteger prime = 	BigInteger.probablePrime(512, rnd);
    return prime;
  }

  //calculate phiN
  public static BigInteger eulerTotient(BigInteger p, BigInteger q){
    return p.subtract(BigInteger.ONE).multiply(q.subtract(BigInteger.ONE));
  }

  //calculate greatest common divisor
  public static BigInteger gcd(BigInteger x, BigInteger y){
    if (x.equals(BigInteger.ZERO))
      return y;
    return gcd(y.mod(x), x);
  }

  //extended Euclidean algorithm
  public static BigInteger multInv(BigInteger x, BigInteger y){
    BigInteger a = BigInteger.ONE, aPrev = BigInteger.ZERO, b = BigInteger.ZERO, bPrev = BigInteger.ONE;
    BigInteger dyx, temp;
    BigInteger origY = y;
    while(x.compareTo(BigInteger.ZERO) != 0){
      dyx = y.divide(x);
      temp = aPrev.subtract(dyx.multiply(a));
      aPrev = a;
      a = temp;

      temp = bPrev.subtract(dyx.multiply(b));
      bPrev = b;
      b = temp;

      temp = x;
      x = y.mod(x);
      y = temp;
    }
    return aPrev.add(origY).mod(origY);
  }

  //decryption method using Chinese Remainder Theorem
  public static BigInteger crt(BigInteger d, BigInteger p, BigInteger q, BigInteger input){
    BigInteger dp, dq, mp, mq, h;
    BigInteger inv = multInv(q,p);

    dp = d.mod(p.subtract(BigInteger.ONE));
    mp = input.modPow(dp, p);

    dq = d.mod(q.subtract(BigInteger.ONE));
    mq = input.modPow(dq, q);

    h = inv.multiply(mp.subtract(mq)).mod(p);
    input = mq.add(h.multiply(q));

    return input;
  }

  //256-bit digest of input file
  public static byte[] createDigest(byte[] s){
    byte[] result = new byte[0];
    try{
      MessageDigest md = MessageDigest.getInstance("SHA-256");
      result = md.digest(s);
    }
    catch(Exception e){
       e.printStackTrace(System.err);
    }
    return result;
  }

  public static String toHex(BigInteger num){
    return num.toString(16);
  }

  public static byte [] readFile(String filename){
    File inFile = new File(filename);
    int fileLength = (int)inFile.length();
    byte[] fileData = new byte[fileLength];
    try{
      DataInputStream inStream = new DataInputStream(new FileInputStream(inFile));
      inStream.readFully(fileData);
      inStream.close();
    }
    catch(Exception e){
      e.printStackTrace(System.err);
    }
    return fileData;
  }

  public static void main(String [] args){
    Boolean restart = true;
    BigInteger e = BigInteger.valueOf(65537);
    BigInteger phiN = BigInteger.ZERO, primeP = BigInteger.ZERO, primeQ = BigInteger.ZERO, n = BigInteger.ZERO;

    while(restart){
      primeP = generatePrime();
      primeQ = generatePrime();
      n = primeP.multiply(primeQ);
      phiN = eulerTotient(primeP, primeQ);

      //ensure primes are different and phi(N) is relatively prime
      if(!primeP.equals(primeQ) && gcd(phiN, e).equals(BigInteger.ONE)){
        restart = false;
      }
    }

    BigInteger d = multInv(e, phiN);

    byte [] inputFile = readFile("CrypAssignTwo_13546657");
    byte [] digest = createDigest(inputFile);

    BigInteger file = new BigInteger(1, digest);
    BigInteger encrypt = crt(d, primeP, primeQ, file);

    System.out.println("\nPrimeP: " + toHex(primeP));
    System.out.println("\nPrimeQ: " + toHex(primeQ));
    System.out.println("\nN: " + toHex(n));
    System.out.println("\nDigital Signature: " + toHex(encrypt));
  }
}
