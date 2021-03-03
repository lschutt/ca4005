import java.io.*;
import java.math.BigInteger;
import java.util.Random;
import java.security.*;
import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;


public class CrypAssignOne_13546657{

  public static BigInteger privateKey(){
    Random rnd = new Random();
    BigInteger key = new BigInteger(1023, 128, rnd);
    return key;
  }

  public static String toHex(BigInteger num){
    return num.toString(16);
  }

  public static BigInteger toDecimal(String hex){
    return new BigInteger(hex, 16);
  }

  public static String byteArrayToHex(byte[] bytes) {
    String result = "";
    for(byte b : bytes) {
        result = result + String.format("%02x", b);
    }
    return result;
  }

  //right to left method
  public static BigInteger modularExp(BigInteger a, BigInteger b, BigInteger c){
    BigInteger result = new BigInteger("1");
    BigInteger numTwo = new BigInteger("2");
    while (b.compareTo(BigInteger.ZERO) != 0){
      if (b.mod(numTwo).equals(BigInteger.ONE)){
        result = result.multiply(a).mod(c);
      }
      b = b.shiftRight(1);
      a = a.multiply(a).mod(c);
    }
    return result;
  }

  public static byte[] createDigest(BigInteger s){
    byte[] result = new byte[0];
    try{
      MessageDigest md = MessageDigest.getInstance("SHA-256");
      result = md.digest(s.toByteArray());
    }
    catch(Exception e){
       e.printStackTrace(System.err);
    }
    return result;
  }

  public static IvParameterSpec createIv(){
    SecureRandom rnd = new SecureRandom();
    byte[] iv = new byte[16];
    rnd.nextBytes(iv);
    IvParameterSpec result = new IvParameterSpec(iv);
    return result;
  }

  //calculate padding for block size
  public static int calculatePadding(File file){
    int fileLength = (int)file.length();
    int marker = fileLength % 16;
    int blockPadding = 16 - marker;
    int result = 0;
    if(marker == 0){
      result = fileLength + 16;
    }
    else{
      result = fileLength + blockPadding;
    }
    return result;
  }

  // padding starting with 1 bit followed by 0 bits
  public static byte[] createPadding(int fileSize, int paddedSize){
    int size = paddedSize - fileSize;
    byte[] result = new byte[size];
    result[0] = (byte)128;
    return result;
  }

  public static void encryptFile(byte[] key, IvParameterSpec iv){
    try{
      SecretKeySpec k = new SecretKeySpec(key, "AES");
      Cipher cip = Cipher.getInstance("AES/CBC/NoPadding");
      cip.init(Cipher.ENCRYPT_MODE, k, iv);
      File inFile = new File("CrypAssignOne_13546657.zip");
      File outFile = new File("CrypAssignOne_13546657en.zip");
      int fileLength = (int)inFile.length();
      int paddingFile = calculatePadding(inFile);
      byte[] fileData = new byte[fileLength];
      byte[] paddedFileData = new byte[paddingFile];
      byte[] padding = createPadding(fileLength, paddingFile);
      DataInputStream inStream = new DataInputStream(new FileInputStream(inFile));
      inStream.readFully(fileData);

      System.arraycopy(fileData, 0, paddedFileData, 0, fileData.length);
      System.arraycopy(padding, 0, paddedFileData, fileData.length, padding.length);

      //print file in hex
      System.out.println("\nFile in Hexadecimal: " + byteArrayToHex(cip.doFinal(paddedFileData)));

      //encrypt as zip
      FileOutputStream os = new FileOutputStream(outFile);
      CipherOutputStream outputStream = new CipherOutputStream(os, cip);
      outputStream.write(paddedFileData);

      inStream.close();
      os.flush();
      os.close();
      outputStream.flush();
      outputStream.close();
    }
    catch(Exception e){
      e.printStackTrace(System.err);
    }
  }

  // method used to test decryption
  // public static void decryptFile(byte[] key, IvParameterSpec iv){
  //   try{
  //     SecretKeySpec k = new SecretKeySpec(key, "AES");
  //     Cipher cip = Cipher.getInstance("AES/CBC/NoPadding");
  //     cip.init(Cipher.DECRYPT_MODE, k, iv);
  //     File inFile = new File("CrypAssignOne_13546657en.zip");
  //     File outFile = new File("CrypAssignOne_13546657de.zip");
  //
  //     int fileLength = (int)inFile.length();
  //     byte[] fileData = new byte[fileLength];
  //
  //     DataInputStream inStream = new DataInputStream(new FileInputStream(inFile));
  //     inStream.readFully(fileData);
  //
  //     FileOutputStream os = new FileOutputStream(outFile);
  //     CipherOutputStream outputStream = new CipherOutputStream(os, cip);
  //     outputStream.write(fileData);
  //
  //     inStream.close();
  //     os.flush();
  //     os.close();
  //     outputStream.flush();
  //     outputStream.close();
  //   }
  //   catch(Exception e){
  //     e.printStackTrace(System.err);
  //   }
  // }


  public static void main(String [] args){
    String modulus = "b59dd79568817b4b9f6789822d22594f376e6a9abc0241846de426e5dd8f6edd"
                      +"ef00b465f38f509b2b18351064704fe75f012fa346c5e2c442d7c99eac79b2bc"
                      +"8a202c98327b96816cb8042698ed3734643c4c05164e739cb72fba24f6156b6f"
                      +"47a7300ef778c378ea301e1141a6b25d48f1924268c62ee8dd3134745cdf7323";
    String generator = "44ec9d52c8f9189e49cd7c70253c2eb3154dd4f08467a64a0267c9defe4119f2"
                      +"e373388cfa350a4e66e432d638ccdc58eb703e31d4c84e50398f9f91677e8864"
                      +"1a2d2f6157e2f4ec538088dcf5940b053c622e53bab0b4e84b1465f5738f5496"
                      +"64bd7430961d3e5a2e7bceb62418db747386a58ff267a9939833beefb7a6fd68";
    String publicKeyA = "5af3e806e0fa466dc75de60186760516792b70fdcd72a5b6238e6f6b76ece1f1"
                      +"b38ba4e210f61a2b84ef1b5dc4151e799485b2171fcf318f86d42616b8fd8111"
                      +"d59552e4b5f228ee838d535b4b987f1eaf3e5de3ea0c403a6c38002b49eade15"
                      +"171cb861b367732460e3a9842b532761c16218c4fea51be8ea0248385f6bac0d";
    BigInteger privateKeyB = privateKey();
    System.out.println("My private key: " + toHex(privateKeyB));

    BigInteger publicKeyB = modularExp(toDecimal(generator), privateKeyB, toDecimal(modulus));
    System.out.println("\nMy public key: " + toHex(publicKeyB));

    BigInteger sharedKey = modularExp(toDecimal(publicKeyA), privateKeyB, toDecimal(modulus));
    System.out.println("\nShared key: " + toHex(sharedKey));

    byte[] key = createDigest(sharedKey);
    IvParameterSpec iv = createIv();
    System.out.println("\nIV: " + byteArrayToHex(iv.getIV()));

    encryptFile(key, iv);
    // decryptFile(key, iv);
  }
}
