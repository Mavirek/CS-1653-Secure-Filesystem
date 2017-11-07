import java.security.*;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import javax.crypto.SecretKey;
import javax.crypto.KeyGenerator;
import javax.crypto.Cipher;
import java.math.*;
import javax.crypto.*;

public class EncryptDecrypt {

  public EncryptDecrypt() {
      Security.addProvider(new BouncyCastleProvider());
  }

  private static final String G = (
           "FFFFFFFF FFFFFFFF C90FDAA2 2168C234 C4C6628B 80DC1CD1" +
           "29024E08 8A67CC74 020BBEA6 3B139B22 514A0879 8E3404DD" +
           "EF9519B3 CD3A431B 302B0A6D F25F1437 4FE1356D 6D51C245" +
           "E485B576 625E7EC6 F44C42E9 A637ED6B 0BFF5CB6 F406B7ED" +
           "EE386BFB 5A899FA5 AE9F2411 7C4B1FE6 49286651 ECE45B3D" +
           "C2007CB8 A163BF05 98DA4836 1C55D39A 69163FA8 FD24CF5F" +
           "83655D23 DCA3AD96 1C62F356 208552BB 9ED52907 7096966D" +
           "670C354E 4ABC9804 F1746C08 CA18217C 32905E46 2E36CE3B" +
           "E39E772C 180E8603 9B2783A2 EC07A28F B5C55DF0 6F4C52C9" +
           "DE2BCBF6 95581718 3995497C EA956AE5 15D22618 98FA0510" +
           "15728E5A 8AACAA68 FFFFFFFF FFFFFFFF")
           .replaceAll("\\s", "");


  public static byte[] hashThis(String msg) {

    MessageDigest md = null;

    try {
      md = MessageDigest.getInstance("SHA256", "BC");
  		md.update(msg.getBytes("UTF-8"));
    }
    catch(Exception e) {
      System.out.println(e);
    }

    //return new String(md.digest(msg.getBytes()));
  	 return md.digest();
  }

  /**private static String bytesToHex(byte[] in) {
 		final StringBuilder builder = new StringBuilder();
 		for(byte b : in) {
 			builder.append(String.format("%02x", b));
 		}
 		return builder.toString();
 	}**/
/**
  public static String[] rsaEncrypt(byte[] userBytes, byte[] passBytes, PublicKey pub) {

    try {

      //System.out.println("Encrypt pubKey : " + pub);

      byte[] decryptedUser;
      byte[] decryptedPassHash;

      Cipher enc = Cipher.getInstance("RSA/ECB/NoPadding", "BC");
  		enc.init(Cipher.ENCRYPT_MODE, pub);

    //  for(int x = 0; x < toEncrypt.length; x++) {

      //  toEncrypt[x] = new String (enc.doFinal(toEncrypt[x].getBytes()));
      decryptedUser = enc.doFinal(userBytes);
      decryptedPassHash = enc.doFinal(passBytes);

    //  }
    }
    catch(Exception e) {
      System.out.println(e);
    }

      return toEncrypt;
  }

  public static String[] rsaDecrypt(String[] toDecrypt, PrivateKey pri) {

    try {
      System.out.println("DECRYPT!!");
      System.out.println("Username : " + toDecrypt[0]);
      Cipher dec = Cipher.getInstance("RSA/ECB/NoPadding", "BC");
      dec.init(Cipher.DECRYPT_MODE, pri);
    //  System.out.println("DECRYPT2!!!");
      for(int x = 0; x < toDecrypt.length; x++) {

        toDecrypt[x] = new String(dec.doFinal(toDecrypt[x].getBytes()));
        System.out.println("HERE!!!!");
        if(x == 0)
          System.out.println("Decrypt username : " + toDecrypt[x]);
      }
    }
    catch(Exception e) {
      System.out.println(e);
    }

    return toDecrypt;
  }
**/
  public static String passDH(byte[] passHash) {

    BigInteger g = new BigInteger("02", 16);
    BigInteger q = new BigInteger(G, 16);
    BigInteger newPass = g.modPow(new BigInteger(passHash), q);

    return newPass.toString();
  }
}
