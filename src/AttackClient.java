import java.util.*;
import java.util.Random;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.macs.HMac;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.util.encoders.Hex;
import javax.crypto.Mac;
import java.security.*;
import javax.crypto.*;
import java.io.*;

import java.math.*;
import org.bouncycastle.crypto.agreement.srp.SRP6Client;
import org.bouncycastle.crypto.agreement.srp.SRP6Server;
import org.bouncycastle.crypto.agreement.srp.SRP6Util;
import org.bouncycastle.crypto.agreement.srp.SRP6VerifierGenerator;
import org.bouncycastle.crypto.digests.SHA256Digest;
import javax.crypto.KeyAgreement;
import javax.crypto.spec.DHParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import javax.crypto.spec.IvParameterSpec;
import java.security.spec.X509EncodedKeySpec;


public class AttackClient extends Client {
     // Get group server's public key
	 private Envelope groupPubKey;
	 private PublicKey groupPK;
	 private EncryptDecrypt ed = new EncryptDecrypt();
	 private SecureRandom random = new SecureRandom();
	 private byte[] challengeD = new byte[4];
	 private SecretKeySpec sessKey;
   private SessionID client = null;
	 private String fileServer;
	 private int filePort;

  public boolean connect(final String server, final int port, String username, String password, String fileServer, int filePort) throws IOException, ClassNotFoundException{
   if(!super.connect(server, port))
     return false;

   this.fileServer = fileServer;
   this.filePort = filePort;
   Envelope message = null, response = null;
   client = new SessionID(username);
   groupPubKey = (Envelope)input.readObject();
   groupPK = (PublicKey)groupPubKey.getObjContents().get(0);

   message = new Envelope("CHECK");

   byte[] userBytes = username.getBytes();
   byte[] passHashBytes = ed.hashThis(password);

   byte[] encryptedUser = null;
   byte[] encryptedPassHash = null;

   try {
     Cipher enc = Cipher.getInstance("RSA/ECB/NoPadding", "BC");
     enc.init(Cipher.ENCRYPT_MODE, groupPK);
     encryptedUser = enc.doFinal(userBytes);
     encryptedPassHash = enc.doFinal(passHashBytes);
   }
   catch(Exception e) {
     System.out.println(e);
   }
   message.addObject(encryptedUser);  //Enc username
   message.addObject(encryptedPassHash);  //Enc password hash
   output.writeObject(message);
   response = (Envelope)input.readObject();

   if(response.getMessage().equals("USER AUTHORIZED")) {
     //response = (Envelope)input.readObject();
     PublicKey dhPK=(PublicKey)response.getObjContents().get(0);
     byte[] groupDHPK = dhPK.getEncoded();
     byte[] challengeC = (byte[])response.getObjContents().get(1);

     try {
       dhPK = KeyFactory.getInstance("DiffieHellman","BC").generatePublic(new X509EncodedKeySpec(groupDHPK));
       BigInteger g256 = new BigInteger(ed.getGen(),16);
       BigInteger p256 = new BigInteger(ed.getPrime(),16);

       DHParameterSpec dhParams = new DHParameterSpec(p256,g256);
       KeyPairGenerator keyGen = KeyPairGenerator.getInstance("DH","BC");
       keyGen.initialize(dhParams, new SecureRandom());

       KeyAgreement clientKA = KeyAgreement.getInstance("DH","BC");
       KeyPair clientPair = keyGen.generateKeyPair();
       clientKA.init(clientPair.getPrivate());

       clientKA.doPhase(dhPK,true);
       byte[] sharedKey = Arrays.copyOfRange(clientKA.generateSecret(),0,16);
       System.out.println("Shared Key : " + new BigInteger(sharedKey));

       byte[] iv = new byte[16];
       random.nextBytes(iv);
       sessKey = new SecretKeySpec(sharedKey,"AES");
       Cipher ciph = Cipher.getInstance("AES/CFB/PKCS5Padding","BC");
       ciph.init(Cipher.ENCRYPT_MODE,sessKey,new IvParameterSpec(iv));

       byte[] encC = ciph.doFinal(challengeC);
       random.nextBytes(challengeD);

       message = new Envelope("Challenge");
       message.addObject(clientPair.getPublic());
       message.addObject(encC);
       message.addObject(iv);
       message.addObject(challengeD);
       output.writeObject(message);

       Envelope incoming = (Envelope)input.readObject();
       if(incoming.getMessage().equals("Match")) {
         ciph.init(Cipher.DECRYPT_MODE,sessKey,new IvParameterSpec(iv));
         byte[] decD = ciph.doFinal((byte[])incoming.getObjContents().get(0));

         if(Arrays.equals(challengeD, decD))
           return true;
       }
     }
     catch(Exception e) {
       e.printStackTrace();
     }
   }
   return false;

  }

  public void attack() {
    try {
      Envelope att = new Envelope("GET");
      att.addObject("jak244");
      att.addObject("localhost");
      att.addObject(4321);
      att.addObject(client);
      output.writeObject(encryptEnv(att));
    }
    catch(Exception e) {
      e.printStackTrace();
    }
  }

  private Envelope encryptEnv(Envelope msg)
 {
   try
   {
     // Generate Hmac hash
     SecretKeySpec key = genKey();
     byte[] hash = genHash(msg.toString(), key);
     msg.addObject(key); //Add key used for hmac hash gen.
     // Encrypt original Envelope
     Cipher c = Cipher.getInstance("AES/CFB/PKCS5Padding","BC");
     SecureRandom rand = new SecureRandom();
     byte[] iv = new byte[16];
     rand.nextBytes(iv);
     c.init(Cipher.ENCRYPT_MODE,sessKey,new IvParameterSpec(iv));
     SealedObject sealedobj = new SealedObject(msg,c);
     Envelope encryptedMsg = new Envelope("ENC");
     encryptedMsg.addObject(sealedobj);
     encryptedMsg.addObject(iv);
     encryptedMsg.addObject(hash);
     return encryptedMsg;
   }
   catch(Exception e)
   {
     System.out.println("Error: "+e);
     e.printStackTrace();
   }
   return null;
 }

 public byte[] genHash(String message, SecretKeySpec key)
 {
   try{
     Mac hmac = Mac.getInstance("Hmac-SHA256", "BC");
     hmac.init(key);
     return hmac.doFinal(message.getBytes());
   }
   catch(Exception e)
   {
     System.out.println("Error: " + e);
     e.printStackTrace();
   }
   return null;
 }
 public SecretKeySpec genKey()
 {
   SecureRandom random = new SecureRandom();
   byte[] keyBytes = new byte[16];
   random.nextBytes(keyBytes);
   return new SecretKeySpec(keyBytes, "AES");
 }
}
