/* Implements the GroupClient Interface */

import java.util.ArrayList;
import java.util.List;
import java.io.ObjectInputStream;
import java.io.*;
import java.util.*;
import java.util.Random;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.macs.HMac;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.util.encoders.Hex;
import javax.crypto.Mac;
import java.security.*;
import javax.crypto.*;
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

public class GroupClient extends Client implements GroupClientInterface {
     // Get group server's public key
	 private Envelope groupPubKey;
	 private PublicKey groupPK;
	 private EncryptDecrypt ed = new EncryptDecrypt();
	 private SecureRandom random = new SecureRandom();
	 private byte[] challengeD = new byte[4];
	 private SecretKeySpec sessKey;
	 private SessionID client = null; 
 	 public boolean connect(final String server, final int port, String username, String password) throws IOException, ClassNotFoundException{
		if(!super.connect(server, port))
			return false;
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

			//SRP6Client client = new SRP6Client();
    	//client.init(new BigInteger(ed.getPrime(), 16), new BigInteger(ed.getGen(), 16), new SHA256Digest(), random);
			//BigInteger A = client.generateClientCredentials((byte[])message.getObjContents().get(1), userBytes, passHashBytes);
			//message = new Envelope("genSecret");
			//message.addObject(A);
			//output.writeObject(message);
			//Envelope incoming = (Envelope)input.readObject();
			//BigInteger B = (BigInteger)incoming.getObjContents().get(0);
			//System.out.println("N : " + new BigInteger(ed.getPrime(), 16).toString());
			//System.out.println("g : " + new BigInteger(ed.getGen(), 16).toString());
			//System.out.println("userBytes : " + new BigInteger(userBytes).toString());
			//System.out.println("passBytes : " + new BigInteger(passHashBytes).toString());
			//System.out.println("B : " + B.toString());
			//System.out.println("A : " + A.toString());
			//BigInteger clientS = null;
			//try {
			//	clientS = client.calculateSecret(B);
			//}
			//catch(Exception e) {
			//	e.printStackTrace();
			//}
			//System.out.println("Client Secret : " + clientS.toString());
		}
		return false;

	 }
	 public void disconnect()
	 {
		 try
		 {
			 Envelope message = new Envelope("DISCONNECT"); 
			 message.addObject(client); 
			 output.writeObject(encryptEnv(message)); 
		 }
		 catch(Exception e)
		 {
			System.err.println("Error: " + e.getMessage());
			e.printStackTrace(System.err);
		 }
		 
		 
	 }
	 public UserToken getToken(String username)
	 {
		try
		{
			UserToken token = null;
			Envelope message = null, response = null;

			//Tell the server to return a token.
			message = new Envelope("GET");
			message.addObject(username); //Add user name string
			message.addObject(client);
			output.writeObject(encryptEnv(message));

			//Get the response from the server
			response = decryptEnv((Envelope)input.readObject());
			client.nextMsg(); 
			//Successful response
			if(response.getMessage().equals("OK"))
			{
				//If there is a token in the Envelope, return it
				ArrayList<Object> temp = null;
				temp = response.getObjContents();

				if(temp.size() == 3)
				{
					String t = (String)temp.get(0);
					byte[] signedHash = (byte[])temp.get(1);
					byte[] hash = (byte[])temp.get(2);
					token = new Token(t, signedHash, hash);
					System.out.println("Token Created");
					return token;
				}
			}

			return null;
		}
		catch(Exception e)
		{
			System.err.println("Error: " + e.getMessage());
			e.printStackTrace(System.err);
			return null;
		}

	 }

	 public boolean createUser(String username, String password, UserToken token)
	 {
		 try
			{
				Envelope message = null, response = null;
				//Tell the server to create a user
				message = new Envelope("CUSER");
				message.addObject(username); //Add user name string
				message.addObject(password);
				message.addObject(token); //Add the requester's token
				message.addObject(client); 
				output.writeObject(encryptEnv(message));

				response = decryptEnv((Envelope)input.readObject());
				client.nextMsg(); 
				//If server indicates success, return true
				if(response.getMessage().equals("OK"))
				{
					return true;
				}

				return false;
			}
			catch(Exception e)
			{
				System.err.println("Error: " + e.getMessage());
				e.printStackTrace(System.err);
				return false;
			}
	 }

	 public boolean deleteUser(String username, UserToken token)
	 {
		 try
			{
				Envelope message = null, response = null;

				//Tell the server to delete a user
				message = new Envelope("DUSER");
				message.addObject(username); //Add user name
				message.addObject(token);  //Add requester's token
				message.addObject(client); 
				output.writeObject(encryptEnv(message));

				response = decryptEnv((Envelope)input.readObject());
				client.nextMsg(); 
				//If server indicates success, return true
				if(response.getMessage().equals("OK"))
				{
					return true;
				}

				return false;
			}
			catch(Exception e)
			{
				System.err.println("Error: " + e.getMessage());
				e.printStackTrace(System.err);
				return false;
			}
	 }

	 public boolean createGroup(String groupname, UserToken token)
	 {
		 try
			{
				Envelope message = null, response = null;
				//Tell the server to create a group
				message = new Envelope("CGROUP");
				message.addObject(groupname); //Add the group name string
				message.addObject(token); //Add the requester's token
				message.addObject(client); 
				output.writeObject(encryptEnv(message));

				response = decryptEnv((Envelope)input.readObject());
				client.nextMsg(); 
				//If server indicates success, return true
				if(response.getMessage().equals("OK"))
				{
					return true;
				}

				return false;
			}
			catch(Exception e)
			{
				System.err.println("Error: " + e.getMessage());
				e.printStackTrace(System.err);
				return false;
			}
	 }

	 public boolean deleteGroup(String groupname, UserToken token)
	 {
		 try
			{
				Envelope message = null, response = null;
				//Tell the server to delete a group
				message = new Envelope("DGROUP");
				message.addObject(groupname); //Add group name string
				message.addObject(token); //Add requester's token
				message.addObject(client); 
				output.writeObject(encryptEnv(message));

				response = decryptEnv((Envelope)input.readObject());
				client.nextMsg(); 
				//If server indicates success, return true
				if(response.getMessage().equals("OK"))
				{
					return true;
				}

				return false;
			}
			catch(Exception e)
			{
				System.err.println("Error: " + e.getMessage());
				e.printStackTrace(System.err);
				return false;
			}
	 }

	 @SuppressWarnings("unchecked")
	public List<String> listMembers(String group, UserToken token)
	 {
		 try
		 {
			 Envelope message = null, response = null;
			 //Tell the server to return the member list
			 message = new Envelope("LMEMBERS");
			 message.addObject(group); //Add group name string
			 message.addObject(token); //Add requester's token
			 message.addObject(client); 
			 output.writeObject(encryptEnv(message));

			 response = decryptEnv((Envelope)input.readObject());
			 client.nextMsg(); 
			 //If server indicates success, return the member list
			 if(response.getMessage().equals("OK"))
			 {
				//ArrayList<String> list = (ArrayList<String>)response.getObjContents().get(0);
				//System.out.println(Arrays.toString(list.toArray(new String[list.size()])));
				return (List<String>)response.getObjContents().get(0); //This cast creates compiler warnings. Sorry.
			 }

			 return null;

		 }
		 catch(Exception e)
			{
				System.err.println("Error: " + e.getMessage());
				e.printStackTrace(System.err);
				return null;
			}
	 }

	 public boolean addUserToGroup(String username, String groupname, UserToken token)
	 {
		 try
			{
				Envelope message = null, response = null;
				//Tell the server to add a user to the group
				message = new Envelope("AUSERTOGROUP");
				message.addObject(username); //Add user name string
				message.addObject(groupname); //Add group name string
				message.addObject(token); //Add requester's token
				message.addObject(client); 
				output.writeObject(encryptEnv(message));

				response = decryptEnv((Envelope)input.readObject());
				client.nextMsg(); 
				//If server indicates success, return true
				if(response.getMessage().equals("OK"))
				{
					return true;
				}

				return false;
			}
			catch(Exception e)
			{
				System.err.println("Error: " + e.getMessage());
				e.printStackTrace(System.err);
				return false;
			}
	 }

	 public boolean deleteUserFromGroup(String username, String groupname, UserToken token)
	 {
		 try
			{
				Envelope message = null, response = null;
				//Tell the server to remove a user from the group
				message = new Envelope("RUSERFROMGROUP");
				message.addObject(username); //Add user name string
				message.addObject(groupname); //Add group name string
				message.addObject(token); //Add requester's token
				message.addObject(client); 
				output.writeObject(encryptEnv(message));

				response = decryptEnv((Envelope)input.readObject());
				client.nextMsg(); 
				//If server indicates success, return true
				if(response.getMessage().equals("OK"))
				{
					return true;
				}

				return false;
			}
			catch(Exception e)
			{
				System.err.println("Error: " + e.getMessage());
				e.printStackTrace(System.err);
				return false;
			}
	 }

	 public PublicKey getGroupPubKey()
	 {
		 return groupPK;
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

 	private Envelope decryptEnv(Envelope msg)
 	{
 		SealedObject sealedobj = (SealedObject)msg.getObjContents().get(0);
 		byte[] iv = (byte[])msg.getObjContents().get(1);
 		try
 		{
 			String alg = sealedobj.getAlgorithm();
 			Cipher c = Cipher.getInstance(alg);
 			c.init(Cipher.DECRYPT_MODE,sessKey,new IvParameterSpec(iv));
 			return (Envelope)sealedobj.getObject(c);
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
