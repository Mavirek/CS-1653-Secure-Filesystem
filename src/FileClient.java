/* FileClient provides all the client functionality regarding the file server */
import java.util.*;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.util.List;
import java.util.Random;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.macs.HMac;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.util.encoders.Hex;
import javax.crypto.Mac;
import java.security.*;
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.SecureRandom;
import javax.crypto.KeyAgreement;
import javax.crypto.spec.DHParameterSpec;
import java.security.spec.X509EncodedKeySpec;
import java.security.PublicKey;
import javax.crypto.spec.SecretKeySpec;
import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.*;


public class FileClient extends Client implements FileClientInterface {
	private Envelope filePubKey;
	private PublicKey filePK; //DH public key
	private String fingerprint;
	private EncryptDecrypt ed = new EncryptDecrypt();
	private SecretKeySpec dhKey = null;

	private SessionID client = null;
	private String serverName;
	public boolean connect(final String server, final int port, String username, String password) throws IOException, ClassNotFoundException{
		if(!super.connect(server, port))
			return false;
		client = new SessionID(username);
		//this.server = server;

		Envelope message = null, response = null;

		message = new Envelope("DH CHECK");
		output.writeObject(message);

		try{
			//receive file server pub key, then decrypt signature from file server
			//System.out.println("HEREEEEEEE");
			response = (Envelope)input.readObject();
			//file server RSA public key
			PublicKey fileRSAPK = (PublicKey)response.getObjContents().get(0);
			//MessageDigest digest = (MessageDigest) response.getObjContents().get(1); 
			Scanner s = new Scanner(System.in);
			//receive file server DH public key
			filePubKey = (Envelope)input.readObject();


			//decrypt signature
			byte[] fileDHPKsignature = (byte[])filePubKey.getObjContents().get(0);

			filePK=(PublicKey)filePubKey.getObjContents().get(1);
			//MessageDigest digest = (MessageDigest)filePubKey.getObjContents().get(2); 
			byte[] fileDHPK = filePK.getEncoded(); //new byte[2048];//dec.doFinal(fileDHPKsignature);
			Signature signer = Signature.getInstance("SHA256withRSA");
			signer.initVerify(fileRSAPK);
			signer.update(fileDHPK);
			boolean validSign = signer.verify(fileDHPKsignature);
			if(validSign)
				filePK = KeyFactory.getInstance("DiffieHellman","BC").generatePublic(new X509EncodedKeySpec(fileDHPK));


			/*
			if(filePK!=null)
				System.out.println("filePK not null");
			else
				System.out.println("filePK is null");
			*/
			MessageDigest digest = MessageDigest.getInstance("SHA256");
			//digest.reset();
			digest.update(fileRSAPK.toString().getBytes());
			fingerprint = ed.bytesToHex(digest.digest());
			System.out.println("File server fingerprint: "+fingerprint);
			System.out.println("Accept? [y]es or [n]o");
			char accept = s.next().charAt(0);
			if(accept=='n' || accept=='N')
			{
				System.out.println("Aborting file server connection...");
				return false;
			}

			//Diffie Hellman

			BigInteger g256 = new BigInteger(ed.getGen(),16);
			BigInteger p256 = new BigInteger(ed.getPrime(),16);

			DHParameterSpec dhParams = new DHParameterSpec(p256,g256);
			KeyPairGenerator keyGen = KeyPairGenerator.getInstance("DH","BC");
			keyGen.initialize(dhParams, new SecureRandom());

			KeyAgreement clientKA = KeyAgreement.getInstance("DH","BC");
			KeyPair clientPair = keyGen.generateKeyPair();
			//System.out.println("generated keypair");
			clientKA.init(clientPair.getPrivate());
			clientKA.doPhase(filePK,true);
			//System.out.println("finished doPhase with filePK");
			MessageDigest hash = MessageDigest.getInstance("SHA256","BC");
			byte[] sharedKey = Arrays.copyOfRange(clientKA.generateSecret(),0,16);
			String clientHash = new String(hash.digest(sharedKey));
			message = new Envelope("SENT CLIENT PK AND HASH");
			message.addObject(clientPair.getPublic());
			message.addObject(clientHash);
			output.writeObject(message);
			//System.out.println("sent client PK and hash");
			//if yes, return true
			//otherwise return false
			response = (Envelope)input.readObject();
			//System.out.println("after response");
			if(response.getMessage().equals("MATCH"))
			{
				//System.out.print("entered if");
				byte[] iv = new byte[16];
				SecureRandom rand = new SecureRandom();
				rand.nextBytes(iv);
				//System.out.println("client iv = "+new String(iv));
				dhKey = new SecretKeySpec(sharedKey,"AES");
				//Cipher ciph = Cipher.getInstance("AES/CFB/PKCS5Padding","BC");
				//ciph.init(Cipher.ENCRYPT_MODE,dhKey);
				BigInteger challenge = new BigInteger(32, new SecureRandom());
				//System.out.println("challenge = "+challenge.toString());
				//KeyChallenge kc = new KeyChallenge(challenge,dhKey);
				//SealedObject outCiph = new SealedObject(challenge,ciph);
				message = new Envelope("Sending keyChallenge Info");
				message.addObject(challenge);
				message.addObject(iv);
				output.writeObject(message);
				//receives challenge respnose from server
				response = (Envelope)input.readObject();
				//SealedObject sealedobj = (SealedObject)response.getObjContents().get(0);
				//String alg = sealedobj.getAlgorithm();
				//Cipher ciph = Cipher.getInstance(alg);
				/*Cipher ciph = Cipher.getInstance("AES/CFB/PKCS5Padding","BC");
				ciph.init(Cipher.DECRYPT_MODE,dhKey,new IvParameterSpec(iv));
				byte[] cipherText = (byte[]) response.getObjContents().get(0);
				byte[] plainText = ciph.doFinal(cipherText);
				BigInteger CR = new BigInteger(plainText); //(BigInteger)sealedobj.getObject(ciph);
				*/ 
				byte[] challengeResponse = (byte[])response.getObjContents().get(0);
				Cipher ciph = Cipher.getInstance("AES/CFB/PKCS5Padding","BC");
				ciph.init(Cipher.DECRYPT_MODE,dhKey,new IvParameterSpec(iv));
				byte[] plainText = ciph.doFinal(challengeResponse); 
				BigInteger CR = new BigInteger(plainText);
				
				if(CR.compareTo(challenge.add(BigInteger.ONE))==0)
					return true;
				else
				{
					System.out.println("Challenge response failed");
				}
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

	public void disconnect()
	{
		Envelope message = new Envelope("DISCONNECT");
		message.addObject(client);
		try
		{
			Cipher c = Cipher.getInstance("AES/CFB/PKCS5Padding","BC");
			SecureRandom rand = new SecureRandom();
			byte[] iv = new byte[16];
			rand.nextBytes(iv);
			c.init(Cipher.ENCRYPT_MODE,dhKey,new IvParameterSpec(iv));
			SealedObject sealedobj = new SealedObject(message,c);
			Envelope encryptedMsg = new Envelope("ENC");
			encryptedMsg.addObject(sealedobj);
			encryptedMsg.addObject(iv);
			output.writeObject(encryptedMsg);
		}
		catch(Exception e)
		{
			System.out.println("Error: "+e);
			e.printStackTrace();
		}
	}

	public boolean delete(String filename, UserToken token) {
		String remotePath;
		if (filename.charAt(0)=='/') {
			remotePath = filename.substring(1);
		}
		else {
			remotePath = filename;
		}
		Envelope env = new Envelope("DELETEF"); //Success
	    env.addObject(remotePath);
	    env.addObject(token);
		env.addObject(client); //ADD SessionID
		env.setStringRep(remotePath + ":" + token.toString() + ":" + client.toString()); 
	    try {
			env = secureMsg(env);
			client.nextMsg(); 
			//output.writeObject(env);
		    //env = (Envelope)input.readObject();
		    
			if (env.getMessage().compareTo("OK")==0) {
				System.out.printf("File %s deleted successfully\n", filename);
			}
			else {
				System.out.printf("Error deleting file %s (%s)\n", filename, env.getMessage());
				return false;
			}
		} catch (Exception e1) {
			e1.printStackTrace();
		} /* catch (ClassNotFoundException e1) {
			e1.printStackTrace();
		} */
		return true;
	}

	public boolean download(String sourceFile, String destFile, UserToken token, Hashtable<String, ArrayList<SecretKey>> gk) {
		if (sourceFile.charAt(0)=='/') {
			sourceFile = sourceFile.substring(1);
		}

		File file = new File(destFile);
		try {		
		
			if (!file.exists()) {
				//System.out.println("does not exist");
				file.createNewFile();
				FileOutputStream fos = new FileOutputStream(file);
				int keyNum;
				String group;
				Envelope env = new Envelope("DOWNLOADF"); //Success
				env.addObject(sourceFile);
				env.addObject(token);
				env.addObject(client); 
				env.setStringRep(sourceFile + ":" + token.toString() + ":" + client.toString()); 
				env = secureMsg(env);
				client.nextMsg(); 
				//output.writeObject(env); 
			
				//env = (Envelope)input.readObject();
				//System.out.println("env message = "+env.getMessage());
				if(env.getMessage().equals("KEYNUMGROUP"))
				{
					//System.out.println("received KEYNUMGROUP");
					keyNum = (Integer)env.getObjContents().get(0);
					group = (String)env.getObjContents().get(1);
					//System.out.println("Decrypting with keyNum  "+keyNum+" for group: "+group);
					env = secureMsg(new Envelope("DOWNLOADF"));
				}
				else
				{
					System.out.println("Error receiving key number and group info");
					file.delete();
					return false;
				}
				
				Cipher ciph = Cipher.getInstance("AES/CTR/NoPadding","BC");
				byte[] ivarray = Arrays.copyOf(group.getBytes(),16);
				//System.out.println("download iv = "+new String(ivarray));
				ArrayList<SecretKey> keys = gk.get(group);
				SecretKey key = keys.get(keyNum);
				//System.out.println("group = "+group+" keyNum = "+keyNum);
				while (env.getMessage().compareTo("CHUNK")==0) {
						//System.out.println("started chunking");
						//System.out.println("key = "+key);
						ciph.init(Cipher.DECRYPT_MODE,key, new IvParameterSpec(ivarray));
						byte[] envContents = (byte[])env.getObjContents().get(0);
						//System.out.println("envContents = "+new String(envContents));
						byte[] plainText = ciph.doFinal(envContents);
						//System.out.println("plainText = "+new String(plainText));
						fos.write(plainText, 0, (Integer)env.getObjContents().get(1));
						System.out.printf(".");
						env = new Envelope("DOWNLOADF"); //Success
						env = secureMsg(env);
						//output.writeObject(env);
						//env = (Envelope)input.readObject();
				}
				fos.close();
        
				if(env.getMessage().compareTo("EOF")==0) {
					 fos.close();
						System.out.printf("\nTransfer successful file %s\n", sourceFile);
						env = new Envelope("OK"); //Success
						//output.writeObject(env);
						try
						{
							Cipher c = Cipher.getInstance("AES/CBC/PKCS5Padding","BC");
							//Cipher c = Cipher.getInstance("AES/CFB/PKCS5Padding","BC");
              
							SecureRandom rand = new SecureRandom();
							byte[] iv = new byte[16];
							rand.nextBytes(iv);
							c.init(Cipher.ENCRYPT_MODE,dhKey,new IvParameterSpec(iv));
							SealedObject sealedobj = new SealedObject(env,c);
							Envelope encryptedMsg = new Envelope("ENC");
							encryptedMsg.addObject(sealedobj);
							encryptedMsg.addObject(iv);
							output.writeObject(encryptedMsg);
						}
						catch(Exception e)
						{
							System.out.println("Error: "+e);
							e.printStackTrace();
						}
				}
				else {
						System.out.printf("Error reading file %s (%s)\n", sourceFile, env.getMessage());
						file.delete();
						return false;								
				}
			}    
			 
			else {
				//System.out.println("inner else");
				System.out.printf("Error couldn't create file %s\n", destFile);
				return false;
			}
						
	
		} catch (Exception e1) {
			//System.out.println("outer catch");
			System.out.printf("Error couldn't create file %s\n", destFile);
			System.out.println(e1.getMessage());
			return false;
		}
		/* catch (ClassNotFoundException e1) {
			e1.printStackTrace();
		} */
		 return true;
	}

	@SuppressWarnings("unchecked")
	public List<String> listFiles(UserToken token) {
		 try
		 {
			 Envelope message = null, e = null;
			 //Tell the server to return the member list
			 message = new Envelope("LFILES");
			 message.addObject(token); //Add requester's token
			 message.addObject(client);
			 message.setStringRep(token.toString() + ":" + client.toString()); 
			 e = secureMsg(message);
			 client.nextMsg(); 
			 //output.writeObject(message); 
			 
			 //e = (Envelope)input.readObject();
			
			 //If server indicates success, return the member list
			 if(e.getMessage().equals("OK"))
			 {
				return (List<String>)e.getObjContents().get(0); //This cast creates compiler warnings. Sorry.
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

	public boolean upload(String sourceFile, String destFile, String group,
			UserToken token, Hashtable<String, ArrayList<SecretKey>> gk) {
			
		if (destFile.charAt(0)!='/') {
			 destFile = "/" + destFile;
		 }

		try
		 {
			 ArrayList<SecretKey> groupKeys = gk.get(group);
			 Envelope message = null, env = null;
			 //Tell the server to return the member list
			 message = new Envelope("UPLOADF");
			 message.addObject(destFile);
			 message.addObject(group);
			 message.addObject(token); //Add requester's token
			 message.addObject(client);
			 message.addObject(groupKeys.size()-1); //key version		
			 message.setStringRep(destFile + ":" + group + ":" + token.toString() + ":" + client.toString()); 
			 //output.writeObject(message);
			
			 
			 FileInputStream fis = new FileInputStream(sourceFile);
			 env = secureMsg(message);
			 client.nextMsg(); 
			 //env = (Envelope)input.readObject();
			 //If server indicates success, return the member list
			 if(env.getMessage().equals("READY"))
			 {
				System.out.printf("Meta data upload successful\n");
			 }
			 else {

				 System.out.printf("Upload failed: %s\n", env.getMessage());
				 return false;
			 }
			 
			Cipher ciph = Cipher.getInstance("AES/CTR/NoPadding", "BC");
			byte[] iv = Arrays.copyOf(group.getBytes(),16);
			//System.out.println("upload iv = "+new String(iv));
			//get the most recent key for that group
			SecretKey key = groupKeys.get(groupKeys.size()-1);
			//System.out.println("upload key = "+key);
			System.out.println("Encrypting with keyNum "+(groupKeys.size()-1)+" for group: "+group);
			 do {
				 byte[] buf = new byte[4096];
				 	if (env.getMessage().compareTo("READY")!=0) {
				 		System.out.printf("Server error: %s\n", env.getMessage());
				 		return false;
				 	}
				 	message = new Envelope("CHUNK");
					int n = fis.read(buf); //can throw an IOException
					if (n > 0) {
						System.out.printf(".");
					} else if (n < 0) {
						System.out.println("Read error");
						return false;
					}

					ciph.init(Cipher.ENCRYPT_MODE,key,new IvParameterSpec(iv));
					byte[] cipherText = ciph.doFinal(buf);
					message.addObject(cipherText);
					message.addObject(new Integer(n));
					//ask sai about changing buf to cipherText
					message.setStringRep(new String(buf) + ":" + n); 
					env = secureMsg(message);
					//output.writeObject(message);
					
					
					//env = (Envelope)input.readObject();
			 }
			 while (fis.available()>0);

			 //If server indicates success, return the member list
			 if(env.getMessage().compareTo("READY")==0)
			 {

				message = new Envelope("EOF");
				//output.writeObject(message);
				//env = (Envelope)input.readObject();
				env = secureMsg(message);
				if(env.getMessage().compareTo("OK")==0) {
					System.out.printf("\nFile data upload successful\n");
				}
				else {

					 System.out.printf("\nUpload failed: %s\n", env.getMessage());
					 return false;
				 }

			}
			 else {

				 System.out.printf("Upload failed: %s\n", env.getMessage());
				 return false;
			 }

		 }catch(Exception e1)
			{
				System.err.println("Error: " + e1.getMessage());
				e1.printStackTrace(System.err);
				return false;
				}
		 return true;
	}

	//The four methods below will verify that the signature matches with the file server and then proceed to the desired methods. 
	public boolean delete(String filename, UserToken token, PublicKey groupPubKey) throws IOException, ClassNotFoundException{
		//Verify signature in file server
		Envelope message = new Envelope("Verify Sign"); 
		message.addObject(token); 
		message.addObject(groupPubKey); 
		message.setStringRep(token.toString() + ":" + groupPubKey.toString()); 
		//output.writeObject(message); 
		Envelope incoming = secureMsg(message); //(Envelope)input.readObject(); 
		if(incoming.getMessage().equals("APPROVED"))
		{
			System.out.println("Signature Approved, Proceeding to delete..."); 
			return delete(filename, token); 
		}
		else if(incoming.getMessage().equals("NOT APPROVED"))
			System.out.println("Signature was not Approved!!!"); 

		return false; 
	}
	public boolean download(String sourceFile, String destFile, UserToken token, PublicKey groupPubKey, Hashtable<String, ArrayList<SecretKey>> gk) throws IOException, ClassNotFoundException{
		//Verify signature in file server
		Envelope message = new Envelope("Verify Sign");
		message.addObject(token); 
		message.addObject(groupPubKey); 
		message.setStringRep(token.toString() + ":" + groupPubKey.toString()); 
		//output.writeObject(message); 
		Envelope incoming = secureMsg(message); //(Envelope)input.readObject(); 
		if(incoming.getMessage().equals("APPROVED"))
		{
			System.out.println("Signature Approved, Proceeding to download..."); 
			return download(sourceFile, destFile, token, gk);
		}
		else if(incoming.getMessage().equals("NOT APPROVED"))
			System.out.println("Signature was not Approved!!!");  

		return false;
	}
	@SuppressWarnings("unchecked")
	public List<String> listFiles(UserToken token, PublicKey groupPubKey) throws IOException, ClassNotFoundException{
		//Verify signature in file server
		Envelope message = new Envelope("Verify Sign"); 
		message.addObject(token); 
		message.addObject(groupPubKey); 
		message.setStringRep(token.toString() + ":" + groupPubKey.toString()); 
		//output.writeObject(message); 
		Envelope incoming = secureMsg(message); //(Envelope)input.readObject();  
		if(incoming.getMessage().equals("APPROVED"))
		{
			System.out.println("Signature Approved, Proceeding to listFiles..."); 
			return listFiles(token); 
		}
		else if(incoming.getMessage().equals("NOT APPROVED"))
			System.out.println("Signature was not Approved!!!"); 
		
		return null; 
	}
	public boolean upload(String sourceFile, String destFile, String group, UserToken token, PublicKey groupPubKey, Hashtable<String, ArrayList<SecretKey>> gk) throws IOException, ClassNotFoundException{
		//Verify signature in file server
		Envelope message = new Envelope("Verify Sign"); 
		message.addObject(token); 
		message.addObject(groupPubKey); 
		message.setStringRep(token.toString() + ":" + groupPubKey.toString()); 
		//output.writeObject(message); 
		Envelope incoming = secureMsg(message); //(Envelope)input.readObject(); 
		if(incoming.getMessage().equals("APPROVED"))
		{
			System.out.println("Signature Approved, Proceeding to upload..."); 
			return upload(sourceFile, destFile, group, token, gk);
		}
		else if(incoming.getMessage().equals("NOT APPROVED"))
			System.out.println("Signature was not Approved!!!"); 
		
		return false; 
	}
	
	public Envelope secureMsg (Envelope message) {
		try {
			// Generate Hmac hash 
			SecretKeySpec key = genKey(); 
			byte[] hash = genHash(message.toString(), key);
			message.addObject(key); //Add key used for hmac hash gen. 
			// Encrypt original Envelope
			Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding", "BC");
			SecureRandom IV = new SecureRandom();
			byte IVarray[] = new byte[16];
			IV.nextBytes(IVarray);
			cipher.init(Cipher.ENCRYPT_MODE, dhKey, new IvParameterSpec(IVarray));
			SealedObject outCipher = new SealedObject(message, cipher);
			// Create new Envelope with encrypted data and IV
			Envelope cipherMsg = new Envelope("ENC");
			Envelope encResponse = null;
			cipherMsg.addObject(outCipher);
			cipherMsg.addObject(IVarray);
			cipherMsg.addObject(hash);
			output.writeObject(cipherMsg);
			// Get and decrypt response
			encResponse = (Envelope)input.readObject();
			if (encResponse.getMessage().equals("ENC")) {
				// Decrypt Envelope contents
				SealedObject inCipher = (SealedObject)encResponse.getObjContents().get(0);
				IVarray = (byte[])encResponse.getObjContents().get(1);
				String algo = inCipher.getAlgorithm();
				Cipher envCipher = Cipher.getInstance(algo);
				envCipher.init(Cipher.DECRYPT_MODE, dhKey, new IvParameterSpec(IVarray));
				return (Envelope)inCipher.getObject(envCipher);
			}
		}
		catch(Exception e) {
			System.out.println("Error: " + e);
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
