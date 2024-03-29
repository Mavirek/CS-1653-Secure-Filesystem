/* File worker thread handles the business of uploading, downloading, and removing files for clients with valid tokens */

import java.lang.Thread;
import java.net.Socket;
import java.util.List;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.util.*;
import java.math.*;
import java.security.*;
import java.security.NoSuchAlgorithmException;
import javax.crypto.Cipher;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.encoders.Hex;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.SecretKey;
import javax.crypto.KeyGenerator;
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.SecureRandom;
import javax.crypto.KeyAgreement;
import javax.crypto.spec.DHParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.*;
import java.net.*;


public class FileThread extends Thread
{
	private final Socket socket;
	private EncryptDecrypt ed = new EncryptDecrypt();
	private SecretKeySpec sessKey = null;
	private String serverIP;
	private int serverPort;

	public FileThread(Socket _socket, String serverIP, int serverPort)
	{
		socket = _socket;
		this.serverIP = serverIP;
		this.serverPort = serverPort;
	}
	
	public void run()
	{
		Security.addProvider(new BouncyCastleProvider());
		boolean proceed = true;
		try
		{
			System.out.println("*** New connection from " + socket.getInetAddress() + ":" + socket.getPort() + "***");
			final ObjectInputStream input = new ObjectInputStream(socket.getInputStream());
			final ObjectOutputStream output = new ObjectOutputStream(socket.getOutputStream());
			Envelope response, message=null;
			
			//System.out.println("FS pub key : " + filePubKey);
			//MessageDigest digest = MessageDigest.getInstance("SHA256");
			Envelope pubKey = new Envelope("FILE PUB KEY");
			pubKey.addObject(FileServer.filePubKey);
			//pubKey.addObject(digest); 
			output.writeObject(pubKey);

			do
			{
				Envelope enc = (Envelope)input.readObject();
				System.out.println("Request received: " + enc.getMessage());
				if(enc.getMessage().equals("DH CHECK"))
				{
					BigInteger g256 = new BigInteger(ed.getGen(),16);
					BigInteger p256 = new BigInteger(ed.getPrime(),16);

					DHParameterSpec dhParams = new DHParameterSpec(p256,g256);
					KeyPairGenerator keyGen = KeyPairGenerator.getInstance("DH","BC");
					keyGen.initialize(dhParams, new SecureRandom());

					KeyAgreement fKA = KeyAgreement.getInstance("DH","BC");
					KeyPair filePair = keyGen.generateKeyPair();

					fKA.init(filePair.getPrivate());
					//System.out.println(filePair.getPublic().toString());
					message = new Envelope("SENDING FPK");
					//sign FPK before sending

					Signature signer = Signature.getInstance("SHA256withRSA", "BC");
					signer.initSign(FileServer.filePrivKey); //sign with file server RSA priv key
					byte[] fileDHPK = filePair.getPublic().getEncoded();
					signer.update(fileDHPK);
					//signed file server DH public key
					byte[] signedFDHPK = signer.sign();
					message.addObject(signedFDHPK);

					//message.addObject(fileDHPK);

					message.addObject(filePair.getPublic());//Send this to verify.

					output.writeObject(message); //send file server public key

					response = (Envelope)input.readObject(); //receive client public key
					PublicKey clientPK = (PublicKey)response.getObjContents().get(0);
					String clientHash = (String)response.getObjContents().get(1);
					//System.out.println("client hash = "+clientHash);
					fKA.doPhase(clientPK,true);
					MessageDigest hash = MessageDigest.getInstance("SHA256","BC");
					byte[] sharedKey = Arrays.copyOfRange(fKA.generateSecret(),0,16);
					String serverHash = new String(hash.digest(sharedKey));
					//System.out.println("server hash = "+serverHash);
					if(serverHash.equals(clientHash))
					{
						response = new Envelope("MATCH");
						output.writeObject(response);
						Envelope msg = (Envelope)input.readObject();

						BigInteger challenge =(BigInteger)msg.getObjContents().get(0);
						byte[] iv = (byte[])msg.getObjContents().get(1);
						sessKey = new SecretKeySpec(sharedKey,"AES");
						Cipher ciph = Cipher.getInstance("AES/CFB/PKCS5Padding","BC");
						ciph.init(Cipher.ENCRYPT_MODE,sessKey,new IvParameterSpec(iv));
						//System.out.println("server iv = "+new String(iv));
						challenge = challenge.add(BigInteger.ONE);
						byte[] cipherText = ciph.doFinal(challenge.toByteArray());
						response = new Envelope("CHECK CHALL");

						response.addObject(cipherText);
					}
					else
					{
						response = new Envelope("FAIL");
					}
					output.writeObject(response);
				}
				else if(enc.getMessage().equals("ENC"))
				{
					Envelope e = decryptEnv(enc,sessKey);
					//System.out.println("Before null");
					if(e != null)
					{
						System.out.println("Request received: " + e.getMessage());
						if(e.getMessage().equals("Verify Sign"))
						{
							//Verify the signed hash in token with the received public key.
							Token t = (Token)e.getObjContents().get(0);
							PublicKey groupPubKey = (PublicKey)e.getObjContents().get(1);
							//System.out.println("Group Server's PublicKey in FileServer: " + groupPubKey.toString());
							System.out.println("Verifying Signature...");
							Signature signed = Signature.getInstance("SHA1WithRSA", "BC");
							signed.initVerify(groupPubKey);
							//System.out.println("Hash in Token in File Server: " + new String(t.getHash()));
							//System.out.println(t.toString());
							signed.update(t.getHash());
							if(signed.verify(t.getSignedHash())) {

								System.out.println("Sign passed");
								if(verifyServer(t)) {
									System.out.println("Server passed");
									response = new Envelope("APPROVED");
								}
								else {
									System.out.println("Server failed");
									response = new Envelope("NOT APPROVED");
								}
							}
							else {
								System.out.println("Sign failed");
								response = new Envelope("NOT APPROVED");
							}
							output.writeObject(encryptEnv(response, sessKey));
						}
						// Handler to list files that this user is allowed to see
						else if(e.getMessage().equals("LFILES"))
						{
							/* TODO: Write this handler */
							if(e.getObjContents().size() != 2)
								response = new Envelope("FAIL-BADCONTENTS");
							else if(e.getObjContents().get(0) == null)
								response = new Envelope("FAIL-BADTOKEN");
							else{
								//Change Token getGroups to the Hashtable
								UserToken ut = (Token)e.getObjContents().get(0);
								SessionID client = (SessionID)e.getObjContents().get(1);
								if(verifySessID(client))
								{
									ArrayList<ShareFile> list = FileServer.fileList.getFiles();

									ArrayList<String> groups = (ArrayList<String>)ut.getGroups();
									//System.out.println("list size: " + list.size() + " groups size: " + groups.size());
									ArrayList<String> result = new ArrayList<String>();
									for(int i = 0; i < groups.size(); i++)
									{
										for(int j = 0; j < list.size(); j++)
										{
											if(list.get(j).getGroup().equals(groups.get(i)))
											{
												//System.out.println("owner: "+list.get(j).getOwner()+" group: "+list.get(j).getGroup()+" path: "+list.get(j).getPath());
												result.add(list.get(j).getPath());
											}
										}
									}
									response = new Envelope("OK");
									response.addObject(result);
								}
								else
								{
									response = new Envelope("FAIL-BADSESSIONID");
								}
								output.writeObject(encryptEnv(response,sessKey));
							}
						}
						else if(e.getMessage().equals("UPLOADF"))
						{

							if(e.getObjContents().size() < 4)
							{
								response = new Envelope("FAIL-BADCONTENTS");
							}
							else
							{
								if(e.getObjContents().get(0) == null) {
									response = new Envelope("FAIL-BADPATH");
								}
								if(e.getObjContents().get(1) == null) {
									response = new Envelope("FAIL-BADGROUP");
								}
								if(e.getObjContents().get(2) == null) {
									response = new Envelope("FAIL-BADTOKEN");
								}
								if(e.getObjContents().get(3) == null) {

									response = new Envelope("FAIL-BADSESSIONID");
								}
								else {
									String remotePath = (String)e.getObjContents().get(0);
									String group = (String)e.getObjContents().get(1);
									UserToken yourToken = (UserToken)e.getObjContents().get(2); //Extract token
									SessionID client = (SessionID)e.getObjContents().get(3);

									int keyNum = (Integer)e.getObjContents().get(4);
									if(verifySessID(client))
									{
										if (FileServer.fileList.checkFile(remotePath)) {
											System.out.printf("Error: file already exists at %s\n", remotePath);
											response = new Envelope("FAIL-FILEEXISTS"); //Fail
										}
										else if (!yourToken.getGroups().contains(group)) {
											System.out.printf("Error: user missing valid token for group %s\n", group);
											response = new Envelope("FAIL-UNAUTHORIZED"); //Fail
										}
										else  {
											File file = new File("shared_files/"+remotePath.replace('/', '_'));
											file.createNewFile();
											FileOutputStream fos = new FileOutputStream(file);
											System.out.printf("Successfully created file %s\n", remotePath.replace('/', '_'));

											response = new Envelope("READY"); //Success
											output.writeObject(encryptEnv(response,sessKey));

											e = decryptEnv((Envelope)input.readObject(),sessKey);
											while (e.getMessage().compareTo("CHUNK")==0) {
												fos.write((byte[])e.getObjContents().get(0), 0, (Integer)e.getObjContents().get(1));
												response = new Envelope("READY"); //Success
												output.writeObject(encryptEnv(response,sessKey));
												e = decryptEnv((Envelope)input.readObject(),sessKey);
											}

											if(e.getMessage().compareTo("EOF")==0) {
												System.out.printf("Transfer successful file %s\n", remotePath);
												FileServer.fileList.addFile(yourToken.getSubject(), group, remotePath, keyNum);
												response = new Envelope("OK"); //Success
											}
											else {
												System.out.printf("Error reading file %s from client\n", remotePath);
												response = new Envelope("ERROR-TRANSFER"); //Success
											}
											fos.close();
										}
									}
									else
										response = new Envelope("FAIL-BADSESSIONID");
								}
							}
							output.writeObject(encryptEnv(response,sessKey));
						}
						else if (e.getMessage().compareTo("DOWNLOADF")==0) {

							String remotePath = (String)e.getObjContents().get(0);
							Token t = (Token)e.getObjContents().get(1);
							SessionID client = (SessionID)e.getObjContents().get(2);

							if(verifySessID(client))
							{
								ShareFile sf = FileServer.fileList.getFile("/"+remotePath);
								if (sf == null) {
									System.out.printf("Error: File %s doesn't exist\n", remotePath);
									e = new Envelope("ERROR_FILEMISSING");
									output.writeObject(encryptEnv(e,sessKey));

								}
								else if (!t.getGroups().contains(sf.getGroup())){
									System.out.printf("Error user %s doesn't have permission\n", t.getSubject());
									e = new Envelope("ERROR_PERMISSION");
									output.writeObject(encryptEnv(e,sessKey));
								}
								else {

									try
									{
										File f = new File("shared_files/_"+remotePath.replace('/', '_'));
										if (!f.exists()) {
											System.out.printf("Error file %s missing from disk\n", "_"+remotePath.replace('/', '_'));
											e = new Envelope("ERROR_NOTONDISK");
											output.writeObject(encryptEnv(e,sessKey));

										}
										else {

											e = new Envelope("KEYNUMGROUP");
											e.addObject(sf.getKeyNum());
											e.addObject(sf.getGroup());
											output.writeObject(encryptEnv(e,sessKey));
											
											e = decryptEnv((Envelope)input.readObject(),sessKey);
											FileInputStream fis = new FileInputStream(f);
											//System.out.println("decrypted response");
											//System.out.println("e = "+e.getMessage());
											do {
												byte[] buf = new byte[4096];
												if (e.getMessage().compareTo("DOWNLOADF")!=0) {
													System.out.printf("Server error: %s\n", e.getMessage());
													break;
												}
												e = new Envelope("CHUNK");
												int n = fis.read(buf); //can throw an IOException
												if (n > 0) {
													System.out.printf(".");
												} else if (n < 0) {
													System.out.println("Read error");

												}

												//System.out.println("chunk = "+new String(buf));
												//System.out.println("n = "+n);
												e.addObject(buf);
												e.addObject(new Integer(n));

												output.writeObject(encryptEnv(e,sessKey));
												//System.out.println("sent CHUNK");
												e = decryptEnv((Envelope)input.readObject(),sessKey);
												

											}
											while (fis.available()>0);
											//System.out.println("e mesg = "+e.getMessage());
											//If server indicates success, return the member list
											if(e.getMessage().compareTo("DOWNLOADF")==0)
											{

												e = new Envelope("EOF");
												output.writeObject(encryptEnv(e,sessKey));

												e = decryptEnv((Envelope)input.readObject(),sessKey);
												if(e.getMessage().compareTo("OK")==0) {
													System.out.printf("File data upload successful\n");
												}
												else {

													System.out.printf("Download failed: %s\n", e.getMessage());

												}

											}
											else {

												System.out.printf("Download failed: %s\n", e.getMessage());

											}
											fis.close(); 
										}
									}
									catch(Exception e1)
									{
										System.err.println("Error: " + e.getMessage());
										e1.printStackTrace(System.err);

									}
								}
							}
						}
						else if (e.getMessage().compareTo("DELETEF")==0) {

							String remotePath = (String)e.getObjContents().get(0);
							Token t = (Token)e.getObjContents().get(1);
							SessionID client = (SessionID)e.getObjContents().get(2); 
							if(verifySessID(client))
							{
								ShareFile sf = FileServer.fileList.getFile("/"+remotePath);
								if (sf == null) {
									System.out.printf("Error: File %s doesn't exist\n", remotePath);
									e = new Envelope("ERROR_DOESNTEXIST");
								}
								else if (!t.getGroups().contains(sf.getGroup())){
									System.out.printf("Error user %s doesn't have permission\n", t.getSubject());
									e = new Envelope("ERROR_PERMISSION");
								}
								else 
								{
									try
									{
										File f = new File("shared_files/"+"_"+remotePath.replace('/', '_'));

										if (!f.exists()) {
											System.out.printf("Error file %s missing from disk\n", "_"+remotePath.replace('/', '_'));
											e = new Envelope("ERROR_FILEMISSING");
										}
										else if (f.delete()) {
											System.out.printf("File %s deleted from disk\n", "_"+remotePath.replace('/', '_'));
											FileServer.fileList.removeFile("/"+remotePath);
											e = new Envelope("OK");
										}
										else {
											System.out.printf("Error deleting file %s from disk\n", "_"+remotePath.replace('/', '_'));
											e = new Envelope("ERROR_DELETE");
										}


									}
									catch(Exception e1)
									{
										System.err.println("Error: " + e1.getMessage());
										e1.printStackTrace(System.err);
										e = new Envelope(e1.getMessage());
									}
								}
							}
							else
								e = new Envelope("ERROR_SESSIONID");
							output.writeObject(encryptEnv(e,sessKey));
						}	

						else if(e.getMessage().equals("DISCONNECT"))
						{
							SessionID client = (SessionID)e.getObjContents().get(0); 
							if(saveSessID(client))
							{
								socket.close();
								proceed = false;
							}
						}
					}
					

				}
				

			} while(proceed);
		}
		catch(Exception e)
		{
			System.err.println("Error: " + e.getMessage());
			e.printStackTrace(System.err);
		}
	}

	private Envelope encryptEnv(Envelope msg, SecretKeySpec sessKey)
	{
		try
		{
			Cipher c = Cipher.getInstance("AES/CFB/PKCS5Padding","BC");
			SecureRandom rand = new SecureRandom();
			byte[] iv = new byte[16];
			rand.nextBytes(iv);
			c.init(Cipher.ENCRYPT_MODE,sessKey,new IvParameterSpec(iv));
			SealedObject sealedobj = new SealedObject(msg,c);
			Envelope encryptedMsg = new Envelope("ENC");
			encryptedMsg.addObject(sealedobj);
			encryptedMsg.addObject(iv);
			return encryptedMsg;
		}
		catch(Exception e)
		{
			System.out.println("Error: "+e);
			e.printStackTrace();
		}
		return null;
	}

	private Envelope decryptEnv(Envelope msg, SecretKeySpec sessKey)
	{
		boolean hashed = false;
		if(msg.getObjContents().size() == 3) hashed = true;
		SealedObject sealedobj = (SealedObject)msg.getObjContents().get(0);
		byte[] iv = (byte[])msg.getObjContents().get(1);
		byte[] hash = null;
		if(hashed) hash = (byte[]) msg.getObjContents().get(2);

		try
		{
			String alg = sealedobj.getAlgorithm();
			Cipher c = Cipher.getInstance(alg);
			c.init(Cipher.DECRYPT_MODE,sessKey,new IvParameterSpec(iv));
			Envelope message = (Envelope)sealedobj.getObject(c);

			// If message was hashed check the hash
			if(hashed)
			{
				//Remove the hash key from envelope before returning.
				//Hash key is in the last index of object contents.
				Envelope newMsg = new Envelope(message.getMessage());
				for(int i = 0; i < message.getObjContents().size() -1; i++)
					newMsg.addObject(message.getObjContents().get(i));
				SecretKeySpec key = (SecretKeySpec)message.getObjContents().get(message.getObjContents().size()-1);
				newMsg.setStringRep(message.toString());
				if(verifyHash(newMsg, hash, key))
					return newMsg;
			}
			else
				return message;

		}
		catch(Exception e)
		{
			System.out.println("Error: "+e);
			e.printStackTrace();
		}
		return null;
	}
	private boolean verifySessID(SessionID clientID)
	{
		System.out.println("Verifying SessionID..."); 

		//This is not the first time the client has connected to the server.
		//System.out.println("FileServer.sessionIDs.contains(clientID.getUserName()): " + FileServer.sessionIDs.containsKey(clientID.getUserName())); 
		if(FileServer.unacceptedSessionIDs != null)
		{
			if(FileServer.unacceptedSessionIDs.containsKey(clientID.getUserName()))
			{
				SessionID storedID = FileServer.unacceptedSessionIDs.get(clientID.getUserName()); 
				storedID.nextMsg(); 
				//System.out.println("TEST SessionID: " + clientID.toString()); 
				//The message is in unacceptedSessionIDs meaning shouldn't be accepted. 
				//System.out.println("StoredID: " + storedID.toString()); 
				//System.out.println("CurrentID: " + clientID.toString()); 
				if(storedID.equals(clientID))
					return false; 
			}
		}
		
		if(FileServer.acceptedSessionIDs.containsKey(clientID.getUserName()))
		{
			//Check date is today
			if(!clientID.isToday())

				return false; 
			
			//Get the last sessionID stored for the client 
			SessionID storedID = FileServer.acceptedSessionIDs.get(clientID.getUserName()); 

			storedID.nextMsg(); 
			//System.out.println("TEST SessionID: " + clientID.toString()); 
			//Ensure the last sessionID is one less message than the current ID. 
			if(storedID.equals(clientID))
			{
				//Replace the old stored sessionID with the current sessionID. 
				//System.out.println("SessionID: " + clientID.toString()); 
				FileServer.acceptedSessionIDs.remove(clientID.getUserName()); 
				FileServer.acceptedSessionIDs.put(clientID.getUserName(), clientID); 
				return true; 
			}
		}
		//This is the first time the client has connected
		else
		{
			//Store this sessionID in the list and accept it. 
			FileServer.acceptedSessionIDs.put(clientID.getUserName(), clientID); 
			//System.out.println("SessionID: " + clientID.toString()); 
			return true; 
		}
		return false;
	}
	private boolean saveSessID(SessionID clientID)
	{
		FileServer.acceptedSessionIDs.remove(clientID.getUserName()); 
		SessionID newClientID = new SessionID(clientID.getUserName(), clientID.getDate(), clientID.getRandNumber(), -1); 
		FileServer.unacceptedSessionIDs.put(clientID.getUserName(), newClientID); 
		//System.out.println("clientID: " + clientID.toString()); 
		//System.out.println("newClientID: " + newClientID.toString()); 
		return FileServer.unacceptedSessionIDs.containsKey(clientID.getUserName()); 
	}
	private boolean verifyHash(Envelope message, byte[] hash, SecretKeySpec key)
	{
		System.out.println("Verifying Hash...");
		try{
			Mac hmac = Mac.getInstance("Hmac-SHA256", "BC");
			hmac.init(key);
			byte[] myHash = hmac.doFinal(message.toString().getBytes());
			return (new String(myHash)).equals(new String(hash));
		}
		catch(Exception e)
		{
			System.out.println("Error: " + e);
			e.printStackTrace();
		}
		return false;
	}

	private boolean verifyServer(Token t) {

		String server = socket.getLocalAddress().toString();
		int port = socket.getLocalPort();

		try {
			System.out.println("FIle Server IP : " + InetAddress.getByName("localhost"));
		}
		catch(Exception e) {
			e.printStackTrace();
		}

		StringBuilder sb = new StringBuilder("");
		sb.append(serverIP);
		sb.append("#");
		sb.append(serverPort);
		//System.out.println(t.getFileServer());
		//System.out.println(sb.toString());
		String[] tsplit = t.getFileServer().split("#");

		try {
			//System.out.println(InetAddress.getByName(tsplit[0]).equals(socket.getLocalAddress()));
			//System.out.println(Integer.parseInt(tsplit[1]) == port);
			//System.out.println("Port : " + port);
			if(InetAddress.getByName(tsplit[0]).equals(socket.getLocalAddress()) && Integer.parseInt(tsplit[1]) == socket.getLocalPort())
				return true;
			else
				return false;
		}
		catch(Exception e) {
			e.printStackTrace();
		}

		System.out.println("ERROR");
		return false;
	}
}
