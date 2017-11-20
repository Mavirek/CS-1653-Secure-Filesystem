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


public class FileThread extends Thread
{
	private final Socket socket;
	private EncryptDecrypt ed = new EncryptDecrypt();

	public FileThread(Socket _socket)
	{
		socket = _socket;
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
			KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA", "BC");
			kpg.initialize(2048);
			KeyPair kp = kpg.generateKeyPair();
			PrivateKey filePrivKey = kp.getPrivate();
			PublicKey filePubKey = kp.getPublic();
			System.out.println("FS pub key : " + filePubKey);
			Envelope pubKey = new Envelope("FILE PUB KEY");
			pubKey.addObject(filePubKey);
			output.writeObject(pubKey);
			
			
			
			
			do
			{
				Envelope e = (Envelope)input.readObject();
				System.out.println("Request received: " + e.getMessage());

				// Handler to list files that this user is allowed to see
				if(e.getMessage().equals("LFILES"))
				{
				    /* TODO: Write this handler */
					if(e.getObjContents().size() != 1)
						response = new Envelope("FAIL-BADCONTENTS"); 
					else if(e.getObjContents().get(0) == null)
						response = new Envelope("FAIL-BADTOKEN"); 
					else{
						//Change Token getGroups to the Hashtable 
						UserToken ut = (Token)e.getObjContents().get(0); 
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
						output.writeObject(response); 
					}
				}
				else if(e.getMessage().equals("Verify Sign"))
				{
					//Verify the signed hash in token with the received public key. 
					Token t = (Token)e.getObjContents().get(0); 
					PublicKey groupPubKey = (PublicKey)e.getObjContents().get(1); 
					System.out.println("Group Server's PublicKey in FileServer: " + groupPubKey.toString()); 
					System.out.println("Verifying Signature..."); 
					Signature signed = Signature.getInstance("SHA1WithRSA", "BC");
					signed.initVerify(groupPubKey);
					System.out.println("Hash in Token in File Server: " + new String(t.getHash())); 
					signed.update(t.getHash()); 
					if(signed.verify(t.getSignedHash()))
						response = new Envelope("APPROVED"); 
					else 
						response = new Envelope("NOT APPROVED"); 
					output.writeObject(response); 
				}
				else if(e.getMessage().equals("DH CHECK"))
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
					/* NEED A BYTE ARRAY THAT'S THE SIZE OF THE MESSAGE BEING SIGNED
					Signature signer = Signature.getInstance("SHA1withRSA");
					signer.initSign(filePrivKey); //sign with file server RSA priv key
					byte[] fileDHPK = filePair.getPublic().getEncoded();
					signer.update(fileDHPK);
					//signed file server DH public key
					byte[] signedFDHPK = signer.sign();
					message.addObject(signedFDHPK);
					*/
					message.addObject(filePair.getPublic());
					output.writeObject(message); //send file server public key
					//do
					//{
					response = (Envelope)input.readObject(); //receive client public key
					//}while(response == null);
					PublicKey clientPK = (PublicKey)response.getObjContents().get(0);
					String clientHash = (String)response.getObjContents().get(1);
					System.out.println("client hash = "+clientHash);
					fKA.doPhase(clientPK,true);
					MessageDigest hash = MessageDigest.getInstance("SHA256","BC");
					byte[] sharedKey = Arrays.copyOfRange(fKA.generateSecret(),0,16);
					String serverHash = new String(hash.digest(sharedKey));
					System.out.println("server hash = "+serverHash);
					if(serverHash.equals(clientHash))
					{
						response = new Envelope("MATCH");
						/* Encrypted challenge isn't giving the same decrypted value because of the IVs being different. 
						POSSIBLE SOLUTION SEND CIPHER OBJECT. 
						output.writeObject(response);
						
						response = (Envelope)input.readObject();
						BigInteger c = (BigInteger)response.getObjContents().get(0);
						System.out.println("generating AES key");
						SecretKeySpec dhKey = new SecretKeySpec(sharedKey,"AES");
						Cipher ciph = Cipher.getInstance("AES/CFB/PKCS5Padding","BC");
						ciph.init(Cipher.ENCRYPT_MODE,dhKey);
						byte[] encryptedChallenge = ciph.doFinal(c.toByteArray());
						response = new Envelope("Sending encrypted C");
						response.addObject(encryptedChallenge);
						output.writeObject(response);
						*/
					}
					else
					{
						response = new Envelope("FAIL");
					}
					output.writeObject(response);
				}
				else if(e.getMessage().equals("UPLOADF"))
				{

					if(e.getObjContents().size() < 3)
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
						else {
							String remotePath = (String)e.getObjContents().get(0);
							String group = (String)e.getObjContents().get(1);
							UserToken yourToken = (UserToken)e.getObjContents().get(2); //Extract token

							if (FileServer.fileList.checkFile(remotePath)) {
								System.out.printf("Error: file already exists at %s\n", remotePath);
								response = new Envelope("FAIL-FILEEXISTS"); //Success
							}
							else if (!yourToken.getGroups().contains(group)) {
								System.out.printf("Error: user missing valid token for group %s\n", group);
								response = new Envelope("FAIL-UNAUTHORIZED"); //Success
							}
							else  {
								File file = new File("shared_files/"+remotePath.replace('/', '_'));
								file.createNewFile();
								FileOutputStream fos = new FileOutputStream(file);
								System.out.printf("Successfully created file %s\n", remotePath.replace('/', '_'));

								response = new Envelope("READY"); //Success
								output.writeObject(response);

								e = (Envelope)input.readObject();
								while (e.getMessage().compareTo("CHUNK")==0) {
									fos.write((byte[])e.getObjContents().get(0), 0, (Integer)e.getObjContents().get(1));
									response = new Envelope("READY"); //Success
									output.writeObject(response);
									e = (Envelope)input.readObject();
								}

								if(e.getMessage().compareTo("EOF")==0) {
									System.out.printf("Transfer successful file %s\n", remotePath);
									FileServer.fileList.addFile(yourToken.getSubject(), group, remotePath);
									response = new Envelope("OK"); //Success
								}
								else {
									System.out.printf("Error reading file %s from client\n", remotePath);
									response = new Envelope("ERROR-TRANSFER"); //Success
								}
								fos.close();
							}
						}
					}

					output.writeObject(response);
				}
				else if (e.getMessage().compareTo("DOWNLOADF")==0) {

					String remotePath = (String)e.getObjContents().get(0);
					Token t = (Token)e.getObjContents().get(1);
					ShareFile sf = FileServer.fileList.getFile("/"+remotePath);
					if (sf == null) {
						System.out.printf("Error: File %s doesn't exist\n", remotePath);
						e = new Envelope("ERROR_FILEMISSING");
						output.writeObject(e);

					}
					else if (!t.getGroups().contains(sf.getGroup())){
						System.out.printf("Error user %s doesn't have permission\n", t.getSubject());
						e = new Envelope("ERROR_PERMISSION");
						output.writeObject(e);
					}
					else {

						try
						{
							File f = new File("shared_files/_"+remotePath.replace('/', '_'));
						if (!f.exists()) {
							System.out.printf("Error file %s missing from disk\n", "_"+remotePath.replace('/', '_'));
							e = new Envelope("ERROR_NOTONDISK");
							output.writeObject(e);

						}
						else {
							FileInputStream fis = new FileInputStream(f);

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


								e.addObject(buf);
								e.addObject(new Integer(n));

								output.writeObject(e);

								e = (Envelope)input.readObject();


							}
							while (fis.available()>0);

							//If server indicates success, return the member list
							if(e.getMessage().compareTo("DOWNLOADF")==0)
							{

								e = new Envelope("EOF");
								output.writeObject(e);

								e = (Envelope)input.readObject();
								if(e.getMessage().compareTo("OK")==0) {
									System.out.printf("File data upload successful\n");
								}
								else {

									System.out.printf("Upload failed: %s\n", e.getMessage());

								}

							}
							else {

								System.out.printf("Upload failed: %s\n", e.getMessage());

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
				else if (e.getMessage().compareTo("DELETEF")==0) {

					String remotePath = (String)e.getObjContents().get(0);
					//System.out.println("remotePath = "+remotePath);
					Token t = (Token)e.getObjContents().get(1);
					ShareFile sf = FileServer.fileList.getFile("/"+remotePath);
					if (sf == null) {
						System.out.printf("Error: File %s doesn't exist\n", remotePath);
						e = new Envelope("ERROR_DOESNTEXIST");
					}
					else if (!t.getGroups().contains(sf.getGroup())){
						System.out.printf("Error user %s doesn't have permission\n", t.getSubject());
						e = new Envelope("ERROR_PERMISSION");
					}
					else {

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
					output.writeObject(e);

				}
				else if(e.getMessage().equals("DISCONNECT"))
				{
					socket.close();
					proceed = false;
				}
			} while(proceed);
		}
		catch(Exception e)
		{
			System.err.println("Error: " + e.getMessage());
			e.printStackTrace(System.err);
		}
	}

}
