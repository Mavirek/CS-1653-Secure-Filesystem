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

public class FileClient extends Client implements FileClientInterface {
	private Envelope filePubKey;
	private PublicKey filePK; //DH public key
	private String fingerprint;
	private EncryptDecrypt ed = new EncryptDecrypt();
	public boolean connect(final String server, final int port, String username, String password) throws IOException, ClassNotFoundException{
		if(!super.connect(server, port))
			return false;
		Envelope message = null, response = null;

		message = new Envelope("DH CHECK");
		output.writeObject(message);
		
		try{
			//receive file server pub key, then decrypt signature from fiel server
			response = (Envelope)input.readObject();
			//file server RSA public key
			PublicKey fileRSAPK = (PublicKey)response.getObjContents().get(0);
			Scanner s = new Scanner(System.in);
			//receive file server DH public key
			filePubKey = (Envelope)input.readObject();
			filePK=(PublicKey)filePubKey.getObjContents().get(0);
			/*
			//decrypt signature
			byte[] fileDHPKsignature = (byte[])filePubKey.getObjContents().get(0);
				
			byte[] fileDHPK = new byte[2048];//dec.doFinal(fileDHPKsignature);
			
			Signature signer = Signature.getInstance("SHA256withRSA");
			signer.initVerify(fileRSAPK);
			signer.update(fileDHPK);
		
			filePK = KeyFactory.getInstance("DiffieHellman","BC").generatePublic(new X509EncodedKeySpec(fileDHPK));
			*/
			if(filePK!=null)
				System.out.println("filePK not null");
			else
				System.out.println("filePK is null");
			MessageDigest digest = MessageDigest.getInstance("SHA256");
			digest.reset();
			digest.update(filePK.toString().getBytes());
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
			System.out.println("generated keypair");
			clientKA.init(clientPair.getPrivate());
			
			clientKA.doPhase(filePK,true);
			System.out.println("finished doPhase with filePK");
			MessageDigest hash = MessageDigest.getInstance("SHA256","BC");
			String clientHash = new String(hash.digest(clientKA.generateSecret()));
			message = new Envelope("SENT CLIENT PK AND HASH");
			message.addObject(clientPair.getPublic());
			message.addObject(clientHash);
			output.writeObject(message);
			System.out.println("sent client PK and hash");
			
			response = (Envelope)input.readObject();
			if(response.getMessage().equals("MATCH"))
				return true;
			return false;
			//check if symmetric keys match
			
			//if yes, return true
			//otherwise return false
		}
		catch(Exception e)
		{
			System.err.println("Error: " + e.getMessage());
			e.printStackTrace(System.err);
			return false;
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
	    try {
			output.writeObject(env);
		    env = (Envelope)input.readObject();
		    
			if (env.getMessage().compareTo("OK")==0) {
				System.out.printf("File %s deleted successfully\n", filename);				
			}
			else {
				System.out.printf("Error deleting file %s (%s)\n", filename, env.getMessage());
				return false;
			}			
		} catch (IOException e1) {
			e1.printStackTrace();
		} catch (ClassNotFoundException e1) {
			e1.printStackTrace();
		}
	    	
		return true;
	}

	public boolean download(String sourceFile, String destFile, UserToken token) {
				if (sourceFile.charAt(0)=='/') {
					sourceFile = sourceFile.substring(1);
				}
		
				File file = new File(destFile);
			    try {
			    				
				
				    if (!file.exists()) {
				    	file.createNewFile();
					    FileOutputStream fos = new FileOutputStream(file);
					    
					    Envelope env = new Envelope("DOWNLOADF"); //Success
					    env.addObject(sourceFile);
					    env.addObject(token);
					    output.writeObject(env); 
					
					    env = (Envelope)input.readObject();
					    
						while (env.getMessage().compareTo("CHUNK")==0) { 
								fos.write((byte[])env.getObjContents().get(0), 0, (Integer)env.getObjContents().get(1));
								System.out.printf(".");
								env = new Envelope("DOWNLOADF"); //Success
								output.writeObject(env);
								env = (Envelope)input.readObject();									
						}										
						fos.close();
						
					    if(env.getMessage().compareTo("EOF")==0) {
					    	 fos.close();
								System.out.printf("\nTransfer successful file %s\n", sourceFile);
								env = new Envelope("OK"); //Success
								output.writeObject(env);
						}
						else {
								System.out.printf("Error reading file %s (%s)\n", sourceFile, env.getMessage());
								file.delete();
								return false;								
						}
				    }    
					 
				    else {
						System.out.printf("Error couldn't create file %s\n", destFile);
						return false;
				    }
								
			
			    } catch (IOException e1) {
			    	
			    	System.out.printf("Error couldn't create file %s\n", destFile);
			    	return false;
			    
					
				}
			    catch (ClassNotFoundException e1) {
					e1.printStackTrace();
				}
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
			 output.writeObject(message); 
			 
			 e = (Envelope)input.readObject();
			 
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
			UserToken token) {
			
		if (destFile.charAt(0)!='/') {
			 destFile = "/" + destFile;
		 }
		
		try
		 {
			 
			 Envelope message = null, env = null;
			 //Tell the server to return the member list
			 message = new Envelope("UPLOADF");
			 message.addObject(destFile);
			 message.addObject(group);
			 message.addObject(token); //Add requester's token
			 output.writeObject(message);
			
			 
			 FileInputStream fis = new FileInputStream(sourceFile);
			 
			 env = (Envelope)input.readObject();
			 
			 //If server indicates success, return the member list
			 if(env.getMessage().equals("READY"))
			 { 
				System.out.printf("Meta data upload successful\n");
				
			}
			 else {
				
				 System.out.printf("Upload failed: %s\n", env.getMessage());
				 return false;
			 }
			 
		 	
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
					
					message.addObject(buf);
					message.addObject(new Integer(n));
					
					output.writeObject(message);
					
					
					env = (Envelope)input.readObject();
					
										
			 }
			 while (fis.available()>0);		 
					 
			 //If server indicates success, return the member list
			 if(env.getMessage().compareTo("READY")==0)
			 { 
				
				message = new Envelope("EOF");
				output.writeObject(message);
				
				env = (Envelope)input.readObject();
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

}
