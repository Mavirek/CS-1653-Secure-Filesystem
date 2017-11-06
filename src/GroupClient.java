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
public class GroupClient extends Client implements GroupClientInterface {
     // Get group server's public key 
	 private Envelope groupPubKey = (Envelope)input.readObject(); 
	 private PublicKey groupPK = groupPubKey.getObjContents().get(0);
	 
 	 public boolean connect(final String server, final int port, String username, String password) {
		if(!super(server, port))
			return false; 
		Envelope message = null, response = null; 
		message = new Envelope("CHECK"); 
		
		//encrypt username and password use groupPK to encrypt
		//Generate a hash of the password
		Cipher enc = Cipher.getInstance("RSA/ECB/PKCS1Padding", "BC"); 
		enc.init(Cipher.ENCRYPT_MODE, groupPK); 
		String encryptedHash = enc.doFinal(hash("key", password).toByteArray()); //Need to change hash to sha from HMAC-sha
		String encryptedUN = enc.doFinal(username.toByteArray()); 
		
		message.addObject(encryptedUN);
		message.addObject(encryptedHash); 
		output.writeObject(message); 
		response = (Envelope)input.readObject(); 
		if(response.getMessage().equals("USER AUTHORIZED"))
			return true; 
		return false; 
		
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
			output.writeObject(message);
		
			//Get the response from the server
			response = (Envelope)input.readObject();
			
			//Successful response
			if(response.getMessage().equals("OK"))
			{
				//If there is a token in the Envelope, return it 
				ArrayList<Object> temp = null;
				temp = response.getObjContents();
				
				if(temp.size() == 1)
				{
					token = (UserToken)temp.get(0);
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
	 
	 public boolean createUser(String username, UserToken token)
	 {
		 try
			{
				Envelope message = null, response = null;
				//Tell the server to create a user
				message = new Envelope("CUSER");
				message.addObject(username); //Add user name string
				message.addObject(token); //Add the requester's token
				output.writeObject(message);
			
				response = (Envelope)input.readObject();
				
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
				output.writeObject(message);
			
				response = (Envelope)input.readObject();
				
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
				output.writeObject(message); 
			
				response = (Envelope)input.readObject();
				
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
				output.writeObject(message); 
			
				response = (Envelope)input.readObject();
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
			 output.writeObject(message); 
			 
			 response = (Envelope)input.readObject();
			
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
				output.writeObject(message); 
			
				response = (Envelope)input.readObject();
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
				output.writeObject(message);
			
				response = (Envelope)input.readObject();
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
	public static String hash(String key, String msg) throws Exception
	{
		Mac hmacSha256 = Mac.getInstance("HmacSHA256");
		SecretKeySpec secretKey = new SecretKeySpec(key.getBytes("UTF-8"),"HmacSHA256");
		hmacSha256.init(secretKey);
		return bytesToHex(hmacSha256.doFinal(msg.getBytes("UTF-8")));
	}
 	
 	public static String bytesToHex(byte[] in) {
 		final StringBuilder builder = new StringBuilder();
 		for(byte b : in) {
 			builder.append(String.format("%02x", b));
 		}
 		return builder.toString();
 	}

}
