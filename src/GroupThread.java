/* This thread does all the work. It communicates with the client through Envelopes.
 * 
 */
import java.lang.Thread;
import java.net.Socket;
import java.io.*;
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
public class GroupThread extends Thread 
{
	private final Socket socket;
	private GroupServer my_gs;

	public GroupThread(Socket _socket, GroupServer _gs)
	{
		socket = _socket;
		my_gs = _gs;
	}
	
	public void run()
	{
		boolean proceed = true;

		try
		{
			//Announces connection and opens object streams
			System.out.println("*** New connection from " + socket.getInetAddress() + ":" + socket.getPort() + "***");
			final ObjectInputStream input = new ObjectInputStream(socket.getInputStream());
			final ObjectOutputStream output = new ObjectOutputStream(socket.getOutputStream());
			//gen pub priv pair
			KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA", "BC");
			kpg.initialize(2048);
			KeyPair kp = kpg.generateKeyPair(); 
			PrivateKey groupPrivKey = kp.getPrivate(); 
			PublicKey groupPubKey = kp.getPublic(); 
			Envelope pubKey = new Envelope("GROUP PUB KEY"); 
			pubKey.addObject(groupPubKey); 
			output.writeObject(pubKey);
			do
			{
				Envelope message = (Envelope)input.readObject();
				System.out.println("Request received: " + message.getMessage());
				Envelope response;
				
				if(message.getMessage().equals("GET"))//Client wants a token
				{
					String username = (String)message.getObjContents().get(0); //Get the username
					if(username == null)
					{
						response = new Envelope("FAIL");
						response.addObject(null);
						output.writeObject(response);
					}
					else
					{
						String yourToken = createToken(username); //Create a token
						
						//Respond to the client. On error, the client will receive a null token
						response = new Envelope("OK");
						response.addObject(yourToken);
						output.writeObject(response);
					}
				}
				else if(message.getMessage().equals("CUSER")) //Client wants to create a user
				{
					if(message.getObjContents().size() < 2)
					{
						response = new Envelope("FAIL");
					}
					else
					{
						response = new Envelope("FAIL");
						
						if(message.getObjContents().get(0) != null)
						{
							if(message.getObjContents().get(1) != null)
							{
								String username = (String)message.getObjContents().get(0); //Extract the username
								String yourToken = (String)message.getObjContents().get(1); //Extract the token
								
								if(createUser(username, new Token(yourToken)))
								{
									response = new Envelope("OK"); //Success
								}
							}
						}
					}
					
					output.writeObject(response);
				}
				else if(message.getMessage().equals("DUSER")) //Client wants to delete a user
				{
					
					if(message.getObjContents().size() < 2)
					{
						response = new Envelope("FAIL");
					}
					else
					{
						response = new Envelope("FAIL");
						
						if(message.getObjContents().get(0) != null)
						{
							if(message.getObjContents().get(1) != null)
							{
								String username = (String)message.getObjContents().get(0); //Extract the username
								String yourToken = (String)message.getObjContents().get(1); //Extract the token
								
								if(deleteUser(username,new Token(yourToken)))
								{
									response = new Envelope("OK"); //Success
								}
							}
						}
					}
					
					output.writeObject(response);
				}
				else if(message.getMessage().equals("CGROUP")) //Client wants to create a group
				{
				    /* TODO:  Write this handler */
					if(message.getObjContents().size() < 2)
					{
						response = new Envelope("FAIL");
					}
					else
					{
						response = new Envelope("FAIL");
						
						if(message.getObjContents().get(0) != null)
						{
							if(message.getObjContents().get(1) != null)
							{
								String group = (String)message.getObjContents().get(0); //Extract the groupname
								String yourToken = (String)message.getObjContents().get(1); //Extract the token
								
								if(cGroup(group, new Token(yourToken)))
								{
									response = new Envelope("OK"); //Success
								}
							}
						}
					}
					output.writeObject(response);
				}
				else if(message.getMessage().equals("DGROUP")) //Client wants to delete a group
				{
				    /* TODO:  Write this handler */
					if(message.getObjContents().size() < 2)
					{
						response = new Envelope("FAIL");
					}
					else
					{
						response = new Envelope("FAIL");
						
						if(message.getObjContents().get(0) != null)
						{
							if(message.getObjContents().get(1) != null)
							{
								String group = (String)message.getObjContents().get(0); //Extract the groupname
								String yourToken = (String)message.getObjContents().get(1); //Extract the token
								
								if(deleteGroup(group, new Token(yourToken)))
								{
									response = new Envelope("OK"); //Success
								}
							}
						}
					}
					output.writeObject(response);
				}
				else if(message.getMessage().equals("LMEMBERS")) //Client wants a list of members in a group
				{
				    /* TODO:  Write this handler */
					if(message.getObjContents().size() < 2)
					{
						response = new Envelope("FAIL");
					}
					else
					{
						response = new Envelope("FAIL");
						
						if(message.getObjContents().get(0) != null)
						{
							if(message.getObjContents().get(1) != null)
							{
								String group = (String)message.getObjContents().get(0); //Extract the groupname
								String yourToken = (String)message.getObjContents().get(1); //Extract the token
								if(my_gs.gList.containsKey(group))  //Group exists
								{
									Group g = my_gs.gList.get(group);
									if(g.getOwner().equals((new Token(yourToken)).getSubject())) //User is owner
									{
										response = new Envelope("OK"); //Success
										response.addObject(g.getUsers());
									}
								}
							}
						}
					}
					output.writeObject(response);
				}
				else if(message.getMessage().equals("AUSERTOGROUP")) //Client wants to add user to a group
				{
				    /* TODO:  Write this handler */
					if(message.getObjContents().size() < 3)
					{
						response = new Envelope("FAIL");
						//System.out.println("msg.size < 3");
					}
					else
					{
						response = new Envelope("FAIL");
						//System.out.println("msg.size else");
						
						if(message.getObjContents().get(0) != null)
						{
							if(message.getObjContents().get(1) != null && message.getObjContents().get(2) != null)
							{
								
								String userToBeAdded = (String)message.getObjContents().get(0); 
								String group = (String) message.getObjContents().get(1); //Extract the groupname
								String yourToken = (String)message.getObjContents().get(2); //Extract the token
								
								if(my_gs.gList.containsKey(group))  //Group exists
								{
									Group g = my_gs.gList.get(group);
									if(g.getOwner().equals((new Token(yourToken)).getSubject())) //User calling is owner
									{
										if(!my_gs.gList.get(group).getUsers().contains(userToBeAdded))
										{
											if(my_gs.userList.checkUser(userToBeAdded))
											{
												my_gs.gList.get(group).addUser(userToBeAdded);
												my_gs.userList.addGroup(userToBeAdded, group);
												response = new Envelope("OK"); //Success
											}
										}
									}
								}
								
							}
						}
					}
					output.writeObject(response);
				}
				else if(message.getMessage().equals("RUSERFROMGROUP")) //Client wants to remove user from a group
				{
				    /* TODO:  Write this handler */
					if(message.getObjContents().size() < 3)
					{
						response = new Envelope("FAIL");
					}
					else
					{
						response = new Envelope("FAIL");
						
						if(message.getObjContents().get(0) != null)
						{
							if(message.getObjContents().get(1) != null && message.getObjContents().get(2) != null)
							{
								
								String userToBeRemoved = (String)message.getObjContents().get(0); 
								String group = (String) message.getObjContents().get(1); //Extract the groupname
								String yourToken = (String)message.getObjContents().get(2); //Extract the token
								if(my_gs.gList.containsKey(group))  //Group exists
								{
									Group g = my_gs.gList.get(group);
									if(g.getOwner().equals((new Token(yourToken)).getSubject())) //User calling is owner
									{
										if(my_gs.gList.get(group).getUsers().contains(userToBeRemoved)) 
										{
											if(!userToBeRemoved.equals((new Token(yourToken)).getSubject()))//User can't remove themselves 
											{
												my_gs.gList.get(group).removeUser(userToBeRemoved); 
												my_gs.userList.removeGroup(userToBeRemoved, group); 
												response = new Envelope("OK"); //Success
											}
										}
									}
								}
							}
						}
					}
					output.writeObject(response);
				}
				else if(message.getMessage().equals("DISCONNECT")) //Client wants to disconnect
				{
					updateUserList();
					socket.close(); //Close the socket
					proceed = false; //End this communication loop
				}
				else if(message.getMessage().equals("CHECK")) //Check Password 
				{
					//decrypt envelope 
					String encryptedUN = (String) message.getObjContents.get(0); 
					String encryptedHash = (String) message.getObjContents.get(1); 
					Cipher enc = Cipher.getInstance("RSA/ECB/PKCS1Padding", "BC"); 
					enc.init(Cipher.DECRYPT_MODE, groupPrivKey); 
					String userName = new String(enc.doFinal(encryptedUN.toByteArray())); 
					String hash = new String(enc.doFinal(encryptedHash.toByteArray())); 
					if(my_gs.userList.containsKey(userName))
					{
						BigInteger g = new BigInteger((long)2); 
						BigInteger q = new BigInteger(my_gs.G, 16); 
						BigInteger newPass = g.modPow(new BigInteger(hash), q);
						if(my_gs.userList.checkPW(userName, newPass.toString()))
							response = new Envelope("USER AUTHORIZED"); 
						else 
						{
							response = new Envelope("USER UNAUTHORIZED"); 
							output.writeObject(response); 
							socket.close(); 
							proceed = false; 
						}
						
						output.writeObject(response); 
					}
					else
					{
						response = new Envelope("USER NOT FOUND ERROR"); 
						output.writeObject(response); 
						updateUserList(); 
						socket.close(); 
						proceed = false; 
					}
				}
				else
				{
					response = new Envelope("FAIL"); //Server does not understand client request
					output.writeObject(response);
				}
			}while(proceed);	
		}
		catch(Exception e)
		{
			System.err.println("Error: " + e.getMessage());
			e.printStackTrace(System.err);
		}
	}
	
	private void updateUserList()
	{
		System.out.println("Saving Group and User list..."); 
		ObjectOutputStream outStream;
		try
		{
			outStream = new ObjectOutputStream(new FileOutputStream("UserList.bin"));
			outStream.writeObject(my_gs.userList);
			outStream = new ObjectOutputStream(new FileOutputStream("GroupList.bin"));
			outStream.writeObject(my_gs.gList); 
		}
		catch(Exception e)
		{
			System.err.println("Error: " + e.getMessage());
			e.printStackTrace(System.err);
		}
	}
	
	//Method to create tokens
	private String createToken(String username) 
	{
		//Check that user exists
		if(my_gs.userList.checkUser(username))
		{
			//Issue a new token with server's name, user's name, and user's groups
			UserToken yourToken = new Token(my_gs.name, username, my_gs.userList.getUserGroups(username));
			return yourToken.toString();
		}
		else
		{
			return null;
		}
	}
	
	//Method to create a user
	private boolean createUser(String username, UserToken yourToken)
	{
		String requester = yourToken.getSubject();
		
		//Check if requester exists
		if(my_gs.userList.checkUser(requester))
		{
			//Get the user's groups
			ArrayList<String> temp = my_gs.userList.getUserGroups(requester);
			//requester needs to be an administrator
			if(temp.contains("ADMIN"))
			{
				//Does user already exist?
				if(my_gs.userList.checkUser(username))
				{
					return false; //User already exists
				}
				else
				{
					my_gs.userList.addUser(username);
					return true;
				}
			}
			else
			{
				return false; //requester not an administrator
			}
		}
		else
		{
			return false; //requester does not exist
		}
	}
	//Method to delete a user
	private boolean deleteUser(String username, UserToken yourToken)
	{
		String requester = yourToken.getSubject();
		if(username.equals(requester)) return false; //Shouldn't be allowed to delete yourself
			
		//Does requester exist?
		if(my_gs.userList.checkUser(requester))
		{
			ArrayList<String> temp = my_gs.userList.getUserGroups(requester);
			//requester needs to be an administer
			if(temp.contains("ADMIN"))
			{
				//Does user exist?
				if(my_gs.userList.checkUser(username))
				{
					//User needs deleted from the groups they belong
					ArrayList<String> deleteFromGroups = new ArrayList<String>();
					
					//This will produce a hard copy of the list of groups this user belongs
					for(int index = 0; index < my_gs.userList.getUserGroups(username).size(); index++)
					{
						deleteFromGroups.add(my_gs.userList.getUserGroups(username).get(index));
						if(my_gs.gList.get(my_gs.userList.getUserGroups(username).get(index)).removeUser(username))
							System.out.println("user successfully deleted from grouplist");
					}
					
					//If groups are owned, they must be deleted
					ArrayList<String> deleteOwnedGroup = new ArrayList<String>();
					
					//Make a hard copy of the user's ownership list
					for(int index = 0; index < my_gs.userList.getUserOwnership(username).size(); index++)
					{
						deleteOwnedGroup.add(my_gs.userList.getUserOwnership(username).get(index));
					}
					
					//Delete owned groups
					for(int index = 0; index < deleteOwnedGroup.size(); index++)
					{
						//Use the delete group method. Token must be created for this action
						deleteGroup(deleteOwnedGroup.get(index), new Token(my_gs.name, username, deleteOwnedGroup));
					}
					
					//Delete the user from the user list
					my_gs.userList.deleteUser(username);
					
					return true;	
				}
				else
				{
					return false; //User does not exist
					
				}
			}
			else
			{
				return false; //requester is not an administer
			}
		}
		else
		{
			return false; //requester does not exist
		}
	}
	private boolean cGroup(String groupName, Token user)
	{
		if(!my_gs.gList.containsKey(groupName))
		{
			my_gs.gList.put(groupName,new Group(groupName, user.getSubject())); 
			user.addGroup(groupName); 
			my_gs.userList.addGroup(user.getSubject(), groupName); 
			my_gs.userList.addOwnership(user.getSubject(), groupName); 
			return true;
		}
		return false; 
	}
	private boolean deleteGroup(String groupName, Token user)
	{
		if(my_gs.gList.containsKey(groupName) && my_gs.userList.getUserOwnership(user.getSubject()).contains(groupName))
		{
			user.removeGroup(groupName);
			Group g = my_gs.gList.remove(groupName);
			for(String userName : g.getUsers())
			{
				my_gs.userList.removeGroup(userName, groupName); 
			}
			my_gs.userList.removeOwnership(user.getSubject(), groupName); 
			return true;
		}
		return false; 
	}
}
