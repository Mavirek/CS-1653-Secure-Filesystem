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
import java.math.*;
import org.bouncycastle.crypto.agreement.srp.SRP6Client;
import org.bouncycastle.crypto.agreement.srp.SRP6Server;
import org.bouncycastle.crypto.agreement.srp.SRP6Util;
import org.bouncycastle.crypto.agreement.srp.SRP6VerifierGenerator;
import org.bouncycastle.crypto.digests.SHA256Digest;
import javax.crypto.KeyAgreement;
import javax.crypto.spec.DHParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import javax.crypto.SealedObject;
import javax.crypto.*;

public class GroupThread extends Thread
{
	private final Socket socket;
	private GroupServer my_gs;
	private EncryptDecrypt ed = new EncryptDecrypt();
	private SecureRandom random = new SecureRandom();
	private SecretKeySpec sessKey;
	private byte[] challengeD;
	private PublicKey groupPubKey;

	public GroupThread(Socket _socket, GroupServer _gs)
	{
		socket = _socket;
		my_gs = _gs;
	}

	public void run()
	{
		Security.addProvider(new BouncyCastleProvider());
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
			groupPubKey = kp.getPublic();

			//System.out.println("GS pub key : " + groupPubKey);
			Envelope pubKey = new Envelope("GROUP PUB KEY");
			pubKey.addObject(groupPubKey);
			output.writeObject(pubKey);

			do
			{
				Envelope message = (Envelope)input.readObject();
				System.out.println("Request received: " + message.getMessage());
				Envelope response;


				if(message.getMessage().equals("ENC")) {
					message = decryptEnv(message);
					System.out.println("Request received: " + message.getMessage());
					if(message.getMessage().equals("GET"))//Client wants a token
					{
						String username = (String)message.getObjContents().get(0); //Get the username
						SessionID client = (SessionID)message.getObjContents().get(3); //Get SessionID
						if(verifySessID(client))
						{
							if(username == null) 
							{
								response = new Envelope("FAIL");
								response.addObject(null);
								output.writeObject(encryptEnv(response));
						    }
							else
							{
								StringBuilder sb = new StringBuilder("");
								sb.append((String)message.getObjContents().get(1));
								sb.append("#");
								sb.append((int)message.getObjContents().get(2));
								Token yourToken = createToken(username, sb.toString()); //Create a token

								//Respond to the client. On error, the client will receive a null token
								response = new Envelope("OK");

								//Generate a Signature
								System.out.println("Group Server Signing Token...");
								byte[] hash = yourToken.genHash();
								//signedHash = [hash]pk;
								Signature signer = Signature.getInstance("SHA1withRSA", "BC");
								signer.initSign(groupPrivKey);
								signer.update(hash);
								//System.out.println("Hash in Token in File Server: " + new String(hash));
								yourToken.setSignedHash(signer.sign());
								response.addObject(yourToken.toString());
								response.addObject(yourToken.getSignedHash());
								response.addObject(hash);
								output.writeObject(encryptEnv(response));
							}
						}
					}
					else if(message.getMessage().equals("CUSER")) //Client wants to create a user
					{
						if(message.getObjContents().size() < 3)
						{
							response = new Envelope("FAIL");
						}
						else
						{
							response = new Envelope("FAIL");

							if(message.getObjContents().get(0) != null)
							{
								if(message.getObjContents().get(1) != null) {
									if(message.getObjContents().get(2) != null)
									{
										String username = (String)message.getObjContents().get(0); //Extract the username
										String password = (String)message.getObjContents().get(1);
										Token yourToken = (Token)message.getObjContents().get(2); //Extract the token
										SessionID client = (SessionID)message.getObjContents().get(3);
										if(checkSig(yourToken) && verifySessID(client)) {
											if(createUser(username,password, yourToken))
											{
												response = new Envelope("OK"); //Success
											}
										}
									}
								}
							}
						}

						output.writeObject(encryptEnv(response));
					}

					else if(message.getMessage().equals("DUSER")) //Client wants to delete a user
					{

						if(message.getObjContents().size() < 3)
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
									UserToken yourToken = (UserToken)message.getObjContents().get(1); //Extract the token
									SessionID client = (SessionID)message.getObjContents().get(2);
									if(checkSig((Token)yourToken) && verifySessID(client)) 
									{
										if(deleteUser(username, yourToken))
										{
											response = new Envelope("OK"); //Success
											    for(String group : yourToken.getGroups())
											    {
													try
													{
													  KeyGenerator keyGen = KeyGenerator.getInstance("AES","BC");
													  keyGen.init(128);
													  SecretKey key = keyGen.generateKey();
													  my_gs.gk.addKey(group,key);
													}
													catch(Exception ge)
													{
													  System.out.println("Error generating new group key after removing user from group");
													}
												}
										}
									}
								}
							}

							output.writeObject(encryptEnv(response));
						}
					}
					else if(message.getMessage().equals("CGROUP")) //Client wants to create a group
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

								if(message.getObjContents().get(1) != null)
								{
									String group = (String)message.getObjContents().get(0); //Extract the groupname
									UserToken yourToken = (UserToken)message.getObjContents().get(1); //Extract the token
									SessionID client = (SessionID)message.getObjContents().get(2);
									if(checkSig((Token)yourToken) && verifySessID(client)) 
									{
										if(cGroup(group, (Token)yourToken))
										{
											response = new Envelope("OK"); //Success
											try
											{
												KeyGenerator keyGen = KeyGenerator.getInstance("AES","BC");
												keyGen.init(128);
												SecretKey key = keyGen.generateKey();
												my_gs.gk.addGroup(group,key);
											}
											catch(Exception ge)
											{
												System.out.println("Error generating new group key after removing user from group");
											}
										}
									}
								}
							}
						}
						output.writeObject(encryptEnv(response));
					}
					
					else if(message.getMessage().equals("DGROUP")) //Client wants to delete a group
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
								if(message.getObjContents().get(1) != null)
								{
									String group = (String)message.getObjContents().get(0); //Extract the groupname
									UserToken yourToken = (UserToken)message.getObjContents().get(1); //Extract the token
									SessionID client = (SessionID)message.getObjContents().get(2);
									if(checkSig((Token)yourToken) && verifySessID(client)) {
										if(deleteGroup(group, (Token)yourToken))
										{
											response = new Envelope("OK"); //Success
											my_gs.gk.removeGroup(group);
										}
									}
								}
							}
						}
						output.writeObject(encryptEnv(response));
					}
					else if(message.getMessage().equals("LMEMBERS")) //Client wants a list of members in a group
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
								if(message.getObjContents().get(1) != null)
								{
									String group = (String)message.getObjContents().get(0); //Extract the groupname
									UserToken yourToken = (UserToken)message.getObjContents().get(1); //Extract the token
									SessionID client = (SessionID)message.getObjContents().get(2);
									if(checkSig((Token)yourToken) && verifySessID(client)) {
										if(my_gs.gList.containsKey(group))  //Group exists
										{
											Group g = my_gs.gList.get(group);
											if(g.getOwner().equals(yourToken.getSubject())) //User is owner
											{
												response = new Envelope("OK"); //Success
												response.addObject(g.getUsers());
											}
										}
									}
								}
							}
						}
						output.writeObject(encryptEnv(response));
					}
					else if(message.getMessage().equals("AUSERTOGROUP")) //Client wants to add user to a group
					{
					    /* TODO:  Write this handler */
						if(message.getObjContents().size() < 4)
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
								if(message.getObjContents().get(1) != null && message.getObjContents().get(2) != null && message.getObjContents().get(3) != null)

								{

									String userToBeAdded = (String)message.getObjContents().get(0);
									String group = (String) message.getObjContents().get(1); //Extract the groupname
									Token yourToken = (Token)message.getObjContents().get(2); //Extract the token
									SessionID client = (SessionID)message.getObjContents().get(3);
									if(checkSig((Token)yourToken) && verifySessID(client)) {
										if(my_gs.gList.containsKey(group))  //Group exists
										{
											Group g = my_gs.gList.get(group);
											if(g.getOwner().equals(yourToken.getSubject())) //User calling is owner
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
						}
						output.writeObject(encryptEnv(response));
					}
					else if(message.getMessage().equals("RUSERFROMGROUP")) //Client wants to remove user from a group
					{
					    /* TODO:  Write this handler */
						if(message.getObjContents().size() < 4)

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
									UserToken yourToken = (UserToken)message.getObjContents().get(2); //Extract the token
									SessionID client = (SessionID)message.getObjContents().get(3);
									if(checkSig((Token)yourToken) && verifySessID(client)) {
										if(my_gs.gList.containsKey(group))  //Group exists
										{
											Group g = my_gs.gList.get(group);
											if(g.getOwner().equals(yourToken.getSubject())) //User calling is owner
											{
												if(my_gs.gList.get(group).getUsers().contains(userToBeRemoved))
												{
													if(!userToBeRemoved.equals(yourToken.getSubject()))//User can't remove themselves
													{
														my_gs.gList.get(group).removeUser(userToBeRemoved);
														my_gs.userList.removeGroup(userToBeRemoved, group);
														response = new Envelope("OK"); //Success
														try
														{
															KeyGenerator keyGen = KeyGenerator.getInstance("AES","BC");
															keyGen.init(128);
															SecretKey key = keyGen.generateKey();
															my_gs.gk.addKey(group,key);
														}
														catch(Exception ge)
														{
															System.out.println("Error generating new group key after removing user from group");
														}
													}
												}
											}
										}
									}
								}
							}
						}
						output.writeObject(encryptEnv(response));
					}
					else if(message.getMessage().equals("DISCONNECT")) //Client wants to disconnect
					{
						SessionID client = (SessionID)message.getObjContents().get(0);
						updateUserList();
						if(saveSessID(client))
						{
							socket.close(); //Close the socket
							proceed = false; //End this communication loop
						}
					}
					//output.writeObject(response);
				}
				else if(message.getMessage().equals("GETFILEKEYS")) //Retrieve corresponding file server file keys for a user
				{
					if(message.getObjContents().size() < 1)
					{
						response = new Envelope("FAIL");
					}
					else
					{
						response = new Envelope("FAIL");

						if(message.getObjContents().get(0) != null)
						{
							UserToken yourToken = (UserToken)message.getObjContents().get(0); //Extract the token
							Hashtable<String, ArrayList<SecretKey>> keyList = new Hashtable<String, ArrayList<SecretKey>>();
							for(String group : yourToken.getGroups())
							{
								System.out.println("adding keys for group: "+group);
								keyList.put(group, my_gs.gk.getKeys(group));
							}
							response = new Envelope("OK");
							response.addObject(keyList);
						}
					}
					output.writeObject(response);
				}
				/*
				else if(message.getMessage().equals("DISCONNECT")) //Client wants to disconnect
				{
					updateUserList();
					socket.close(); //Close the socket
					proceed = false; //End this communication loop
				}
				*/
				else if(message.getMessage().equals("CHECK")) //Check Password
				{
					//decrypt envelope
					//String[] toDecrypt = new String[2];
					//toDecrypt[0] = (String)message.getObjContents().get(0);
					//toDecrypt[1] = (String)message.getObjContents().get(1);
					//System.out.println("MAKES IT HERE!!");
					//System.out.println("private : " + groupPrivKey);
					byte[] encryptedUser = (byte[])message.getObjContents().get(0);
					byte[] encryptedPassHash = (byte[])message.getObjContents().get(1);
					byte[] decryptedUser=null;
					byte[] decryptedPassHash=null;

					try {
						Cipher dec = Cipher.getInstance("RSA/ECB/NoPadding", "BC");
						dec.init(Cipher.DECRYPT_MODE, kp.getPrivate());
						decryptedUser = dec.doFinal(encryptedUser);
						decryptedPassHash = dec.doFinal(encryptedPassHash);
						//System.out.println("decrypted username : " + new String(decryptedUser));
					}
					catch(Exception e) {
						System.out.println(e);
					}

					String userName = new String(decryptedUser);

					if(my_gs.userList.checkUser(userName))
					{

						if(my_gs.userList.checkPass(userName, ed.passDH(decryptedPassHash))) {
							response = new Envelope("USER AUTHORIZED");

							BigInteger g256 = new BigInteger(ed.getGen(),16);
							BigInteger p256 = new BigInteger(ed.getPrime(),16);

							DHParameterSpec dhParams = new DHParameterSpec(p256,g256);
							KeyPairGenerator keyGen = KeyPairGenerator.getInstance("DH","BC");
							keyGen.initialize(dhParams, new SecureRandom());

							KeyAgreement gKA = KeyAgreement.getInstance("DH","BC");
							KeyPair groupPair = keyGen.generateKeyPair();

							gKA.init(groupPair.getPrivate());
							response.addObject(groupPair.getPublic());//Send this to verify.
							byte[] challengeC = new byte[4];
							random.nextBytes(challengeC);
							response.addObject(challengeC);
							output.writeObject(response); //send file server public key
							response = (Envelope)input.readObject(); //receive client public key
							PublicKey clientPK = (PublicKey)response.getObjContents().get(0);
							gKA.doPhase(clientPK,true);
							byte[] sharedKey = Arrays.copyOfRange(gKA.generateSecret(),0,16);
							//System.out.println("Shared Key : " + new BigInteger(sharedKey));

							byte[] encC = (byte[])response.getObjContents().get(1);
							byte[] iv = (byte[])response.getObjContents().get(2);
							challengeD = (byte[])response.getObjContents().get(3);

							sessKey = new SecretKeySpec(sharedKey,"AES");
							Cipher ciph = Cipher.getInstance("AES/CFB/PKCS5Padding","BC");
							ciph.init(Cipher.DECRYPT_MODE,sessKey,new IvParameterSpec(iv));
							byte[] decC = ciph.doFinal(encC);
							if(Arrays.equals(challengeC, decC)) {
								response = new Envelope("Match");
								ciph.init(Cipher.ENCRYPT_MODE,sessKey,new IvParameterSpec(iv));
								byte[] encD = ciph.doFinal(challengeD);
								response.addObject(encD);
							}
							else {
								response = new Envelope("Failed");
							}
						}
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
				updateUserList();
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

		System.out.println("Saving Group, User, and GroupKeys lists...");
		ObjectOutputStream outStream;
		try
		{
			outStream = new ObjectOutputStream(new FileOutputStream("UserList.bin"));
			outStream.writeObject(my_gs.userList);
			outStream = new ObjectOutputStream(new FileOutputStream("GroupList.bin"));
			outStream.writeObject(my_gs.gList);
			outStream = new ObjectOutputStream(new FileOutputStream("GroupKeysList.bin"));
			outStream.writeObject(my_gs.gk);
			outStream = new ObjectOutputStream(new FileOutputStream("SessionIDGS.bin"));
			outStream.writeObject(my_gs.unacceptedSessionIDs);
		}
		catch(Exception e)
		{
			System.err.println("Error: " + e.getMessage());
			e.printStackTrace(System.err);
		}
	}

	//Method to create tokens
	private Token createToken(String username, String fileServer)
	{
		//Check that user exists
		if(my_gs.userList.checkUser(username))
		{
			//Issue a new token with server's name, user's name, and user's groups
			Token yourToken = new Token(my_gs.name, username, my_gs.userList.getUserGroups(username), fileServer);
			return yourToken;
		}
		else
		{
			return null;
		}
	}

	//Method to create a user
	private boolean createUser(String username, String password, UserToken yourToken)
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
					byte[] passHash = ed.hashThis(password);
					String passToStore = ed.passDH(passHash);
					my_gs.userList.setPassword(username, passToStore);
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
			try
			{
				KeyGenerator keyGen = KeyGenerator.getInstance("AES","BC");
				keyGen.init(128);
				SecretKey key = keyGen.generateKey();
				my_gs.gk.addGroup(groupName,key);
			}
			catch(Exception e)
			{
				System.out.println("Error creating new key for group created");
			}
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
			my_gs.gk.removeGroup(groupName);
			return true;
		}
		return false;
	}

	private Envelope encryptEnv(Envelope msg)
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

	private Envelope decryptEnv(Envelope msg)
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

	private boolean checkSig(Token checkToken) {

		try {
			Signature signed = Signature.getInstance("SHA1WithRSA", "BC");
			signed.initVerify(groupPubKey);
			signed.update(checkToken.getHash());
			if(signed.verify(checkToken.getSignedHash()))
				return true;
			else
				return false;
		}
		catch(Exception e) {
			e.printStackTrace();
		}

		return false;
	}
	private boolean verifySessID(SessionID clientID)
	{
		System.out.println("Verifying SessionID...");
		if(my_gs.unacceptedSessionIDs != null)
		{
			if(my_gs.unacceptedSessionIDs.containsKey(clientID.getUserName()))
			{
				SessionID storedID = my_gs.unacceptedSessionIDs.get(clientID.getUserName());
				storedID.nextMsg();
				//System.out.println("TEST SessionID: " + clientID.toString());
				//The message is in unacceptedSessionIDs meaning shouldn't be accepted.
				if(storedID.equals(clientID))
					return false;
			}
		}
		//This is not the first time the client has connected to the server.
		if(my_gs.acceptedSessionIDs.containsKey(clientID.getUserName()))
		{
			//Check date is today
			if(!clientID.isToday())
				return false;

			//Get the last sessionID stored for the client
			SessionID storedID = my_gs.acceptedSessionIDs.get(clientID.getUserName());
			storedID.nextMsg();
			//System.out.println("TEST SessionID: " + clientID.toString());
			//Ensure the last sessionID is one less message than the current ID.
			if(storedID.equals(clientID))
			{
				//Replace the old stored sessionID with the current sessionID.
				//System.out.println("SessionID: " + clientID.toString());
				my_gs.acceptedSessionIDs.remove(clientID.getUserName());
				my_gs.acceptedSessionIDs.put(clientID.getUserName(), clientID);
				return true;
			}
		}
		//This is the first time the client has connected
		else
		{
			//Store this sessionID in the list and accept it.
			my_gs.acceptedSessionIDs.put(clientID.getUserName(), clientID);
			//System.out.println("SessionID: " + clientID.toString());
			return true;
		}
		return false;
	}
	private boolean saveSessID(SessionID clientID)
	{
		my_gs.acceptedSessionIDs.remove(clientID.getUserName());
		SessionID newClientID = new SessionID(clientID.getUserName(), clientID.getDate(), clientID.getRandNumber(), -1);
		my_gs.unacceptedSessionIDs.put(clientID.getUserName(), newClientID);
		//System.out.println("clientID: " + clientID.toString());
		//System.out.println("newClientID: " + newClientID.toString());
		return my_gs.unacceptedSessionIDs.containsKey(clientID.getUserName());
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
}
