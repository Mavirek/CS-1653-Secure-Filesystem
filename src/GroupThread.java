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
					if(message.getMessage().equals("GET"))//Client wants a token
					{
						String username = (String)message.getObjContents().get(0); //Get the username
						if(username == null)
						{
							response = new Envelope("FAIL");
							response.addObject(null);
							output.writeObject(encryptEnv(response));
						}
						else
						{
							Token yourToken = createToken(username); //Create a token

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
								if(message.getObjContents().get(1) != null) {
									if(message.getObjContents().get(2) != null)
									{
										String username = (String)message.getObjContents().get(0); //Extract the username
										String password = (String)message.getObjContents().get(1);
										Token yourToken = (Token)message.getObjContents().get(2); //Extract the token

										if(checkSig(yourToken)) {
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
									UserToken yourToken = (UserToken)message.getObjContents().get(1); //Extract the token

									if(checkSig((Token)yourToken)) {
										if(deleteUser(username, yourToken))
										{
											response = new Envelope("OK"); //Success
										}
									}
								}
							}
						}

						output.writeObject(encryptEnv(response));
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
									UserToken yourToken = (UserToken)message.getObjContents().get(1); //Extract the token

									if(checkSig((Token)yourToken)) {
										if(cGroup(group, (Token)yourToken))
										{
											response = new Envelope("OK"); //Success
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
									UserToken yourToken = (UserToken)message.getObjContents().get(1); //Extract the token

									if(checkSig((Token)yourToken)) {
										if(deleteGroup(group, (Token)yourToken))
										{
											response = new Envelope("OK"); //Success
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
									UserToken yourToken = (UserToken)message.getObjContents().get(1); //Extract the token
									if(checkSig((Token)yourToken)) {
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
									Token yourToken = (Token)message.getObjContents().get(2); //Extract the token

									if(checkSig((Token)yourToken)) {
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
									UserToken yourToken = (UserToken)message.getObjContents().get(2); //Extract the token
									if(checkSig((Token)yourToken)) {
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
						updateUserList();
						socket.close(); //Close the socket
						proceed = false; //End this communication loop
					}
				}
				else if(message.getMessage().equals("CHECK")) //Check Password
				{

					byte[] encryptedUser = (byte[])message.getObjContents().get(0);
					byte[] encryptedPassHash = (byte[])message.getObjContents().get(1);
					byte[] decryptedUser=null;
					byte[] decryptedPassHash=null;

					try {
			      Cipher dec = Cipher.getInstance("RSA/ECB/NoPadding", "BC");
			  		dec.init(Cipher.DECRYPT_MODE, kp.getPrivate());
			      decryptedUser = dec.doFinal(encryptedUser);
			      decryptedPassHash = dec.doFinal(encryptedPassHash);


						System.out.println("decrypted username : " + new String(decryptedUser));
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
							System.out.println("Shared Key : " + new BigInteger(sharedKey));

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

							//byte[] salt;

						//	if((salt = my_gs.userList.getSalt(userName)) == null) {
						//		salt = new byte[16];
						//		SecureRandom sr = new SecureRandom();
						//		sr.nextBytes(salt);
						//		my_gs.userList.setSalt(userName, salt);
						//	}

							//SRP6VerifierGenerator gen = new SRP6VerifierGenerator();
							//BigInteger N = new BigInteger(ed.getPrime(), 16);
							//BigInteger g = new BigInteger(ed.getGen(), 16);
							//gen.init(N, g, new SHA256Digest());
    				  //BigInteger v = gen.generateVerifier(salt, decryptedUser, decryptedPassHash);
							//SRP6Server server = new SRP6Server();
	 						//server.init(N, g, v, new SHA256Digest(), random);
							//BigInteger B = server.generateServerCredentials();
							//response.addObject(B);
							//System.out.println("N : " + N.toString());
							//System.out.println("g : " + g.toString());
							//System.out.println("userBytes : " + new BigInteger(decryptedUser).toString());
							//System.out.println("userBytes : " + new BigInteger(decryptedPassHash).toString());
							//System.out.println("B : " + B.toString());
							//output.writeObject(response);
							//Envelope incoming = (Envelope)input.readObject();
							//System.out.println(incoming.getMessage());
							//BigInteger A = (BigInteger)incoming.getObjContents().get(0);
							//System.out.println("A : " + A.toString());
					  	//BigInteger serverS = server.calculateSecret(A);
							//System.out.println("Server Secret : " + serverS);
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
	private Token createToken(String username)
	{
		//Check that user exists
		if(my_gs.userList.checkUser(username))
		{
			//Issue a new token with server's name, user's name, and user's groups
			Token yourToken = new Token(my_gs.name, username, my_gs.userList.getUserGroups(username));
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
}
