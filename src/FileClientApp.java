import java.io.*;
import java.util.*;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import java.security.*; 
import javax.crypto.SecretKey;
import java.net.*;

public class FileClientApp
{
	protected static Token userToken = null;
	public static void main(String[] args) throws IOException, ClassNotFoundException
	{
		if(args.length != 6)
		{
			System.err.println("Usage: java FileClientApp <Username> <Password> <Group Server Name> <File Server Name> <Group Port> <File Port>\n");
			System.exit(-1);
		}

		Hashtable<String, ArrayList<SecretKey>> keysList = null;
		System.out.println("FIle Server IP : " + InetAddress.getByName(args[3]));
		//System.out.println("FIle Server IP4 : " + new Inet4Address().getHostAddress());
		PublicKey groupPubKey = null;
		FileClient fc = new FileClient();
		GroupClient gc = new GroupClient();
		Scanner sc = new Scanner(System.in);

		int z = 0;
		do{
			System.out.println("Please Select an Option");
			System.out.println("1: Show Group Server Options");
			System.out.println("2: Show File Server Options");
			System.out.println("3: Done");
			z = sc.nextInt();
			switch(z)
			{
				case 1:
					if(gc.connect(args[2],Integer.parseInt(args[4]), args[0], args[1],  args[3], Integer.parseInt(args[5])))
					{
						System.out.println("Connected to Group Server: "+args[2]+" Port: "+args[4]);
						//Get the groups public key to use for file server signature verification
						groupPubKey = gc.getGroupPubKey();

						int x = 0;
						do{
							System.out.println();
							System.out.println("Please Select an Option");
							System.out.println("1: Get a Token");
							System.out.println("2: Create a User");
							System.out.println("3: Delete a User");
							System.out.println("4: Create a Group");
							System.out.println("5: Delete a Group");
							System.out.println("6: List Members");
							System.out.println("7: Add a User to a Group");
							System.out.println("8: Delete a User From a Group");
							System.out.println("9: Disconnect");
							x = sc.nextInt();
							sc.nextLine();
							switch(x)
							{
								case 1:

								//Get Token

									userToken = (Token) gc.getToken(args[0]);
									if(userToken==null)
									{
										System.out.println("Error: Token could not be created. User does not exist\nDisconnecting..");
										System.exit(1);
									}
									break;
								case 2:
								//Create User
									if(userToken != null)
									{
										System.out.println("Please enter the name of the new user: ");
										String newUser = sc.nextLine();
										while(newUser.contains(":"))
										{
											System.out.println("Please enter a username that does not contain the ':' char: ");
											newUser = sc.nextLine();
										}
										System.out.println("Please enter the password of the new user: ");
										if(gc.createUser(newUser, sc.nextLine(), userToken))
										{
											System.out.println("User successfully created");
											userToken = (Token) gc.getToken(args[0]);
										}
										else
										{
											System.out.println("Error: User could not be created");
										}
									}
									else
										System.out.println("Please Select Option 1 to Get Token First");
									break;
								case 3:
								//Delete User
									if(userToken != null)
									{
										System.out.println("Please enter the name of the user: ");
										if(gc.deleteUser(sc.nextLine(), userToken))
										{
											System.out.println("User successfully deleted");
											userToken = (Token) gc.getToken(args[0]);
										}
										else
										{
											System.out.println("Error: User could not be deleted");
										}
									}
									else
										System.out.println("Please Select Option 1 to Get Token First");
									break;
								case 4:
								//Create Group
									if(userToken != null)
									{
										System.out.println("Group Name:");
										String groupName = sc.nextLine();
										while(groupName.contains(":"))
										{
											System.out.println("Please enter a group name that does not contain the ':' char: ");
											groupName = sc.nextLine();
										}
										if(gc.createGroup(groupName, userToken))
										{
											System.out.println("Group successfully created");
											userToken = (Token) gc.getToken(args[0]);
										}
										else
										{
											System.out.println("Error: Group could not be created");
										}
									}
									else
										System.out.println("Please Select Option 1 to Get Token First");
									break;
								case 5:
								//Delete Group

									if(userToken != null)
									{
										System.out.println("Group Name:");
										if(gc.deleteGroup(sc.nextLine(), userToken))
										{
											System.out.println("Group successfully deleted");
											userToken = (Token) gc.getToken(args[0]);
										}
										else
										{
											System.out.println("Error: Group could not be deleted");
										}
									}
									else
										System.out.println("Please Select Option 1 to Get Token First");
									break;
								case 6:
								//List Members
									if(userToken != null)
									{
										System.out.println("Group Name:");
										List<String> list = gc.listMembers(sc.nextLine(), userToken);
										if(list!=null)
										{
											System.out.println("Meme-bers: ");
											if(list!=null)
											{
												for(String s : list)
													if(!s.equals(null))
														System.out.println(s);
											}
										}
										else
										{
											System.out.println("Group does not exist");
										}

									}
									else
										System.out.println("Please Select Option 1 to Get Token First");
									break;
								case 7:
								//Add User to Group
									if(userToken != null)
									{
										System.out.println("Group Name:");
										String group = sc.nextLine();
										System.out.println("Username of the new user: ");

										if(gc.addUserToGroup(sc.nextLine(), group, userToken))
										{
											System.out.println("User successfully added");
											userToken = (Token) gc.getToken(args[0]);
										}
										else
										{
											System.out.println("Error: User could not be added");
										}
									}
									else
										System.out.println("Please Select Option 1 to Get Token First");
									break;
								case 8:
								//Delete User from Group
									if(userToken != null)
									{
										System.out.println("Group Name:");
										String group = sc.nextLine();
										System.out.println("Username of the user: ");
										if(gc.deleteUserFromGroup(sc.nextLine(), group, userToken))
										{
											System.out.println("User successfully deleted from group");
											userToken = (Token) gc.getToken(args[0]);
										}
										else
										{
											System.out.println("Error: User could not be deleted from group");
										}
									}
									else
										System.out.println("Please Select Option 1 to Get Token First");
									break;
								case 9:

								//Disconnect 
									userToken = (Token) gc.getToken(args[0]);
									
									keysList = gc.getFileKeys(userToken);
									if(keysList.size()>0)
										System.out.println("Retrieved user's file keys");
									else
										System.out.println("Unable to retrieve user's file keys");
									gc.disconnect();
									System.out.println("Disconnected From Group Server");
									break;
								default:
									System.out.println("Invalid entry!");
									x = 1;
							}

						}while(x > 0 && x < 9);

					}
					else
					{
						System.out.println("Unable to connect");
						System.exit(1);
					}
					break;
				case 2:
					if(userToken == null)
					{
						System.out.println("Please Connect to Group Server and Get a Token");
						break;
					}
					System.out.println(userToken.toString());

					if(fc.connect(args[3],Integer.parseInt(args[5]),args[0],args[1]))
					{
						Token t = userToken;
						Scanner s = new Scanner(System.in);
						System.out.println("Connected to File Server: "+args[3]+" Port: "+args[5]);
						int y = 0;
						do{
							System.out.println();
							System.out.println("Please Select an Option");
							System.out.println("1: Delete");
							System.out.println("2: Download");
							System.out.println("3: List Files");
							System.out.println("4: Upload");
							System.out.println("5: Disconnect");
							y = s.nextInt();
							s.nextLine();
							switch(y)
							{
								case 1:
									System.out.println("Please enter a file name: ");
									if(fc.delete(s.nextLine(), t, groupPubKey))
									{
										System.out.println("File successfully deleted");
									}
									else
									{
										System.out.println("File could not be deleted");
									}
									break;
								case 2:
									System.out.println("Please enter the Source File: ");
									String sf = s.nextLine();
									System.out.println("Please enter the Destination File: ");
									String df = s.nextLine();

									if(fc.download(sf, df, t, groupPubKey, keysList))
									{
										System.out.println("File successfully downloaded");
									}
									else
									{
										System.out.println("File could not be downloaded");
									}
									break;
								case 3:
									List<String> flist = fc.listFiles(t, groupPubKey);
									if(flist != null)
									{
										for(String c : flist)
											System.out.println(c);
									}
									else
									{
										System.out.println("Error Listing Files"); 
									}
									break;
								case 4:
									System.out.println("Please enter the Source File: ");
									String scf = s.nextLine();
									System.out.println("Please enter the Destination File: ");
									String dtf = s.nextLine();
									System.out.println("Please enter the Group Name: ");
									if(fc.upload(scf, dtf, s.nextLine(), t, groupPubKey, keysList))
									{
										System.out.println("File successfully uploaded");
									}
									else
									{
										System.out.println("File could not be uploaded");
									}
									break;
								case 5:
									fc.disconnect();
									keysList = null;
									System.out.println("Disconnected From File Server");
									break;
								default:
									System.out.println("Invalid entry!");
									y = 1;
							}
						}while(y > 0 && y < 5);

					}
					else
					{
						System.out.println("Unable to connect");
						System.exit(1);
					}
					break;
				case 3:
					System.out.println("Thank You for using the File Sharing System");
					System.exit(1);
			}
		}while(z > 0  && z < 4);
	}

}
