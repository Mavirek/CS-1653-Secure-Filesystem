import java.io.*;
import java.util.*;

public class FileClientApp
{
	protected static Token userToken = null; 
	public static void main(String[] args)
	{
		if(args.length != 5)
		{
			System.err.println("Usage: java FileClientApp <Username> <Group Server Name> <File Server Name> <Group Port> <File Port>\n");
			System.exit(-1);
		}

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
					if(gc.connect(args[1],Integer.parseInt(args[3])))
					{
						System.out.println("Connected to Group Server: "+args[1]+" Port: "+args[3]);
						int x = 0; 
						//userToken = (Token) gc.getToken(args[0]);
						do{
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
									userToken = (Token) gc.getToken(args[0]);
									break;
								case 2:
									if(userToken != null)  
									{
										System.out.println("Please enter the name of the new user: ");
										if(gc.createUser(sc.nextLine(), userToken))
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
									if(userToken != null)  
									{
										System.out.println("Group Name:"); 
										if(gc.createGroup(sc.nextLine(), userToken))
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
									if(userToken != null)  
									{
										System.out.println("Group Name:"); 
										List<String> list = gc.listMembers(sc.nextLine(), userToken);
										System.out.println("Meme-bers: ");
										if(list!=null)
										{
											for(String s : list)
												if(!s.equals(null))
													System.out.println(s); 
										}
									}
									else 
										System.out.println("Please Select Option 1 to Get Token First"); 
									break;
								case 7:
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
									userToken = (Token) gc.getToken(args[0]);
									gc.disconnect(); 
									System.out.println("Disconnected From Group Server"); 
									break; 
								default:
									System.out.println("Invalid entry!"); 
									x = 1; 
							}
							userToken.print(); 

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
					if(fc.connect(args[2],Integer.parseInt(args[4])))
					{
						String userFile = "UserList.bin";
						UserList userList = null; 
						ObjectInputStream userStream;
						try
						{
							FileInputStream fis = new FileInputStream(userFile);
							userStream = new ObjectInputStream(fis);
							userList = (UserList)userStream.readObject();
							
						}
						catch(FileNotFoundException e)
						{
							System.err.println(e); 
							System.exit(1); 
						}
						catch(IOException e)
						{
							System.out.println("Error reading from UserList file");
							System.exit(-1);
						}
						catch(ClassNotFoundException e)
						{
							System.out.println("Error Class Not found ");
							System.exit(-1);
						}
						System.out.println("FILESERVER TOKEN PRINT:"); 
						Token t = new Token("FilePile", args[0], userList.getUserGroups(args[0])); 
						//userToken = (Token) gc.getToken(args[0]);
						t.print();
						
						Scanner s = new Scanner(System.in);
						System.out.println("Connected to File Server: "+args[2]+" Port: "+args[4]);
						int y = 0; 
						do{
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
									if(fc.delete(s.nextLine(), t))
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
									if(fc.download(sf, df, t))
									{
										System.out.println("File successfully downloaded");
									}
									else
									{
										System.out.println("File could not be downloaded");
									}
									break;
								case 3:
									List<String> flist = fc.listFiles(t);
									for(String c : flist)
										System.out.println(c); 
									
									break; 
								case 4: 
									System.out.println("Please enter the Source File: ");
									String scf = s.nextLine(); 
									System.out.println("Please enter the Destination File: "); 
									String dtf = s.nextLine(); 
									System.out.println("Please enter the Group Name: ");
									if(fc.upload(scf, dtf, s.nextLine(), t))
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