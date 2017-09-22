import java.util.*;

public class FileClientApp
{
	public static void main(String[] args)
	{
		if(args.length != 5)
		{
			System.err.println("Usage: java FileClientApp <Username> <Group Server Name> <File Server Name> <Group Port> <File Port>\n");
			System.exit(-1);
		}

		FileClient fc = new FileClient();
		GroupClient gc = new GroupClient();
		Token userToken = null; 
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
						userToken = (Token) gc.getToken(args[0]);
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
							
							switch(x)
							{
								case 1: 
									userToken = (Token) gc.getToken(args[0]);
									break;
								case 2:
									if(userToken != null)  
									{
										System.out.println("Please enter the name of the new user: ");
										gc.createUser(sc.nextLine(), userToken);
									}
									else 
										System.out.println("Please Select Option 1 to Get Token First"); 
									break; 
								case 3: 
									if(userToken != null)  
									{
										System.out.println("Please enter the name of the user: ");
										gc.deleteUser(sc.nextLine(), userToken);
									}
									else 
										System.out.println("Please Select Option 1 to Get Token First"); 
									break;
								case 4: 
									if(userToken != null)  
									{
										System.out.println("Group Name:"); 
										gc.createGroup(sc.nextLine(), userToken);
									}
									else 
										System.out.println("Please Select Option 1 to Get Token First"); 
									break;
								case 5:
									if(userToken != null)  
									{
										System.out.println("Group Name:"); 
										gc.deleteGroup(sc.nextLine(), userToken);
									}
									else 
										System.out.println("Please Select Option 1 to Get Token First"); 
									break;
								case 6:
									if(userToken != null)  
									{
										System.out.println("Group Name:"); 
										List<String> list = gc.listMembers(sc.nextLine(), userToken);
										System.out.println("Memebers: ");
										for(String s : list)
											System.out.println(s); 
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
										gc.addUserToGroup(sc.nextLine(), group, userToken);
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
										gc.deleteUserFromGroup(sc.nextLine(), group, userToken);
									}
									else 
										System.out.println("Please Select Option 1 to Get Token First"); 
									break;
								case 9:
									gc.disconnect(); 
									System.out.println("Disconnected From Group Server"); 
									break; 
								default:
									System.out.println("Invalid entry!"); 
									x = 1; 
							}
						}while(x > 0 && x < 10);
						
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
							switch(y)
							{
								case 1: 
									System.out.println("Please enter a file name: "); 
									fc.delete(s.nextLine(), userToken); 
									break;
								case 2:
									System.out.println("Please enter the Source File: ");
									String sf = s.nextLine(); 
									System.out.println("Please enter the Destination File: "); 
									String df = s.nextLine(); 
									fc.download(sf, df, userToken); 
									break;
								case 3:
									fc.listFiles(userToken); 
									break; 
								case 4: 
									System.out.println("Please enter the Source File: ");
									String scf = s.nextLine(); 
									System.out.println("Please enter the Destination File: "); 
									String dtf = s.nextLine(); 
									System.out.println("Please enter the Group Name: ");
									fc.upload(scf, dtf, s.nextLine(), userToken); 
									break;
								case 5:
									fc.disconnect(); 
									System.out.println("Disconnected From File Server"); 
									break; 
								default:
									System.out.println("Invalid entry!"); 
									y = 1; 
							}
						}while(y > 0 && y < 6);
						
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