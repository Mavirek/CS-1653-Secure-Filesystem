/* Group server. Server loads the users from UserList.bin.
 * If user list does not exists, it creates a new list and makes the user the server administrator.
 * On exit, the server saves the user list to file. 
 */

/*
 * TODO: This file will need to be modified to save state related to
 *       groups that are created in the system
 *
 */

import java.net.ServerSocket;
import java.net.Socket;
import java.io.*;
import java.util.*;
import org.bouncycastle.crypto.digests.SHA256Digest; 
import org.bouncycastle.crypto.macs.HMac; 
import org.bouncycastle.crypto.params.KeyParameter; 
import org.bouncycastle.util.encoders.Hex; 
import java.math.*; 


public class GroupServer extends Server {

	public static final int SERVER_PORT = 8765;
	public UserList userList;
	public Hashtable<String, Group> gList = new Hashtable<String, Group>(); 
	public static final String G = (
        "FFFFFFFF FFFFFFFF C90FDAA2 2168C234 C4C6628B 80DC1CD1" +
        "29024E08 8A67CC74 020BBEA6 3B139B22 514A0879 8E3404DD" +
        "EF9519B3 CD3A431B 302B0A6D F25F1437 4FE1356D 6D51C245" +
        "E485B576 625E7EC6 F44C42E9 A637ED6B 0BFF5CB6 F406B7ED" +
        "EE386BFB 5A899FA5 AE9F2411 7C4B1FE6 49286651 ECE45B3D" +
        "C2007CB8 A163BF05 98DA4836 1C55D39A 69163FA8 FD24CF5F" +
        "83655D23 DCA3AD96 1C62F356 208552BB 9ED52907 7096966D" +
        "670C354E 4ABC9804 F1746C08 CA18217C 32905E46 2E36CE3B" +
        "E39E772C 180E8603 9B2783A2 EC07A28F B5C55DF0 6F4C52C9" +
        "DE2BCBF6 95581718 3995497C EA956AE5 15D22618 98FA0510" +
        "15728E5A 8AACAA68 FFFFFFFF FFFFFFFF")
        .replaceAll("\\s", "");
	public HMac hmac = new HMac(new SHA256Digest());  
	public GroupServer() {
		super(SERVER_PORT, "ALPHA");
	}
	
	public GroupServer(int _port) {
		super(_port, "ALPHA");
	}
	
	public void start() {
		// Overwrote server.start() because if no user file exists, initial admin account needs to be created
		
		String userFile = "UserList.bin";
		String groupFile = "GroupList.bin"; 
		Scanner console = new Scanner(System.in);
		ObjectInputStream userStream;
		ObjectInputStream groupStream;
		String username="";
		String password = ""; 
		//This runs a thread that saves the lists on program exit
		Runtime runtime = Runtime.getRuntime();
		runtime.addShutdownHook(new ShutDownListener(this));
		
		//Open user file to get user list
		try
		{
			FileInputStream fis = new FileInputStream(userFile);
			userStream = new ObjectInputStream(fis);
			userList = (UserList)userStream.readObject();
		}
		catch(FileNotFoundException e)
		{
			System.out.println("UserList File Does Not Exist. Creating UserList...");
			System.out.println("No users currently exist. Your account will be the administrator.");
			System.out.print("Enter your username: ");
			username = console.next();
			System.out.print("Enter your password: "); 
			password = console.next(); 
			
			BigInteger g = new BigInteger((long)2); 
			BigInteger q = new BigInteger(G, 16); 
			BigInteger newPass = g.modPow(hash, q);
			//Create a new list, add current user to the ADMIN group. They now own the ADMIN group.
			userList = new UserList();
			userList.addUser(username);
			userList.addGroup(username, "ADMIN");
			userList.addOwnership(username, "ADMIN");
		}
		catch(IOException e)
		{
			System.out.println("Error reading from UserList file");
			System.exit(-1);
		}
		catch(ClassNotFoundException e)
		{
			System.out.println("Error reading from UserList file");
			System.exit(-1);
		}
		try
		{
			FileInputStream gfis = new FileInputStream(groupFile);
			groupStream = new ObjectInputStream(gfis);
			gList = (Hashtable<String, Group>)groupStream.readObject();
			System.out.println("Reading From GroupList...");
		}
		catch(FileNotFoundException e)
		{
			System.out.println("GroupList File Does Not Exist. Creating GroupList...");
			System.out.println("No Groups exist. You will be a member of the ADMIN group"); 
			gList.put("ADMIN", new Group("ADMIN", username)); 
		}
		catch(IOException e)
		{
			System.out.println("Error reading from GroupList file");
			System.exit(-1);
		}
		catch(ClassNotFoundException e)
		{
			System.out.println("Error reading from GroupList file");
			System.exit(-1);
		}
		System.out.println("Group Server is up and running!"); 
		//Autosave Daemon. Saves lists every 5 minutes
		AutoSave aSave = new AutoSave(this);
		aSave.setDaemon(true);
		aSave.start();
		
		//This block listens for connections and creates threads on new connections
		try
		{
			
			final ServerSocket serverSock = new ServerSocket(port);
			
			Socket sock = null;
			GroupThread thread = null;
			
			while(true)
			{
				sock = serverSock.accept();
				thread = new GroupThread(sock, this);
				thread.start();
			}
		}
		catch(Exception e)
		{
			System.err.println("Error: " + e.getMessage());
			e.printStackTrace(System.err);
		}

	}
	
}

//This thread saves the user list
class ShutDownListener extends Thread
{
	public GroupServer my_gs;
	
	public ShutDownListener (GroupServer _gs) {
		my_gs = _gs;
	}
	
	public void run()
	{
		System.out.println("Shutting down server");
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
}

class AutoSave extends Thread
{
	public GroupServer my_gs;
	
	public AutoSave (GroupServer _gs) {
		my_gs = _gs;
	}
	
	public void run()
	{
		do
		{
			try
			{
				Thread.sleep(300000); //Save group and user lists every 5 minutes
				System.out.println("Autosave group and user lists...");
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
			catch(Exception e)
			{
				System.out.println("Autosave Interrupted");
			}
		}while(true);
	}
}
