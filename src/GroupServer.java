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
import java.security.*;
import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import java.security.KeyPairGenerator;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.SecretKey;
import org.bouncycastle.jce.provider.BouncyCastleProvider;


public class GroupServer extends Server {

	public static final int SERVER_PORT = 8765;
	public UserList userList;
	public Hashtable<String, Group> gList = new Hashtable<String, Group>();
	private EncryptDecrypt ed = new EncryptDecrypt();
	//gk<String groupName, ArrayList<SecretKey> gkList>
	public GroupKeys gk;
    protected Hashtable<GroupThread, String> gtip;
	public static Hashtable<String, SessionID> acceptedSessionIDs;
	public static Hashtable<String, SessionID> unacceptedSessionIDs; 
	public GroupServer() {
		super(SERVER_PORT, "ALPHA");
	}
	
	public GroupServer(int _port) {
		super(_port, "ALPHA");
	}
	@SuppressWarnings("unchecked")
	public void start() {
		// Overwrote server.start() because if no user file exists, initial admin account needs to be created
	    
		Security.addProvider(new BouncyCastleProvider());
		String userFile = "UserList.bin";
		String groupFile = "GroupList.bin";
		String gkFile = "GroupKeysList.bin";
		String sessFile = "SessionIDGS.bin";
		Scanner console = new Scanner(System.in);
		ObjectInputStream userStream;
		ObjectInputStream groupStream;
		ObjectInputStream gkStream;
		gtip = new Hashtable<GroupThread, String>();
		String username = "";
		String password = "";
		byte[] hashPass;
		String storePass;

		//This runs a thread that saves the lists on program exit
		Runtime runtime = Runtime.getRuntime();
		runtime.addShutdownHook(new ShutDownListener(this));

		//Open user file to get user list
		try
		{
			FileInputStream fis = new FileInputStream(userFile);
			userStream = new ObjectInputStream(fis);
			userList = (UserList)userStream.readObject();
			FileInputStream gkfis = new FileInputStream(gkFile);
			gkStream = new ObjectInputStream(gkfis);
			gk = (GroupKeys)gkStream.readObject();
		}
		catch(FileNotFoundException e)
		{
			System.out.println("UserList File Does Not Exist. Creating UserList...");
			System.out.println("No users currently exist. Your account will be the administrator.");
			System.out.print("Enter your username: ");
			username = console.next();
			while(username.contains(":"))
			{
				System.out.println("Please enter a username that does not contain the ':' char: "); 
				username = console.next(); 
			}
			System.out.print("Enter your password: ");
 			password = console.next();
			hashPass = ed.hashThis(password);
			storePass = ed.passDH(hashPass);

			//System.out.println("Pass to store : " + storePass);

 			//BigInteger g = new BigInteger((long)2);
 			//BigInteger q = new BigInteger(G, 16);
 			//BigInteger newPass = g.modPow(hash, q);
			//Create a new list, add current user to the ADMIN group. They now own the ADMIN group.
			userList = new UserList();
			userList.addUser(username);
			userList.setPassword(username, storePass);
			userList.addGroup(username, "ADMIN");
			userList.addOwnership(username, "ADMIN");
			System.out.println("GroupKeysList file does not exist. Creating GroupsKeysList...");
			gk = new GroupKeys();
			try
			{
				KeyGenerator keyGen = KeyGenerator.getInstance("AES","BC");
				keyGen.init(128);
				SecretKey key = keyGen.generateKey();
				gk.addGroup("ADMIN",key);
			}
			catch(Exception ge)
			{
				System.out.println("Error creating the group's file key");
				System.exit(-1);
			}
			
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
		//Open Session file to get SessionIDs Hashtable
		try
		{
			//Read SessionIDGS.bin
			FileInputStream fis = new FileInputStream(sessFile);
			groupStream = new ObjectInputStream(fis);
			unacceptedSessionIDs = (Hashtable<String, SessionID>)groupStream.readObject();
			acceptedSessionIDs = new Hashtable<String, SessionID>(); 
		}
		catch(FileNotFoundException e)
		{
			System.out.println("SessionIDs Does Not Exist. Creating SessionIDs...");
			unacceptedSessionIDs = new Hashtable<String, SessionID>();
			acceptedSessionIDs = new Hashtable<String, SessionID>(); 
		}
		catch(IOException e)
		{
			System.out.println("Error reading from FileList file");
			System.exit(-1);
		}
		catch(ClassNotFoundException e)
		{
			System.out.println("Error reading from FileList file");
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
				if(!gtip.contains(sock.getInetAddress().toString()))
			        {
				    gtip.put(thread,sock.getInetAddress().toString());
				    thread.start();
				    System.out.println("connected");
				     if(thread.getState()==Thread.State.TERMINATED)
				    	{
				     gtip.remove(thread);
					    	}
				}
				else{
				    sock.close();
				    System.out.println("rejected");
				}
			
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
				System.out.println("Autosave group, user, and groupkey lists...");
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
			catch(Exception e)
			{
				System.out.println("Autosave Interrupted");
			}
		}while(true);
	}
}
