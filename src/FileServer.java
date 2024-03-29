/* FileServer loads files from FileList.bin.  Stores files in shared_files directory. */

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.net.ServerSocket;
import java.net.Socket;
import java.io.*;
import java.util.*;
import javax.crypto.*;
import java.security.*;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
public class FileServer extends Server {

	public static final int SERVER_PORT = 4321;
	public static FileList fileList;

	public static Hashtable<String, SessionID> acceptedSessionIDs;
	public static Hashtable<String, SessionID> unacceptedSessionIDs; 
	public static PublicKey filePubKey; 
	public static PrivateKey filePrivKey; 
	public FileServer() {
		super(SERVER_PORT, "FilePile");
	}

	public FileServer(int _port) {
		super(_port, "FilePile");
	}
  
	@SuppressWarnings("unchecked")
	public void start() throws Exception {
		Security.addProvider(new BouncyCastleProvider());
		
		KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA", "BC");
		kpg.initialize(2048);
		KeyPair kp = kpg.generateKeyPair();
		filePrivKey = kp.getPrivate();
		filePubKey = kp.getPublic();
		
		String fileFile = "FileList.bin";
		String sessFile = "SessionIDFS.bin";
		ObjectInputStream fileStream;
		//This runs a thread that saves the lists on program exit
		Runtime runtime = Runtime.getRuntime();
		Thread catchExit = new Thread(new ShutDownListenerFS());
		runtime.addShutdownHook(catchExit);

		//Open user file to get user list
		try
		{
			//Read FileList.bin
			FileInputStream fis = new FileInputStream(fileFile);
			fileStream = new ObjectInputStream(fis);
			fileList = (FileList)fileStream.readObject();
		}
		catch(FileNotFoundException e)
		{
			System.out.println("FileList Does Not Exist. Creating FileList...");
			fileList = new FileList();

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
		//Open Session file to get SessionIDs Hashtable
		try
		{
			//Read SessionIDFS.bin
			FileInputStream fis = new FileInputStream(sessFile);
			fileStream = new ObjectInputStream(fis);
			unacceptedSessionIDs = (Hashtable<String, SessionID>)fileStream.readObject();
			acceptedSessionIDs = new Hashtable<String, SessionID>(); 
		}
		catch(FileNotFoundException e)
		{
			System.out.println("SessionIDs Does Not Exist. Creating SessionIDs...");
			acceptedSessionIDs = new Hashtable<String, SessionID>();
			unacceptedSessionIDs = new Hashtable<String, SessionID>(); 
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

		
		File file = new File("shared_files");
		 if (file.mkdir()) {
			 System.out.println("Created new shared_files directory");
		 }
		 else if (file.exists()){
			 System.out.println("Found shared_files directory");
		 }
		 else {
			 System.out.println("Error creating shared_files directory");
		 }

		//Autosave Daemon. Saves lists every 5 minutes
		AutoSaveFS aSave = new AutoSaveFS();
		aSave.setDaemon(true);
		aSave.start();


		boolean running = true;

		try
		{
			final ServerSocket serverSock = new ServerSocket(port);
			System.out.printf("%s up and running\n", this.getClass().getName());

			Socket sock = null;
			Thread thread = null;

			while(running)
			{
				sock = serverSock.accept();
				/*System.out.println("Sock host name : " + sock.getInetAddress().getHostName());
				System.out.println("Sock IP : " + sock.getInetAddress());
				System.out.println("Sock Local port : " +sock.getLocalPort());
				System.out.println("Sock string : " + sock.toString());
				System.out.println("ServerSock host name : " + serverSock.getInetAddress().getHostName());
				System.out.println("ServerSock IP : " + serverSock.getInetAddress());
				System.out.println("ServerSock port : " + serverSock.getLocalPort());*/
				thread = new FileThread(sock, sock.getInetAddress().toString(), port);
				thread.start();
			}

			System.out.printf("%s shut down\n", this.getClass().getName());
		}
		catch(Exception e)
		{
			System.err.println("Error: " + e.getMessage());
			e.printStackTrace(System.err);
		}
	}
}

//This thread saves user and group lists
class ShutDownListenerFS implements Runnable
{
	public void run()
	{
		System.out.println("Shutting down server");
		ObjectOutputStream outStream;

		try
		{
			outStream = new ObjectOutputStream(new FileOutputStream("FileList.bin"));
			outStream.writeObject(FileServer.fileList);
			outStream = new ObjectOutputStream(new FileOutputStream("SessionIDFS.bin"));
			outStream.writeObject(FileServer.unacceptedSessionIDs);
		}
		catch(Exception e)
		{
			System.err.println("Error: " + e.getMessage());
			e.printStackTrace(System.err);
		}
	}
}

class AutoSaveFS extends Thread
{
	public void run()
	{
		do
		{
			try
			{
				Thread.sleep(300000); //Save group and user lists every 5 minutes
				System.out.println("Autosave file list...");
				ObjectOutputStream outStream;
				try
				{
					outStream = new ObjectOutputStream(new FileOutputStream("FileList.bin"));
					outStream.writeObject(FileServer.fileList);
					outStream = new ObjectOutputStream(new FileOutputStream("SessionIDFS.bin"));
					outStream.writeObject(FileServer.unacceptedSessionIDs);
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
