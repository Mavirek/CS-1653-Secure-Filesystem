import java.util.*;
import java.io.*;

public class Group  implements java.io.Serializable{
	private String name;
	private String owner;
	private ArrayList<String> users = new ArrayList<String>();

	public Group(String gName, String gOwner)
	{
		name = gName;
		owner = gOwner;
		users.add(owner);
	}
	public synchronized void addUser(String user)
	{
		users.add(user);
	}
	public synchronized boolean removeUser(String user)
	{
		if(users.contains(user))
		{
			users.remove(user);
			//System.out.println("removeUser()");
			//printUserNames();
			return true;
		}
		return false;
	}
	public synchronized String getOwner()
	{
		return owner;
	}
	public synchronized String getName()
	{
		return name;
	}
	public synchronized ArrayList<String> getUsers()
	{
		ArrayList<String> temp = new ArrayList<String>();

		for(String s : users) {

			temp.add(s);
		}

		return temp;
	}
	public synchronized void printUserNames()
	{
		for(String t : users)
		{
			System.out.println(t);
		}
	}
}
