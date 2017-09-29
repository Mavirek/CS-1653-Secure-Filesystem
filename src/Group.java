import java.util.*;
import java.io.*;

public class Group implements java.io.Serializable {
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
		return users;
	}
	public synchronized void printUserNames()
	{
		for(String t : users)
		{
			System.out.println(t);
		}
	}
}
