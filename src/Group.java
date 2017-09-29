import java.util.*;
import java.io.*;

public class Group{
	private String name; 
	private String owner;
	private ArrayList<String> users = new ArrayList<String>(); 

	public Group(String gName, String gOwner)
	{
		name = gName; 
		owner = gOwner; 
		users.add(owner); 
	}
	public void addUser(String user)
	{
		users.add(user); 
	}
	public boolean removeUser(String user)
	{
		if(users.contains(user))
		{
			users.remove(user);
			System.out.println("removeUser()");
			printUserNames();
			return true;
		}
		return false; 
	}
	public String getOwner()
	{
		return owner; 
	}
	public String getName()
	{
		return name; 
	}
	public ArrayList<String> getUsers()
	{
		return users; 
	}
	public void printUserNames()
	{
		for(String t : users)
		{
			System.out.println(t); 
		}
	}
}