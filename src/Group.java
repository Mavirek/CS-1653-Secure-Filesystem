import java.util.*;
import java.io.*;

public class Group{
	private String name; 
	private Token owner;
	private ArrayList<Token> users = new ArrayList<Token>(); 
	//USE THIS FOR ADMIN GROUP
	public Group(String gName)
	{
		name = gName;
	}
	public Group(String gName, Token gOwner)
	{
		name = gName; 
		owner = gOwner; 
		users.add(owner); 
	}
	public void addUser(Token user)
	{
		users.add(user); 
	}
	public boolean removeUser(Token user)
	{
		if(users.contains(user))
		{
			users.remove(user);
			return true;
		}
		return false; 
	}
	public Token getOwner()
	{
		return owner; 
	}
	public String getName()
	{
		return name; 
	}
	public ArrayList<Token> getUsers()
	{
		return users; 
	}
	public void printUserNames()
	{
		for(Token t : users)
		{
			System.out.println(t.getSubject()); 
		}
	}
}