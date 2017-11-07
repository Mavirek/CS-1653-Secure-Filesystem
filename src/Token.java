//Sai Made this.
//NOT A GIVEN FILE
//COULD BE WRONG


import java.util.*;
import java.security.*;


public class Token implements UserToken, java.io.Serializable{

	private String issuer;
	private String subject;
	private ArrayList<String> groups = new ArrayList<String>();
	private boolean isAdmin;
	private String hash;
	private String signedHash;
	public Token()
	{
		issuer = "Group";
		subject = "ADMIN OF ADMIN";
	}
	//subject:issuer:group1:group2:...:
	public Token(String tk)
	{
		String[] attributes = tk.split(":");
		subject = attributes[0];
		issuer = attributes[1];
		for(int i = 2; i < attributes.length; i++)
			groups.add(attributes[i]);
	}
	public Token(ArrayList<String> g)
	{
		groups = g;
	}
	public Token(String server, String user, ArrayList<String> g)
	{
		issuer = server;
		subject = user;
		groups = g;
	}
	public String getIssuer(){
		return issuer;
	}
	public String getSubject(){
		return subject;
	}
	public List<String> getGroups(){
		return groups;
	}
	public void addGroup(String groupName){
		System.out.println("Group being added for user: " + subject);
		if(groups.add(groupName))
			System.out.println("Group " + groupName + " added for user: " + subject);
	}
	public void removeGroup(String groupName){
		groups.remove(groupName);
	}
	public void setAdmin(boolean admin){
		isAdmin = admin;
	}
	public boolean isAdministrator(){
		return isAdmin;
	}
	//subject:issuer:group1:group2:...:
	public String toString()
	{
		StringBuilder builder = new StringBuilder();
		builder.append(subject);
		builder.append(":");
		builder.append(issuer);
		builder.append(":");
		String[] groupsArr = groups.toArray(new String[groups.size()]);
		Arrays.sort(groupsArr);
		for(int i = 0; i < groupsArr.length; i++)
		{
			builder.append(groupsArr[i] + ":");
		}
		return builder.toString();
	}
	public void setHash(String newHash)
	{
		hash = newHash;
	}
/*	public String getHash()
	{
		return hash;
	}*/
	public void signHash(Key pk)
	{
		//signedHash = [hash]pk;
	}
	public String getSignedHash()
	{
		return signedHash;
	}
}
