//Sai Made this.
//NOT A GIVEN FILE
//COULD BE WRONG 


import java.util.*; 


public class Token implements UserToken, java.io.Serializable{
	
	private String issuer;
	private String subject; 
	private ArrayList<String> groups = new ArrayList<String>(); 
	private boolean isAdmin; 
	public Token()
	{
		issuer = "Group"; 
		subject = "ADMIN OF ADMIN"; 
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
	public void print()
	{
		System.out.println("Issuer: " + issuer); 
		System.out.println("Subject: " + subject); 
		System.out.println(groups.size()); 
		for(int i = 0; i < groups.size(); i++)
		{
			System.out.println("Group " + i + ": " + groups.get(i)); 
		}
	}
}