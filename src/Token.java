//Sai Made this.
//NOT A GIVEN FILE
//COULD BE WRONG 


import java.util.*; 


public class Token implements UserToken {
	
	private String issuer;
	private String subject; 
	private ArrayList<String> groups = new ArrayList<String>(); 
	private boolean isAdmin; 
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
	public void setAdmin(boolean admin){
		isAdmin = admin; 
	}
	public boolean isAdministrator(){
		return isAdmin; 
	}
}
