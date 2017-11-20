//Sai Made this.
//NOT A GIVEN FILE
//COULD BE WRONG


import java.util.*;
import java.security.*;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

public class Token implements UserToken, java.io.Serializable{

	private String issuer;
	private String subject; 
	private ArrayList<String> groups = new ArrayList<String>(); 
	private boolean isAdmin; 
	private byte[] signedHash;
	private boolean signed = false; 
	private byte[] hash; 
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
	public byte[] genHash()
	{
		String token = this.toString(); 
		MessageDigest md = null;
		try {
			md = MessageDigest.getInstance("SHA256", "BC");
			md.update(token.getBytes()); //"UTF-8"));
		}
		catch(Exception e) {
			System.out.println(e);
		}
		signed = false; 
		hash = md.digest(); 
		return hash; 
	}
	public byte[] getHash()
	{
		return hash; 
	}
	/* public void signHash(PrivateKey pk) throws Exception 
	{
		byte[] hash = genHash(); 
		//signedHash = [hash]pk; 
		Signature signer = Signature.getInstance("SHA1withRSA"); 
		signer.initSign(pk);
		signer.update(hash); 
		sgn = signer.sign(); 		
		signedHash = new String(sgn); 
		signed = true; 
	}
	public boolean verifySign(PublicKey pk) throws Exception
	{
		if(!signed) return false; 
		Signature signer = Signature.getInstance("SHA1withRSA"); 
		signer.initVerify(pk); 
		signer.update(this.genHash());
		return signer.verify(sgn); //signedHash.getBytes()); 
	} */
	public void setSignedHash(byte[] sHash)
	{
		signedHash = sHash; 
		signed = true; 
	}
	public boolean isSigned()
	{
		return signed; 
	}
	public byte[] getSignedHash()
	{
		return signedHash;
	}
}
