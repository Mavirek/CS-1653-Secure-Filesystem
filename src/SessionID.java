import java.io.*; 
import java.util.*;
import java.security.*; 
import java.text.SimpleDateFormat; 
public class SessionID implements java.io.Serializable
{
	private String username; 
	private Date date; 
	private int randomNumber;
	private int sequenceNumber;
	private final SimpleDateFormat sdf = new SimpleDateFormat("E MM.dd.YYYY");
	private SecureRandom sr = new SecureRandom(); 
	public SessionID(String un)
	{
		username = un; 
		date = new Date(); 
		randomNumber = sr.nextInt(); 
		sequenceNumber = 0; 
	}
	public SessionID(String un, Date d, int rn, int sn)
	{
		username = un; 
		date = d; 
		randomNumber = rn; 
		sequenceNumber = sn; 
	}
	public void nextMsg()
	{
		sequenceNumber++; 
	}
	public void newSession()
	{
		randomNumber = sr.nextInt(); 
		sequenceNumber = 0; 
	}
	public void setSession(int x)
	{
		sequenceNumber = x; 
	}
	public String toString()
	{
		return username + ":" + sdf.format(date) + ":" + randomNumber + ":" + sequenceNumber;  
	}
	public boolean equals(SessionID sd)
	{
		return toString().equals(sd.toString()); 
	}
	public boolean isToday()
	{
		Date newDate = new Date();  
		return sdf.format(date).equals(sdf.format(newDate)); 
	}
	public String getUserName()
	{
		return username; 
	}
	public int getRandNumber()
	{
		return randomNumber; 
	}
	public Date getDate()
	{
		return date; 
	}
}