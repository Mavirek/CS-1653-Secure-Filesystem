import java.io.*; 
import java.util.*;
import java.security.*; 
public class Test
{
	public static void main(String[] args)
	{
		/* Token tk = new Token("sck42:ALPHA:squad2:squad:"); 
		Token tk2 = new Token("sck42:ALPHA:squad:squad2:"); 

		System.out.println(tk.toString()); 
		System.out.println(tk2.toString());  */
		Date today = new Date();
		System.out.println(today.toString()); 
		SecureRandom sr = new SecureRandom();
		SessionID me = new SessionID("sck42");
		System.out.println(me.toString()); 
		SessionID allen = new SessionID("alp170"); 
		System.out.println(me.equals(me)); 
		System.out.println(me.equals(allen)); 
		me.nextMsg(); 
		System.out.println(me.toString());
		me.newSession(); 
		System.out.println(me.toString());
		me.nextMsg(); 
		System.out.println(me.toString());
		System.out.println(me.isToday()); 
	}
}