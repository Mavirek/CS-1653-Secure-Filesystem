import java.util.*;
import java.io.*;
import java.security.*;
import javax.crypto.*;

public class Attack{

	public static void main(String[] args)
	{
		System.out.println("I am the attacker");
		AttackClient ac = new AttackClient();
		while(true)
		{
			try{
				if(ac.connect(args[0], Integer.parseInt(args[1]), "jak244", "keener", "localhost", 4321)) {
          ac.attack();
        }

			}
			catch(Exception e){
				e.printStackTrace();
				System.exit(0);
			}
		}

	}
}
