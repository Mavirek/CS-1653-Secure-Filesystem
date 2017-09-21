import java.util.*;

public class FileClientApp
{
	public static void main(String[] args)
	{
		if(args.length != 5)
		{
			System.err.println("Usage: java FileClientApp <Username> <Group Server Name> <File Server Name> <Group Port> <File Port>\n");
			System.exit(-1);
		}

		FileClient fc = new FileClient();
		GroupClient gc = new GroupClient();
		if(fc.connect(args[1],Integer.parseInt(args[3])) && gc.connect(args[2],Integer.parseInt(args[4])))
		{
			Scanner s = new Scanner(System.in);
			System.out.println("Connected to Group Server: "+args[1]+" Port: "+args[3]+" File Server: "+args[2]+" Port: "+args[4]);
			System.out.print("Please enter the group name: ");
			String groupName = s.next();
			
		}
		else
		{
			System.out.println("Unable to connect");
			System.exit(1);
		}

	}
}