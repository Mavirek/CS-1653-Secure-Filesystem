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
			//check if group exists
			System.out.println("Options:");
			System.out.println("GET - get a token");
			System.out.println("CUSER - create a user");
			System.out.println("DUSER - delete a user");
			System.out.println("CGROUP - create a group");
			System.out.println("DGROUP - delete a group");
			System.out.println("LMEMBERS - list members of a group");
			System.out.println("AUSERTOGROUP - add a user to a group");
			System.out.println("RUSERFROMGROUP - remove a user from a group");
			System.out.println("DISCONNECT - disconnect from group server");

		}
		else
		{
			System.out.println("Unable to connect");
			System.exit(1);
		}

	}
}
