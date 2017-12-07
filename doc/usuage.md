# Usage Instructions

## Running the Group Server

To start the Group Server:
 - Enter the directory containing `RunGroupServer.class`
 - Type `java RunGroupServer [port number]`

Note that the port number argument to `RunGroupServer` is optional.  This argument specifies the port that the Group Server will listen to.  If unspecified, it defaults to port 8765.

When the group server is first started, there are no users or groups. Since there must be an administer of the system, the user is prompted via the console to enter a username. This name becomes the first user and is a member of the *ADMIN* group.  No groups other than *ADMIN* will exist.

## Running the File Server

To start the File Server:
 - Enter the directory containing `RunFileServer.class`
 - Type `java RunFileServer [port number]`

Note that the port number argument to `RunFileServer is optional.  This argument speficies the port that the File Server will list to. If unspecified, it defaults to port 4321.

The file server will create a shared_files inside the working directory if one does not exist. The file server is now online.

## Running the Client App
	java FileClientApp <username> <password> <group server name> <file server name> <group server port> <file server port>
	
## Resetting the Group or File Server

To reset the Group Server, delete the files `UserList.bin`, `GroupKeysList.bin`, `GroupList.bin` & `SessionIDGS.bin`

To reset the File Server, delete the `FileList.bin` & `SessionIDFS.bin` files and the `shared_files/` directory.

## Setup the Attack Without Solution
In GroupServer.java comment out all code in the while(true) except for sock = serverSock.accept(); thread = new GroupThread(sock, this); thread.start();
In GroupThread.java comment out my_gs.gtip.remove(this); in the two ifs it appears in on lines 409 and 416. 

Attack has to be done by an authorized client meaning a client that has been added to the group server. In Attack.java the client is hardcoded with the username "jak244" and password "keener". The File server information is hardcoded to be "localhost" with a port number of 4321. Should this information be kept without being modified, make sure that the user jak244 with the password keener has been added to the group server. 
Compile as normal.

## Run the Attack
	java Attack <group server name> <group server port>
	
## Implement Solution 
Uncomment the code from the "Setup the Attack Without Solution" section, recompile and run the Attack. 

