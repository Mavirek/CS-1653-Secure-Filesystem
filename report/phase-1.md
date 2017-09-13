   Allen Poon, alp170, mavrick  
   Justin Keenan, jak244, jak244  
   Sai Konduru, sck42, sck42

  
**Section 1 : Security Properties**

1. Limited Access
	* Each group’s admin can pass permissions to read only or read/write, and can add/delete files. 
	* Least Privilege says that each user can operate with a minimal access prevent malicious corruption. Follows the Fail-safe 		defaults principle. Follows the Least common mechanism.
	* Assumes the admin has no intent to corrupt. Assumes each user gets correct privilege. 
1. Isolation
	* Each group’s admin controls who can see the group’s file so no one has access to files from groups that they don’t belong to. 
	* Helps maintain integrity and confidentiality. In the event that an admin account gets corrupted, the attacker cannot gain 		access to other groups. 
	* Assumes groups are assigned correctly. 
1. Reliability 
	* File servers are automatically backed up daily. 
	* Insures data integrity despite failures because corrupted files can be compared to the backup files to ensure data matches. 		Protects against attacks that cause data breaches resulting in data being lost or modified. 
	* Assumes servers back up regularly and accurately. 
1. Two Factor Authorization
	* Each user has to pass two forms of authorization in-order to gain access to account. The second form of authorization is a 		randomly generated passcode sent to a previously approved mobile device. 
	* Prevents data breach by confiscation of the password because attacker will still need to provide the passcode sent to the 		account holder’s mobile device. 
	* Assumes only the user has access to both forms of authorization. Assumes an account is needed to login to access files. 		Assumes attacker doesn’t have access to the approved device.
1. Transit Attacks 
	* Data is encrypted and decrypted locally before sending to prevent attackers from gaining access through transit attacks.  
	* This ensures that attacks can’t gain access by attacking data as it flows through the network because they will only see 		ciphertext.
	* Assumes encryption occurs on a secure local system.   
1. Encrypted Server Data
	* Data in the servers is encrypted and keys used for the encryption are on the local systems of the authorized user. 
	* Ensures that direct attack towards server won’t result in a data breach because the data in the server is ciphertext. 
	* Assumes keys are safe on authorized systems.
1. Malicious Files
	* Both the group server and the file servers should be protected from viruses and malicious files that could be uploaded or 		discretely transferred from clients.  
	* If a malicious file or virus were to be introduced to the server, the server will automatically defend itself.  
	* Assumes virus can be detected by the server. 
1. Session Control
	* Connection to server is established and discontinued after the user’s session is over and/or the session times out.
	* Session timeouts are for preventing piggybacking off a client’s connection and attacks where the client’s hardware is 		compromised (as in stolen or tampered with when the user is not physically around) while the user is still connected to the 		server.
	* Assumes user can connect and logs out when done.
1. Concurrency Control
	* When a user is writing to a file, the server places a lock on the file. This lock causes other users to only have read access 	in order to prevent race condition exploitations.
	* Prevents multiple people from writing to the same file at once and prevent concurrent modification.
	* Assumes lock is given at a first come first serve. 
1. Local Encryptor
	* Encrypting any downloads from the server to local systems in the case where the attackers can steal downloaded files from the 	local systems either physically or virtually.
	* Prevents unauthorized access of files through downloads on local systems. 
	* Assumes local systems aren’t as secure as the servers since the security on local systems may vary. 
1. Device Management
	* Ensure an approved device is used when accessing file sharing servers.
	* Prevents unauthorized access of accounts. 
	* Assumes the user registers all their devices that they plan to use to access the server
1. Traffic Control
	* Each group’s amount of traffic from server to clients will be limited. 
	* Prevents attacks where hacker floods server with file requests and prevents overload or shutdown of server via too much 		traffic flow. 
	* Assumes the limit will be high enough for the group to work efficiently but low enough to prevent the overload. 
1. Private Connections
	* All communication between servers and clients will be through a private connection. (VPN)
	* Harder for attackers to steal data in transit since the connections are hidden. 
	* Assumes the private connections are harder to find. 
1. Strong Passwords 
	* Restricts what a password can be and ensures that a user gets a certain amount of tries to enter the correct authorization. 
	* Protects against brute force password guessing. 
	* Assumes the amount of tries is high enough for an authorized user to gain access to his account but low enough to prevent 		brute forcing. 
1. Unauthorized Modifications
	* Keeps track of file modifications via file history made by various users to ensure the file hasn’t gone through unapproved 		modification. 
	* Ensures that files have only been changed when appropriate i.e no malicious modifications of the files were made. We know what 	files have been changed but not how they have been changed. 
	* Assumes attacker can’t modify the logs. 
1. Sniffing Attacks
	* Servers should be physically and wirelessly secure in the case of sniffing attacks
	* Prevents transmitted server traffic from being intercepted by the attacker wirelessly through the air or physically by being 		in contact with the router.
	* Assumes servers are physically secured away from unauthorized employees and visitors, as well as having a strong wireless 		security.
1. Authorized Communication
	* Communication between client and company behind file sharing software is authorized and verified.
	* Ensures that attackers can’t interrupt communication between client and company and gain private user information by 			pretending to be the company. 
	* Assumes user will know how to use verification method to accurately determine if the one they are communicating with is in 		fact the company. 
	
  	
**Section 2 : Threat Models**

1. Employee Network

	Used for employees to share files with their supervisor. The company has a large scale employee base meaning multiple employees per supervisor and multiple supervisors per building. This results in multiple small groups using the file sharing system throughout the company. Each supervisor is incharge of how many people are in his group thereby how many people have access to his files. The supervisor also passes out privileges for each member of the group. Servers will be a wired setup where the local computers are connected via ethernet.

	Assume supervisor and employees are background checked by the company. Supervisors have thorough knowledge of their corresponding group servers. Assume employees maintain servers and its backups regularly. Employees are also assumed to have had training on using the servers’ interface and security protocols. Assume employees seldomly write to the same file at similar times, while most of the time they just read the same file at the same time. Assumes nobody is allowed to have access to the servers unless they are an authorized employee.
	
* Limited Access
	* Supervisor is the admin for each group. The admin sets permissions for everyone in their specific group. 
* Isolation
	* Keeps each member’s accessibility contained to their group. 
* Reliability 
	* Servers are regularly maintained and backed up by the employees of the company. 
* Two Factor Authorization
	* Each employee has two forms of authorization to access the system. 
* Encrypted Server Data 
	* Ensures any physical attacks towards the servers don’t result in data confidentiality because of servers only contain 		ciphertext. 
* Malicious Files
	* None of the employees can physically or virtually attack the server through malicious files or viruses. 
* Concurrency Control
	* Server ensures that only one employee can write a file at once to avoid concurrent modification.
* Device Management
	* All company devices are registered and approved so only company devices have access to the system. 
* Traffic Control
	* Employees cannot put too much strain on the traffic and prevent any malicious employee from overloading the servers. 
* Strong Passwords
	* Each employee is given an appropriate password by the company. 
* Unauthorized Modifications
	* Supervisor can monitor each employee’s logs and ensure they are doing their given task. 

	
2. Foreign Network

	A company with remote workers will use this file sharing system. Network is assumed to be privately, wirelessly connected and accessible from anywhere provided the employees have the application, developed by the company. It communicates directly with the file servers and has the correct encryption/decryption algorithms needed for sending/receiving files to/from the servers. Employees will need to register their devices with the company first before using the file server application. These registered devices will employ the two factor authentication system. A supervisor will be incharge of managing a certain number of employee determined by the company. 
	
	All employees and supervisors will go through training and background checks to ensure no malicious intent and ensure that employees have knowledge of all security protocols. Supervisors have thorough knowledge of their corresponding group servers. Assume servers are automatically backed up regularly. Connections between groups and group member are hidden. Assume local devices used by the employees are registered by the company and secure. Assume employee don’t need to write to the same file at the same time. Assumes servers have good physical and wireless security.
	
* Limited Access
	* Supervisor is the admin for each group. The admin sets permissions for everyone in their specific group. 
* Isolation
	* Keeps each member’s accessibility contained to their group. 
* Reliability 
	* Servers are regularly maintained and backed up by the employees of the company.
* Simple Design
	* Employees are trained to use the software, and the software is kept simple to make for easy use of the system. 
* Two Factor Authorization
	* Each employee has two forms of authorization to access the system. 
* Public 
	* The system’s architecture and software are made public. 
* Log in Encryption/Decryption
	* The system will encrypt and decrypt files at rest. 
* Server Firewall
	* Protects server from viruses that could be introduced by rival companies and attackers. 
* Session Control
	* Employees will only have access to server for an allotted time or until they log out.
* Concurrency Control
	* Server ensures that only one employee can write a file at once to avoid concurrent modification.
* Certificate Pinning
	* Forces the employees to connect via the application. Verifies each employee’s identification. 
* Local Encryptor
	* When employees wish to download a file, the application will split encrypt and separate the file throughout the local system. 
* IP detection
	* Detects unregistered devices and notifies employees. Assumes employees will respond appropriately.  
* Upload Limit
	* Any file greater than a preset size uploaded by the user is split into chunks and encrypted by the system before being sent to 	the server. 
* File server storage scheme
	* Server splits any file, that an employee wishes to store, into blocks for easy storage, encryption, and checksumming. 

  
**Section 3 : References**

https://msdn.microsoft.com/en-us/library/windows/desktop/aa365233(v=vs.85).aspx
https://www.dropbox.com/business/trust/security/information-security
https://en.wikipedia.org/wiki/Digital_signature#How_they_work  
http://www.fsl.cs.sunysb.edu/docs/integrity-storagess05/integrity.html
