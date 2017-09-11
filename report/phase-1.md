Allen Poon     alp170   mavrick
Justin Keenan  jak244   jak244
Sai Konduru    sck42    sck42

Section 1 : Security Properties

1. Limited Access
	* Each user in their group has appropriate access to their corresponding files based on permissions set by the admin. Each 		group’s admin can pass permissions to read only or read/write, can add/delete people from group and can add/delete files. 
	* Least Privilege says that each user can operate with a minimal access prevent malicious corruption. Follows the Fail-safe 		defaults principle. Follows the Least common mechanism. 
	* Assumes the admin has no intent to corrupt. Assumes each user gets correct privilege. 
1. Isolation
	* No one has access to files outside of their group scope. 
	* Helps maintain integrity and confidentiality. 
	* Assumes groups are assigned correctly. 
1. Reliability 
	* Backup servers that maintain up-to-date copies of the files. 
	* Insures data integrity despite failures. 
	* Assumes servers back up regularly and accurately. 
1. Simple Design
	* Simple and easy interface for all users. 
	* Prevents any human error caused by complicated interfaces. Follows the Economy of Mechanism principle. 
	* Assumes users understand simple design. 
1. Two Factor Authorization
	* Each user has to pass two forms of authorization in-order to gain access to account. 
	* Prevents data breach by confiscation of single password. 
	* Assumes only the user has access to both forms of authorization. Assumes an account is needed to login to access files.
1. Public 
	* The structure of the software is made public for all view. 
	* Follows open design principle, meaning even with access to how the software is designed, people can’t break it because of 		privilege and password protections. 
	* Assumes all password and privileges work correctly.  
1. Log in Encryption/Decryption
	* After user logs in, the data from file server is decrypted after the user receives it. After user logs off, the data is 		encrypted locally and sent back to the file server. 
	* Prevents any hacking attacks toward the file servers directly and during transit. Most probable crypto scheme would be 		asymmetric and uses synchronous stream cipher. 
	* Assumes keys stay hidden. Assumes user’s key is generated via a random string 
1. Server Firewall
	* Both the group server and the file servers have a firewall in place to protect the data and limits incoming traffic from the 		client side.
	* If an infected client were to gain access to the group server and file server, the firewall will prevent any viruses from 		infect the servers and thereby infecting other clients. 
	* Assumes virus can be detected by the firewall. 
1. Session Control
	* Connection to server is established and discontinued after the user’s session is over and/or the session times out.
	* Limits the amount of time the server is accessible to prevent it from being prone to attacks over a connection.
	* Assumes user can connect and logs out when done.
1. Concurrency Control
	* When a user is writing to a file, the server places a lock on the file. This lock causes other users to only have read access. 
	* Prevents multiple people from writing to the same file at once and prevent concurrent modification. 
	* Assumes lock is given at a first come first serve. 
1. Certificate Pinning
	* Everytime client accesses the server, they send a certificate that’s compared to verify their identity. 
	* Makes sure that an authorized client is accessing the server. 
	* Assume certificates are up-to-date. Assume user is accessing through the file-sharing application. 
1. Local Encryptor
	* Within the application, there exists an encryption protocol which encrypts and splits any file being downloaded from the 		servers into multiple blocks and separates through the local system. Ex. Spotify music files 
	* Prevents unauthorized access of files through downloads on local systems. 
	* Assumes user is using file sharing system for work purposes. 
1. IP detection
	* An email notification is sent to a user if his account has been accessed through a previously unknown device. 
	* Prevents unauthorized access of accounts. Detection of security breaches. 
	* Assumes users will respond to email notifications appropriately. Also assumes emails are not compromised. 
1. Upload limit
	* If a user wants to upload a file larger than a preset limit, an alternate encryption protocol is in place.
	* Ensures the larger file is received in one place to the server/client because other encryption would split the file into 		chunks and encrypts each one.
	* Assumes the admin sets an appropriate limit. 
1. File server storage scheme
	* When stored into the file server, all files are split into chunks before being encrypted. 
	* Ensures easier encryption and data integrity through checksumming. 
	* Assumes the encryption algorithm chooses most appropriate and efficient chunk size. 
	
Section 2 : Threat Models

1. Employee Network

	Used for employees to share files with their supervisor. The company has a large scale employee base meaning multiple employee per supervisor and multiple supervisors per building. This results in multiple small groups using the file sharing system throughout the company. Each supervisor is incharge of how many people are in his group thereby how many people have access to his files. The supervisor also passes out privileges for each member of the group. Servers will be a wired setup where the local computers are connected via ethernet.

	Assume supervisor and employees are background checked by the company. Supervisors have thorough knowledge of their corresponding group servers. Assume employees maintain servers and its backups regularly. Employees are also assumed to have had training on using the servers’ interface and security protocols. Assume employees seldomly write to the same file at similar times, while most of the time they just read the same file at the same time. 
	
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
* Server Firewall
	* Protects server from viruses that could be introduced by rival companies and attackers. 
* Concurrency Control
	* Server ensures that only one employee can write a file at once to avoid concurrent modification.
* File server storage scheme
	* Server splits any file, that an employee wishes to store, into blocks for easy storage, encryption, and checksumming.
	
2. Foreign Network

	A company with remote workers will use this file sharing system. Network is assumed to be outside of company headquarters. Most environment assumptions are similar to the Employee Network threat model, but with heavier security features when accessing company file servers. Employees access file servers through an application developed by the company that is used on any device. The application communicates directly with the file servers and has the correct encryption/decryption algorithms needed for sending/receiving files to/from the servers. Employees will need to register their devices with the company first before using the file server application.
	
	Trust assumptions regarding players in the system are similar to the Employee Network threat model. In this threat model, however, employees won’t be in direct contact with each other so additional security measures will be inplace. These security measure will require employees to respond appropriately to notification emails and notify the correct personal if they notice a breach of any kind. Employees will also be responsible for knowing and protecting their user information including usernames and passwords. Finally, employees are expected to log out of the application once they finish the session. 
	
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

Section 3 : References

https://msdn.microsoft.com/en-us/library/windows/desktop/aa365233(v=vs.85).aspx
https://www.dropbox.com/business/trust/security/information-security
https://en.wikipedia.org/wiki/Digital_signature#How_they_work
http://www.fsl.cs.sunysb.edu/docs/integrity-storagess05/integrity.html
