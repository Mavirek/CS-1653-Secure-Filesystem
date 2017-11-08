Run Group Server
java -cp .:/afs/cs.pitt.edu/usr0/adamlee/public/cs1653/bcprov-jdk15on-158.jar RunGroupServer <Groupserver port>

Run File Server
java -cp .:/afs/cs.pitt.edu/usr0/adamlee/public/cs1653/bcprov-jdk15on-158.jar RunFileServer <Fileserver port>

Run FileClientApp
java -cp .:/afs/cs.pitt.edu/usr0/adamlee/public/cs1653/bcprov-jdk15on-158.jar FileClientApp <Username> <Password> <Group server name> <File server name> <Group server port> <File server port>

Use numpad to pick choices. Ex. 1 to connect to Group Server
Be sure to get a UserToken (Option 1) before performing any Group Server operations and connecting to File Server.