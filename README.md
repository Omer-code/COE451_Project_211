# COE 451 – Computer and Network Security (T211) Term Project

## Phase One:
This is step by step demonstration for phase one of COE-451 term project.

Phase One Description:
Build a client-server file transfer application using any programming language of your choice. The
application must use TCP as a transport layer to ensure reliability. The client application must
continuously provide the user with a command prompt allowing the user to select between 3 commands;
GET, PUT, and QUIT. The GET command (syntax: GET filename) retrieves a copy of a specified file
from the server side. The PUT command (syntax: PUT filename) places a copy of a specified file from the
client side on the server side. Once a GET command or a PUT command has been executed, the command
prompt should be provided back to the user. If the user issues a QUIT command, then the client
application should close the TCP connection and terminate the client application.

* Requirements to run the project:
1. Python.
2. Python Socket package.
3. Python OS package.
4. Preferably a virtual machine for testing.
5. When sending files from the server or client, make sure the files are located in the workplace of your project.

* You can watch the video linked below for a live demo:
https://kfupmedusa.sharepoint.com/:v:/s/gg606/EdgypfBWUPRCvcg2a9iA5LsBVqFrtHT_-OTb2DTpfAzqCA?e=XICJ8p

* References:
-for sending files via tcp client-server application:
     https://www.thepythoncode.com/article/send-receive-files-using-sockets-python
-for socket programming:
     https://www.youtube.com/watch?v=3QiPPX-KeSc

## Phase Two: 

Phase Two Description:
Modify the online file transfer application that you had for phase 1 so that your code encrypts/decrypts the
files that are exchanged between the client and the server. Use AES symmetric-key crypto system with
256-bit key and with CBC mode in your code. Use an online SHA256 to hash your student ID to
generate a unique 256 bits hashed value to be used as the AES 256-bit key. For this phase, you can hard
code the 256-bit key in your client and server applications. As for the Initialization Vector (IV) to be used
by the CBC mode, make sure to generate a new IV for each file transfer. The file sending side is
responsible for generating the IV, and should send the IV to the other side. The IV should be 128 bits long
to match the AES plaintext block size, and it should be generated using a cryptographically secure
random number generator (CSRNG) function/method (research which CSRNG function/method is the
most suitable to use for your code through the Internet). To encrypt a file to be sent to the other side, you
may need to pad the file if the last generated plaintext block of the file is less than 128 bits long (research
the proper way of how padding should be done through the Internet). Once the IV is generated and the
encrypted file is produced, then send the IV (in plaintext) first before sending the encrypted file to the
other side (i.e., the file receiving side will always expect the first 16 bytes (or 128 bits) of a received
encrypted file to contain the IV that the other side has used for encrypting the file). The file receiving side
should use the received IV along with the hard-coded symmetric key to decrypt the received encrypted
file.

* Requirements to run the project:
1. Python.
2. Python Socket package.
3. Python OS package.
4. Python pycryptodome package.
5. Preferably a virtual machine for testing.
6. When sending files from the server or client, make sure the files are located in the workplace of your project.

* You can watch the video linked below for a step by step live demo:
https://kfupmedusa.sharepoint.com/:v:/s/gg606/EdgypfBWUPRCvcg2a9iA5LsBVqFrtHT_-OTb2DTpfAzqCA?e=XICJ8p

* Or, you can follow the the instructions below:
1. Run server_side.py on one of your machines.
2. Run client_side.py on another machine.
3. In the client side, it will ask you for the IP address of your server, enter the IP. (you can check your IP address by ipconfig command)
4. After the connection is established, the program will ask you to choose one of three commands: PUT, GET, or QUIT. (refer to phase one for more about this)
     -for PUT command: 
          1. you can choose whether you to encrypt the file ot not, then enter the file you want to send.
          2. in case you have encrypted the file, from your server side, you can choose whether to decrypt it or not.
     -for GET command:
          1. enter the file you want to receive from the server side.
          2. you will receive an encrypted the file, you can choose whether to decrypt it or not.
     -for QUIT command:
          it will terminate both programs and close the socket.

* References:
-for AES encryption:
     https://pycryptodome.readthedocs.io/en/latest/src/introduction.html
     https://www.youtube.com/watch?v=KRA_scVTBp0
-for online AES encryption tool:
     https://cryptii.com/pipes/aes-encryption