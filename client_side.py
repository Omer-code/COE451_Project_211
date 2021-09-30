import socket
import os
 
SEPARATOR = "<SEPARATOR>"
BUFFER_SIZE = 4096 # send 4096 bytes each time step
request_type = "" # type of the requset: PUT, GET, or QUIT
# the ip address or hostname of the server, the receiver
host = input("What is the ip address of the server?\n")
# the port, let's use 5001
port = 5001
 
# create the client socket
s = socket.socket()
 
print(f"[+] Connecting to {host}:{port}")
s.connect((host, port))
print("[+] Connected.")
 
# a while loop to ensure the client is waiting for commands from user
while True:
   # Get the type of the requset from the user
   request_type = input("What do you want to do?\n1.GET\n2.PUT\n3.QUIT\n")
   request_type = request_type.lower()
   s.send(request_type.encode())
   if request_type=="put":
       # the name of file we want to send, make sure it exists
       filename = input("Enter the name of the file you want to send:\n")
       # get the file size
       filesize = os.path.getsize(filename)
       # send the filename and filesize
       s.send(f"{filename}{SEPARATOR}{filesize}".encode())
       # start sending the file
       with open(filename, "rb") as f:
           while True:
               # read the bytes from the file
               bytes_read = f.read(BUFFER_SIZE)
               if not bytes_read:
                   # a tag to let the server know that we reached the end of the file
                   s.send("--END--".encode())
                   # file transmitting is done
                   break
               # we use sendall to assure transimission in
               # busy networks
               s.sendall(bytes_read)
               # update the progress bar
       print(filename + " has been sent.\n")
   elif request_type=="get":
       # the name of file we want to send, make sure it exists
       filename = input("Enter the name of the file you want to receive:\n")
       # send the filename
       s.send(f"{filename}".encode())
       filesize = s.recv(BUFFER_SIZE).decode()
       # remove absolute path if there is
       filename = os.path.basename(filename)
       # convert to integer
       filesize = int(filesize)
       # start receiving the file from the socket
       # and writing to the file stream
       with open(filename, "wb") as f:
           while True:
               # read 1024 bytes from the socket (receive)
               bytes_read = s.recv(BUFFER_SIZE)
               # to check if we reached the end of the file
               if b"--END--" in bytes_read:
                   bytes_read, a = bytes_read.split(b"--END--")
                   f.write(bytes_read)
                   break
               if not bytes_read:   
                   # nothing is received
                   # file transmitting is done
                   break
               # write to the file the bytes we just received
               f.write(bytes_read)
               # update the progress bar
           print(filename + " has been received.\n")       
   elif request_type=="quit":
       print("Quit!\n")
       # close the socket
       s.close()
       break
   else:
       print("Wrong Input! Please enter one of the three commands, GET, PUT, or QUIT.\n")
print("Done! Thank You!")
 
 
########################################
# References:
# for sending files via tcp client-server:
#     https://www.thepythoncode.com/article/send-receive-files-using-sockets-python
# for socket programming:
#     https://www.youtube.com/watch?v=3QiPPX-KeSc  
########################################
