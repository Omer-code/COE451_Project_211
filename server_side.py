import socket
import os

# device's IP address
SERVER_HOST = socket.gethostbyname(socket.gethostname())
SERVER_PORT = 5001
# receive 4096 bytes each time
BUFFER_SIZE = 4096
SEPARATOR = "<SEPARATOR>"
# the request type, PUT, GET or QUIT
request_type = ""

# create the server socket
# TCP socket
s = socket.socket()

# bind the socket to our local address
s.bind((SERVER_HOST, SERVER_PORT))

# enabling our server to accept connections
# 5 here is the number of unaccepted connections that
# the system will allow before refusing new connections
s.listen(5)
print(f"[*] Listening as {SERVER_HOST}:{SERVER_PORT}")

# accept connection if there is any
client_socket, address = s.accept() 
# if below code is executed, that means the sender is connected
print(f"[+] {address} is connected.")

# a while loop to ensure the server is waiting for commands
while request_type !="quit":
    # receive the request type
    request_type = client_socket.recv(BUFFER_SIZE).decode()
    # print the request type
    print(request_type)
    if request_type=="put":
        # receive the file infos
        # receive using client socket, not server socket
        received = client_socket.recv(BUFFER_SIZE).decode()
        filename, filesize = received.split(SEPARATOR)
        # remove absolute path if there is
        filename = os.path.basename(filename)
        # convert to integer
        filesize = int(filesize)
        # start receiving the file from the socket
        # and writing to the file stream
        with open(filename, "wb") as f:
            while True:
                # read 1024 bytes from the socket (receive) 
                bytes_read = client_socket.recv(BUFFER_SIZE)
                # to check if we reached the end of the file
                if b"--END--" in bytes_read:
                    bytes_read, a = bytes_read.split(b"--END--")
                    f.write(bytes_read)
                    # print to check
                    print(bytes_read)
                    break
                if not bytes_read:    
                    # nothing is received
                    # file transmitting is done
                    break
                # write to the file the bytes we just received
                f.write(bytes_read)
                # update the progress bar
    if request_type=="get":
        # receive the filename of the file you want to get
        filename = client_socket.recv(BUFFER_SIZE).decode()
        # get the file size
        filesize = os.path.getsize(filename)
        # send the filename and filesize
        client_socket.send(f"{filesize}".encode())
        # start sending the file
        with open(filename, "rb") as f:
            while True:
                # read the bytes from the file
                bytes_read = f.read(BUFFER_SIZE)
                print(bytes_read)
                if not bytes_read:
                    client_socket.send("--END--".encode())
                    # file transmitting is done
                    break
                # we use sendall to assure transimission in
                # busy networks
                client_socket.sendall(bytes_read)
                # update the progress bar

# close the client socket
client_socket.close()
# close the server socket
s.close()

