import socket
import os
from hashlib import new
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
from binascii import unhexlify

KEY = unhexlify('46c5ae5c3023b4bda04f589346cb26830a7667943b9f55bf0d187da91ce40a1f')
# device's IP address
SERVER_HOST = socket.gethostbyname(socket.gethostname())
SERVER_PORT = 5001
# receive 4096 bytes each time
BUFFER_SIZE = 4096
SEPARATOR = "<SEPARATOR>"
# the request type, PUT, GET or QUIT
request_type = ""
def encrypt_file(iv, input_file, output_file):
    with open(input_file, "rb") as f:
        bytes_read = f.read()
        print(bytes_read)
    with open(output_file, "wb") as f:
        paded_bytes = pad(bytes_read,AES.block_size)
        AES_opject = AES.new(KEY,AES.MODE_CBC,iv)
        cipher_text = AES_opject.encrypt(paded_bytes)
        print(cipher_text)
        f.write(cipher_text)

def decrypt_file(iv, input_file, output_file):
    with open(input_file, "rb") as f:
        bytes_read = f.read()
        print(bytes_read)
    with open(output_file, "wb") as f:
        AES_opject = AES.new(KEY,AES.MODE_CBC,iv)
        data_bytes = AES_opject.decrypt(bytes_read)
        unpaded_bytes = unpad(data_bytes,AES.block_size)
        print(unpaded_bytes)
        f.write(unpaded_bytes)

if __name__ == '__main__':
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
    while True:
        decrypt_flag = False
        # receive the request type
        request_type = client_socket.recv(BUFFER_SIZE).decode()
        print(request_type)
        if request_type == "quit":
            print("Quit!")
            # close the client socket
            client_socket.close()
            # close the server socket
            s.close()
            break
        # print the request type
        elif request_type=="put":
            encrypt_flag = client_socket.recv(BUFFER_SIZE).decode()
            print(encrypt_flag)
            if encrypt_flag == "True":
                iv = client_socket.recv(BUFFER_SIZE)
                print(iv)
                decrypt_flag = True
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
            if decrypt_flag:
                encrypt_prompt = input("You have received an encrypted file. Do you want to decrypt it? (y/n)")
                if encrypt_prompt =="y":
                    print(iv)
                    decrypt_file(iv, filename, filename)
        elif request_type=="get":
            # receive the filename of the file you want to get
            filename = client_socket.recv(BUFFER_SIZE).decode()
            # get the file size
            filesize = os.path.getsize(filename)
            # send the filename and filesize
            client_socket.send(f"{filesize}".encode())
            # start sending the file
            opened_file = 'enc.txt'
            iv = get_random_bytes(16)
            client_socket.send(iv)
            with open(opened_file, "rb") as f:
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
        else:
            break

    

