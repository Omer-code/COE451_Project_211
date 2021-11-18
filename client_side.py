import socket
import os
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes # a cryptographically secure random number generator method, that get sourced directly from the OS
from binascii import unhexlify
# define constants
# The symmetric 256 bits key, generated from my student ID hash value (used SHA-256)
KEY = unhexlify('46c5ae5c3023b4bda04f589346cb26830a7667943b9f55bf0d187da91ce40a1f')
SEPARATOR = "<SEPARATOR>"
BUFFER_SIZE = 4096 # send 4096 bytes each time step

# two prime large numbers p1,q1
p1=3130000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001183811000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000313
p1_reduced = p1 - 1
q1=3136666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666313
q1_reduced = q1 - 1
# client public Key (N1,e1)
N1 = p1*q1
e1 = 7
N1_reduced = p1_reduced*q1_reduced
# client private Key d1
d1 = pow(e1, -1, N1_reduced)

# our encrypt function, takes a file as an input and produce a decrypted file
def encrypt_file(iv, input_file, output_file):
    # read the data from the input_file
    with open(input_file, "rb") as f:
        bytes_read = f.read()
    # encrypt the data and write it to the output_file
    with open(output_file, "wb") as f:
        # pad the data with AES.block_size (128 bytes)
        paded_bytes = pad(bytes_read,AES.block_size)
        # create a new AES_opject
        AES_opject = AES.new(KEY,AES.MODE_CBC,iv)
        # encrypt the paded data using .encrypt()
        cipher_text = AES_opject.encrypt(paded_bytes)
        f.write(cipher_text)
# our decrypt function, takes an encrypted file as an input and produce a decrypted file
def decrypt_file(iv, input_file, output_file):
    # read the encrypted data from the input_file
    with open(input_file, "rb") as f:
        bytes_read = f.read()
    # decrypt the data and write it to the output_file
    with open(output_file, "wb") as f:
        # create a new AES_opject
        AES_opject = AES.new(KEY,AES.MODE_CBC,iv)
        # decrypt the unpaded data using .decrypt()
        data_bytes = AES_opject.decrypt(bytes_read)
        # unpad the data with AES.block_size (128 bytes)
        unpaded_bytes = unpad(data_bytes,AES.block_size)
        f.write(unpaded_bytes)
# main function
if __name__ == '__main__':
    # the ip address or hostname of the server, the receiver
    host = input("What is the IP address of the server?\n")
    # the port, let's use 5001
    port = 5001
    # create the client socket
    s = socket.socket()
    print(f"[+] Connecting to {host}:{port}")
    s.connect((host, port))
    print("[+] Connected.")
    # a while loop to ensure the client is waiting for commands from user
    while True:
        # a flag to know whather we need to encrypt or not
        encrypt_flag = False
        # Get the type of the request from the user, PUT, GET, or QUIT
        request_type = input("What do you want to do?\n1.GET\n2.PUT\n3.QUIT\n")
        request_type = request_type.lower()
        # send the request_type to the server
        s.send(request_type.encode())
        if request_type=="quit":
            print("Quit!\n")
            # close the socket
            s.close()
            break
        elif request_type=="put":
            # let the user decide wether to encrypt the file or not
            encrypt_prompt = input("Do you want to encrypt the file? (y/n)")
            if encrypt_prompt == "y":
                encrypt_flag = True
            # send the encrypt flag
            s.send(f"{encrypt_flag}".encode())
            # the name of file we want to send, make sure it exists
            filename = input("Enter the name of the file you want to send:\n")
            opened_file = filename
            filesize = os.path.getsize(filename)
            if encrypt_flag:
                # genetrate the IV
                iv = get_random_bytes(16)
                # send the IV to the server
                s.send(iv)
                # enc.txt is a local intermediate file in the encryption process
                opened_file = "enc.txt"
                encrypt_file(iv, filename, opened_file)
                print(filename+ ' has been encrypted.')
            # send the filename and filesize
            s.send(f"{filename}{SEPARATOR}{filesize}".encode())
            print('Sending '+filename+' ...')
            # start sending the file
            with open(opened_file, "rb") as f:
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
            print(filename + " has been sent.\n")
        elif request_type=="get":
            # the name of file we want to send, make sure it exists
            filename = input("Enter the name of the file you want to receive:\n")
            # send the filename
            s.send(f"{filename}".encode())
            iv = s.recv(BUFFER_SIZE)
            print('receiveing '+filename+' ...')
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
            # let the user decide wether to decrypt the file or not
            decrypt_prompt = input("You have received an encrypted file. Do you want to decrypt it? (y/n)")
            if decrypt_prompt == "y":
                # start decrypting the received file 
                decrypt_file(iv, filename, filename)
                print(filename+ ' has been decrypted.')
        # in case we got a wrong request
        else:
            print("Wrong Input! Please enter one of the three commands, GET, PUT, or QUIT.\n")
    print("Done! Thank You!")

########################################
# References:
# for sending files via tcp client-server:
#     https://www.thepythoncode.com/article/send-receive-files-using-sockets-python
# for socket programming:
#     https://www.youtube.com/watch?v=3QiPPX-KeSc
# for AES encryption:
#     https://pycryptodome.readthedocs.io/en/latest/src/introduction.html
#     https://www.youtube.com/watch?v=KRA_scVTBp0
# online AES encryption tool:
#     https://cryptii.com/pipes/aes-encryption
########################################