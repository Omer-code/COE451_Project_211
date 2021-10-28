import socket
import os
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes # a cryptographically secure random number generator method, that get sourced directly from the OS
from binascii import unhexlify, hexlify 

# define constants
# The symmetric 256 bits key, generated from my student ID hash value (used SHA-256)
KEY = unhexlify('46c5ae5c3023b4bda04f589346cb26830a7667943b9f55bf0d187da91ce40a1f')
print('Key: ')
print(KEY)
# device's IP address
SERVER_HOST = socket.gethostbyname(socket.gethostname())
SERVER_PORT = 5001
# receive 4096 bytes each time
BUFFER_SIZE = 4096
SEPARATOR = "<SEPARATOR>"

# our encrypt function, takes a file as an input and produce a decrypted file
def encrypt_file(iv, input_file, output_file):
    # read the data from the input_file
    with open(input_file, "rb") as f:
        bytes_read = f.read()
        print('P: ')
        print(hexlify(bytes_read))
    # encrypt the data and write it to the output_file
    with open(output_file, "wb") as f:
        # pad the data with AES.block_size (128 bytes)
        paded_bytes = pad(bytes_read,AES.block_size)
        # create a new AES_opject
        AES_opject = AES.new(KEY,AES.MODE_CBC,iv)
        # encrypt the paded data using .encrypt()
        cipher_text = AES_opject.encrypt(paded_bytes)
        # print the cipher in hex
        print('C: ')
        print(hexlify(cipher_text))
        f.write(cipher_text)
# our decrypt function, takes an encrypted file as an input and produce a decrypted file
def decrypt_file(iv, input_file, output_file):
    # read the encrypted data from the input_file
    with open(input_file, "rb") as f:
        bytes_read = f.read()
        print('C: ')
        print(hexlify(bytes_read))
    # decrypt the data and write it to the output_file
    with open(output_file, "wb") as f:
        # create a new AES_opject
        AES_opject = AES.new(KEY,AES.MODE_CBC,iv)
        # decrypt the unpaded data using .decrypt()
        data_bytes = AES_opject.decrypt(bytes_read)
        # unpad the data with AES.block_size (128 bytes)
        unpaded_bytes = unpad(data_bytes,AES.block_size)
        # print the original data in hex
        print('P: ')
        print(hexlify(unpaded_bytes))
        f.write(unpaded_bytes)

# main function
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
        # a flag to know whather we need to decrypt or not
        decrypt_flag = False
        # receive the request type, PUT, GET or QUIT
        request_type = client_socket.recv(BUFFER_SIZE).decode()
        # print the request
        print('REQUEST: ')
        print(request_type)
        # quit from the server side
        if request_type == "quit":
            print("Quit!")
            # close the client socket
            client_socket.close()
            # close the server socket
            s.close()
            break
        # print the request type
        elif request_type=="put":
            # receive the encrypt_flag
            encrypt_flag = client_socket.recv(BUFFER_SIZE).decode()
            print('encrypt flag: ')
            print(encrypt_flag)
            if encrypt_flag == "True":
                iv = client_socket.recv(BUFFER_SIZE)
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
                        # print the data to check
                        print(bytes_read)
                        break
                    if not bytes_read:    
                        # nothing is received
                        # file transmitting is done
                        break
                    # write to the file the bytes we just received
                    f.write(bytes_read)
            if decrypt_flag:
                # let the user decide whether to decrypt the file or not
                encrypt_prompt = input("You have received an encrypted file. Do you want to decrypt it? (y/n)")
                if encrypt_prompt =="y":
                    print('IV: ')
                    print(hexlify(iv))
                    decrypt_file(iv, filename, filename)
        elif request_type=="get":
            # receive the filename of the file you want to get
            filename = client_socket.recv(BUFFER_SIZE).decode()
            # start sending the file
            # enc.txt is an intermediate file in the encryption process 
            opened_file = 'enc.txt'
            # genetrate the IV
            iv = get_random_bytes(16)
            print('IV: ')
            print(hexlify(iv))
            # send the IV to the client
            client_socket.send(iv)
            # start encrypting
            encrypt_file(iv, filename, opened_file)
            # read the encrypted file and sent it
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
        else:
            # close the client socket
            client_socket.close()
            # close the server socket
            s.close()
            break
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

    

