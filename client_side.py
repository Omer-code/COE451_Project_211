import socket
import os
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes # a cryptographically secure random number generator method, that get sourced directly from the OS
from binascii import unhexlify
import hashlib

# define constants
# The symmetric 256 bits key, generated from my student ID hash value (used SHA-256)
KEY = unhexlify('46c5ae5c3023b4bda04f589346cb26830a7667943b9f55bf0d187da91ce40a1f')
SEPARATOR = "<SEPARATOR>"
BYTES_SEPARATOR = b'*-<SEPARATOR>-*'
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

# two prime large numbers p2,q2
p2=11111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111
q2=1357911131517193133353739515355575971737577799193959799111113115117119131133135137139151153155157159171173175177179191193195197199311313315317319331333335337339351353355357359371373375377379391393395397399511513515517519531533535537539551553555557559571573575577579591593595597599711713715717719731733735737739751753755757759771
# server public Key (N2,e2)
N2 = p2*q2
e2 = 17

# prime number m
m = int('0xFFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6955817183995497CEA956AE515D2261898FA051015728E5A8AACAA68FFFFFFFFFFFFFFFF',base=16)
# generator g
g = 2

H = hashlib.sha256()

def authenticate_bob(s):
        a =  int.from_bytes(os.urandom(256),'big')
        Ra = os.urandom(32)
        Ka = pow(g,a,m)
        print(Ka)
        Ka_bytes = str(Ka).encode()
        print(int(Ka_bytes.decode()))
        s.send(Ra+BYTES_SEPARATOR+Ka_bytes)
        print('Ra:')
        print(Ra)
        received = s.recv(2048)
        print(received)
        Rb, Kb, Sb = received.split(BYTES_SEPARATOR)
        Kb_bytes = Kb
        Kb = int(Kb)
        print('Kb:')
        print(Kb)
        print('Rb:')
        print(Rb)
        print('Sb:')
        print(Sb)
        Sb = int(Sb.decode())
        H.update(b'Alice')
        H.update(b'Bob')
        H.update(Ra)
        H.update(Rb)
        H.update(Ka_bytes)
        H.update(Kb_bytes)
        K = pow(Kb,a,m)
        print('K:')
        print(K)
        K_bytes = str(K).encode()
        H.update(K_bytes)
        print(H.digest())
        print(H.digest()+b'Bob')
        B = int.from_bytes(H.digest()+b'Bob','big')
        A = int.from_bytes(H.digest()+b'Alice','big')
        print(str(B).encode())
        Sa = pow(A,d1,N1) 
        H2 = pow(Sb,e2,N2)
        print(B)
        print(H2)
        if H2 == B:
            print('Good, this is Bob!')
        else:
            print('Bad, Trudyyyyyy!!!')
        a = 0

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
    authenticate_bob(s)
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