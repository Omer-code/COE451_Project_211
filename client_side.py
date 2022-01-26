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
# (p1-1)(q1-1)
N1_reduced = p1_reduced*q1_reduced
# client private Key d1
d1 = pow(e1, -1, N1_reduced)
# Test case 3:
#d1 = pow(44, 66, 555)
# server public Key (N2,e2)
N2 = 15087901461302145926152661281728621908195308879932886656790145723523545901479279301546123923946190657457479724190879902146613302214570147947970214792592614859326126148392859548570815281970882126593282193327905705727972439239261505972661683928395083995239706395306439906595506639996796819063530219241485952641552797263801984982842534096294028942738269336473602466756226688987654098320320096540762762540094316316093648980980758313646756534089422533409854076075853407629629406962294294071626960069847402735846734289622733622276498498275831163162940495828938716271604715603158491602491156489600489155587587364920253363140696029140027582916026915581
e2 = 17
# prime number m from 2048-bit MODP Group
m = int('0xFFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6955817183995497CEA956AE515D2261898FA051015728E5A8AACAA68FFFFFFFFFFFFFFFF',base=16)
# generator g
g = 2
 
# the hash object for H
H = hashlib.sha256()
# the hash object for H_K
H_K = hashlib.sha256()
 
def authenticate_bob(s):
        # generate random exponent a
        a =  int.from_bytes(os.urandom(256),'big')
        # generate random number Ra
        Ra = os.urandom(32)
        # compute g^a mod m
        Ka = pow(g,a,m)
        # convert to bytes
        Ka_bytes = str(Ka).encode()
        # send Ra, Ka to Bob
        s.send(Ra+BYTES_SEPARATOR+Ka_bytes)
        # recivce Rb, Kb, Sb (signature) from Bob
        received = s.recv(2048)
        Rb, Kb, Sb = received.split(BYTES_SEPARATOR)
        Kb_bytes = Kb
        Kb = int(Kb)
        Sb_bytes = Sb
        # convert from bytes to int
        Sb = int(Sb_bytes.decode())
        # compute the hash of ('Alice', 'Bob', Ra, Rb, Ka, Kb, K)
        H.update(b'Alice')
        H.update(b'Bob')
        H.update(Ra)
        H.update(Rb)
        H.update(Ka_bytes)
        H.update(Kb_bytes)
        # campute the session key K (g^ab mod m)
        K = pow(Kb,a,m)
        K_bytes = str(K).encode()
        # compute the hash of session key
        H_K.update(K_bytes)
        Hashed_key = H_K.digest()
        H.update(K_bytes)
        # get the int value of the hash
        B = int.from_bytes(H.digest()+b'Bob','big')
        A = int.from_bytes(H.digest()+b'Alice','big')
        Sa = pow(A,d1,N1)
        Sa_bytes = str(Sa).encode()
        # decrypt the Sb (signature) to get the hash 
        H2 = pow(Sb,e2,N2)
        # delete the private key for PFS
        a = 0
        # check for Bob
        if H2 == B:
            bytes_read = b'Alice'+Sa_bytes
            paded_bytes = pad(bytes_read,AES.block_size)
            iv = os.urandom(16)
            # encryprt with the session key (Hashed_key)
            AES_opject = AES.new(Hashed_key,AES.MODE_CBC,iv)
            cipher_text = AES_opject.encrypt(paded_bytes)
            # send the ecncrypted Sa and 'Alice' to Bob
            s.send(iv+BYTES_SEPARATOR+cipher_text)
            return True
        else:
            # send random bytes to Trudy
            s.send(os.urandom(16)+BYTES_SEPARATOR+os.urandom(64))
            return False
      
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
    print('Authenticating Server...')
    if authenticate_bob(s):
        print('Good, this is Bob!')
        KEY = H_K.digest()
    else:
        print('Baaaaaad, Trudyyyyyy!!!')
        request_type = "quit"
        print("Quit!\n")
        # close the socket
        s.close()
        exit()
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
 
 
 
