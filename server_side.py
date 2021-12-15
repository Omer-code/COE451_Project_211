import socket
import os
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes # a cryptographically secure random number generator method, that get sourced directly from the OS
from binascii import unhexlify, hexlify
import hashlib


# define constants
KEY = ''
# device's IP address
SERVER_HOST = socket.gethostbyname(socket.gethostname())
SERVER_PORT = 5001
# receive 4096 bytes each time
BUFFER_SIZE = 4096
SEPARATOR = "<SEPARATOR>"
BYTES_SEPARATOR = b'*-<SEPARATOR>-*'

# two prime large numbers p2,q2
p2=11111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111
p2_reduced = p2 - 1
q2=1357911131517193133353739515355575971737577799193959799111113115117119131133135137139151153155157159171173175177179191193195197199311313315317319331333335337339351353355357359371373375377379391393395397399511513515517519531533535537539551553555557559571573575577579591593595597599711713715717719731733735737739751753755757759771
q2_reduced = q2 - 1
# server public Key (N2,e2)
N2 = p2*q2
N2_reduced = q2_reduced*p2_reduced
e2 = 17
# server's (Bob) private Key d2
d2 = pow(e2, -1, N2_reduced)
# Test case 2:
#d2 = pow(e2, -1, N2_reduced+10)


# client's (Alice) public Key (N1,e1)
N1 = 9817766666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666670379887169999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999874799999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999581325509666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666555969
e1 = 7
# prime number m from 2048-bit MODP Group
m = int('0xFFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6955817183995497CEA956AE515D2261898FA051015728E5A8AACAA68FFFFFFFFFFFFFFFF',base=16)
# generator g
g = 2

# hash object for H
H = hashlib.sha256()
# the hash object for H_K
H_K = hashlib.sha256()

def authenticate_alice(conn):
    # generate random exponent b
    b =  int.from_bytes(os.urandom(256),'big')
    print('b: ',b)
    # generate random number Rb
    Rb =  os.urandom(32)
    # compute g^b mod m
    Kb = pow(g,b,m)
    # convert to bytes
    Kb_bytes = str(Kb).encode()
    # recivce Ra, Ka from Alice
    received = conn.recv(2048)
    Ra, Ka = received.split(BYTES_SEPARATOR)
    Ka_bytes = Ka
    Ka = int(Ka.decode())
    # compute the hash of ('Alice', 'Bob', Ra, Rb, Ka, Kb, K)
    H.update(b'Alice')
    H.update(b'Bob')
    H.update(Ra)
    print('Ra: ',Ra)
    print('Rb: ',Rb)
    H.update(Rb)
    H.update(Ka_bytes)
    H.update(Kb_bytes)
    # campute the session key K (g^ba mod m)
    K = pow(Ka,b,m)
    print('K as number: ',K)
    # convert to bytes
    K_bytes = str(K).encode()
    print('K as bytes: ',K_bytes)
    # compute the hash of session key
    H_K.update(K_bytes)
    Hashed_key = H_K.digest()
    H.update(K_bytes)
    # get the int value of the hash
    B = int.from_bytes(H.digest()+b'Bob','big')
    A = int.from_bytes(H.digest()+b'Alice','big')
    # sign the hash with Bob's private key
    Sb = pow(B,d2,N2)
    # convert to bytes
    Sb_bytes = str(Sb).encode()
    # send Rb, Kb and the signature 
    conn.send(Rb+BYTES_SEPARATOR+Kb_bytes+BYTES_SEPARATOR+Sb_bytes)
    # delete the private key for PFS
    b = 0 
    # recivce the ecncrypted Sa and 'Alice' from Alice
    received = conn.recv(2048)
    iv, bytes_read = received.split(BYTES_SEPARATOR)
    print('IV: ',iv)
    AES_opject = AES.new(Hashed_key,AES.MODE_CBC,iv)
    # decryprt the message with the session key (Hashed_key)
    data_bytes = AES_opject.decrypt(bytes_read)
    unpaded_bytes = unpad(data_bytes,AES.block_size)
    l,Sa = unpaded_bytes.split(b'Alice')
    Sa = int(Sa.decode())
    # decrypt the Sa (signature) to get the hash 
    H2 = pow(Sa,e1,N1)
    # check for Alice
    if H2 == A:
        return True
    else:
        return False


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
    print('Authenticating Client...')
    if authenticate_alice(client_socket):
            print('Good, this is Alice!')
            KEY = H_K.digest()
    else:
        print('Game over pal, Trudyyyyyyyyyyyyyyyyyy')
        request_type = "quit"
        print("Quit!")
        # close the client socket
        client_socket.close()
        # close the server socket
        s.close()
        exit()
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

    

