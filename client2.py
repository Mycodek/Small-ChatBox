import socket, threading
import base64
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import dsa, rsa ,padding
from cryptography.hazmat.primitives import serialization ,hashes

class SendThread(threading.Thread):

    def __init__(self, sendsocket, username):
        threading.Thread.__init__(self)
        #print("called")
        self.csock = sendsocket
        self.username = username
        self.pks = []
        #print("username -> ", self.username)

    def run(self):
        #print("Send message : REGISTER TOSEND ")
        regMsg = bytes("REGISTER TOSEND " + self.username + "\n\n",'UTF-8')
        
        b64registerMsg = base64.b64encode(regMsg)
        self.csock.sendall(b64registerMsg)
        
        in_data =  self.csock.recv(1024)

        if in_data.decode() == "REGISTERED TOSEND " + self.username + "\n":
            print("REGISTERED TOSEND " + self.username) 

            while True:
                out_data = input(">>") #row_input
                if len(out_data) == 0:
                    print("Write something")
                    continue
                print(out_data)
                if out_data=='UNREGISTER':
                    msg = bytes(out_data+"\n",'UTF-8')
                    msgb64 = base64.b64encode(msg)
                    self.csock.sendall(msgb64)
                    rply = self.csock.recv(1024).decode()
                    print(rply)
                    return

                if out_data[0] != '@':
                    print("Insert @username at starting ")
                    continue

                ind = out_data.find(':')

                if ind == -1:
                    print("reciever name improper")
                    continue
                
                recvr_name = out_data[1: ind]
                recvr_msg = out_data[ind + 1:]

                # send msg to server for getting rcvr public key
                check = -1
                for entry in self.pks:
                    if entry[0] == recvr_name:
                        pk = entry[1]
                        check = 1
                if check == -1:
                    pkrequest = "FETCHKEY " + recvr_name + "\n"
                    pkrequest = bytes(pkrequest, 'UTF-8')
                    b64pkrequest = base64.b64encode(pkrequest)
                    self.csock.sendall(b64pkrequest)
                    pemPublic = self.csock.recv(1024)
                    # print("pemPublic \n",pemPublic)
                    pemPublic = base64.b64decode(pemPublic)
                    if pemPublic.decode() == "RECVR NOT FOUND\n":
                        print(pemPublic.decode())
                        continue
                    # somehow pemPublic find
                    try:
                        pk = serialization.load_pem_public_key(pemPublic,backend=default_backend())
                        self.pks.append((recvr_name,pk))
                    except:
                        print("reciver's public key is not valid")
                        continue
                
                try:    
                    ciphertext = pk.encrypt(
                                recvr_msg.encode(),
                                padding.OAEP(
                                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                                        algorithm=hashes.SHA256(),
                                        label=None
                                    )
                                )
                except:
                    print("data is too large to send please send in chunks")
                    continue

                b64ciphertext = base64.b64encode(ciphertext)
                recvr_combine = bytes("SEND " + recvr_name + "\nContent-length: " + str(len(b64ciphertext)) + "\n\n",'UTF-8') + b64ciphertext
                base64_recvr_combine = base64.b64encode(recvr_combine)
                # self.csock.sendall(bytes("FETCHKEY TOSEND " + recvr_name + "\n\n",'UTF-8'))
                # publicKey =  self.csock.recv(1024)
                
                self.csock.sendall(base64_recvr_combine)
                in_data = self.csock.recv(1024)
                in_data = in_data.decode().split('\n')
                print(in_data[0])
                # if out_data=='bye':
                    # break

        elif in_data.decode() == "ERROR 100 Malformed username\n\n":
            print("ERROR 100 Malformed username")
            self.csock.close()
            return

        elif in_data.decode() == "ERROR 101 No user registered\n\n":
            print("ERROR 101 No user registered")
            self.csock.close()
            return
            
        else:
            in_data = in_data.decode().split('\n')
            print("Unknown error at sender server response ",in_data[0])
            self.csock.close()
            return

class RecieveThread(threading.Thread):

    def __init__(self, recsocket, username):
        threading.Thread.__init__(self)
        #print("called")
        self.rsock = recsocket
        self.username = username
        self.private_key = rsa.generate_private_key(
                                public_exponent=65537,
                                key_size=2048,
                                backend=default_backend()
                            )
        self.public_key = self.private_key.public_key()
        #print("||username -> ", self.username)

    def run(self):
        #print("||Send message : REGISTER TORECV ")
        pemPublic = self.public_key.public_bytes(
                        encoding=serialization.Encoding.PEM,
                        format=serialization.PublicFormat.SubjectPublicKeyInfo
                    )
        regMsg = bytes("REGISTER TORECV " + username + "\n\n",'UTF-8') + pemPublic
        b64registerMsg = base64.b64encode(regMsg)
        self.rsock.sendall(b64registerMsg)

        in_datar =  self.rsock.recv(1024)
        #print("||-> ", in_datar.decode())
        if in_datar.decode() == "REGISTERED TORECV " + self.username + "\n":
            print("REGISTERED TORECV " + self.username)

            while True:
                in_datar = self.rsock.recv(1024)
                # need works
                datar = base64.b64decode(in_datar)
                        # msg_fwd = "FORWARD " + self.username + "\nContent-length: " + str(len(msg_bdy.encode('utf-8'))) + "\n\n" + msg_bdy
                msgr = datar.decode()
                # print(msgr)
                msgrpart = msgr.split('\n', 3)
                sndr_name = msgrpart[0][8:]
                msgr_len = int(msgrpart[1][16:])
                msgr_bdy = msgrpart[3]


                # why not comparing decoded length why comparing with bytes**
                if msgr_len != len(bytes(msgr_bdy,'UTF-8')):
                    print("Packet corrupted:expected bdy-> ", msgr_len," actual -> ",len(bytes(msgr_bdy,'UTF-8')))
                    self.rsock.sendall(bytes("ERROR 103 Header incomplete\n\n",'UTF-8'))
                    continue

                ciphertext = base64.b64decode(msgr_bdy.encode())
                try:
                    plaintext = self.private_key.decrypt(
                        ciphertext,
                        padding.OAEP(
                                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                                algorithm=hashes.SHA256(),
                                label=None
                            )
                        )
                except:
                    self.rsock.sendall(bytes("ERROR In decryption " + sndr_name + "\n\n", 'UTF-8'))
                plaintext = plaintext.decode()
                print("#",sndr_name,":",plaintext)
                self.rsock.sendall(bytes("RECEIVED " + sndr_name + "\n\n", 'UTF-8'))

        elif in_datar.decode() == "ERROR 100 Malformed username\n\n":
            print("ERROR 100 Malformed username")
            self.rsock.close()
            return

        elif in_datar.decode() == "ERROR 101 No user registered\n\n":
            print("ERROR 101 No user registered")
            self.rsock.close()
            return

        else:
            in_datar = in_datar.decode().split('\n')
            print("Unknown error at sender server response ",in_datar[0])            
            self.rsock.close()
            return

SERVER = "127.0.0.1"
PORT = 8080

while True:
    username = input("Enter your username: ")
    if username.isalnum() == False:
        print("Illegal username. Please re-enter : ")
        continue
    else:
        break

clients = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
clients.connect((SERVER, PORT))

clientr = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
clientr.connect((SERVER, PORT))


sthread = SendThread(clients, username)
#print(clients, username)
sthread.start()

rthread = RecieveThread(clientr, username)
rthread.start()
