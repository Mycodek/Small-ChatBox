import socket, threading
import base64
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import dsa, rsa ,padding
from cryptography.hazmat.primitives import serialization ,hashes

global private_key
global public_key


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
                # print(out_data)
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
                recvr_msg = out_data[ind + 1: ]

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
                    # in_data = self.csock.recv(1024)
                    pemPublic = self.csock.recv(1024)
                    pemPublic = base64.b64decode(pemPublic)
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
                signature = private_key.sign(
                                ciphertext,
                                padding.PSS(
                                    mgf=padding.MGF1(hashes.SHA1()),
                                    salt_length=padding.PSS.MAX_LENGTH
                                ),
                                hashes.SHA1()
                            )
                # print('ciphertext \n',ciphertext)
                # print('signature \n',signature)                
                b64cipherSign = base64.b64encode(ciphertext) + '\n'.encode() + base64.b64encode(signature)
                b64combine = base64.b64encode(b64cipherSign)
                recvr_combine = bytes("SEND " + recvr_name + "\nContent-length: " + str(len(b64combine)) + "\n\n",'UTF-8') + b64combine
                base64_recvr_combine = base64.b64encode(recvr_combine)
                # self.csock.sendall(bytes("FETCHKEY TOSEND " + recvr_name + "\n\n",'UTF-8'))
                # publicKey =  self.csock.recv(1024)
                
                self.csock.sendall(base64_recvr_combine)
                in_data = self.csock.recv(1024)
                # print(in_data)
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
            print("Unknown error at sender side ",in_data[0])
            self.csock.close()
            return

class RecieveThread(threading.Thread):

    def __init__(self, recsocket, username):
        threading.Thread.__init__(self)
        #print("called")
        self.rsock = recsocket
        self.username = username
        # self.private_key = rsa.generate_private_key(
        #                         public_exponent=65537,
        #                         key_size=2048,
        #                         backend=default_backend()
        #                     )
        # self.public_key = self.private_key.public_key()
        #print("||username -> ", self.username)

    def run(self):
        #print("||Send message : REGISTER TORECV ")
        pemPublic = public_key.public_bytes(
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
                in_datar = self.rsock.recv(2048)
                # need works
                datar = base64.b64decode(in_datar)
                # msg_fwd = "FORWARD " + self.username + "\nContent-length: " + str(len(msg_bdy.encode('utf-8'))) + "\n\n" + msg_bdy
                msgr = datar.decode()
                msgrpart = msgr.split('\n', 3)
                sndr_name = msgrpart[0][8:]
                msgr_len = int(msgrpart[1][16:])
                msgr_bdy = msgrpart[3]
                msgr_decodedBody = base64.b64decode(msgr_bdy.encode())
                b64cip_n_b64sig = msgr_decodedBody.decode().split('\n')

                ciphertext = base64.b64decode(b64cip_n_b64sig[0].encode())
                # print('ciphertext \n',ciphertext)
                signature = base64.b64decode(b64cip_n_b64sig[1].encode())
                # print('signature \n',signature)

                if msgr_len != len(bytes(msgr_bdy,'UTF-8')):
                    # print("ERROR 103 Header incomplete\n")
                    self.rsock.sendall(bytes("ERROR 103 Header incomplete\n\n",'UTF-8'))
                    continue
                
                self.rsock.sendall(bytes("FETCHKEY " + sndr_name + "\n", 'UTF-8'))
                pemPublic = self.rsock.recv(2048)
                pemPublic = base64.b64decode(pemPublic)
                # print(pemPublic)
                # public key gets
                try:
                    spk = serialization.load_pem_public_key(pemPublic,backend=default_backend())
                except:
                    self.rsock.sendall(bytes("SVP : incorrect sender's public key\n\n",'UTF-8'))
                    # print("SVP : incorrect sender's public key")
                    continue
                
                try: 
                    spk.verify(
                            signature,
                            ciphertext,
                            padding.PSS(
                                    mgf=padding.MGF1(hashes.SHA1()),
                                    salt_length=padding.PSS.MAX_LENGTH
                                ),
                            hashes.SHA1()
                        )
                except:
                    # print("E:signature verification failed \n")
                    self.rsock.sendall(bytes("E:signature verification failed \n\n",'UTF-8'))
                    continue

                plaintext = private_key.decrypt(
                    ciphertext,
                    padding.OAEP(
                            mgf=padding.MGF1(algorithm=hashes.SHA256()),
                            algorithm=hashes.SHA256(),
                            label=None
                        )
                    )
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
            print("Unknown error at reciver side ",in_datar[0])            
            self.rsock.close()
            return

SERVER = "127.0.0.1"
PORT = 8087

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

private_key = rsa.generate_private_key(
                                public_exponent=65537,
                                key_size=2048,
                                backend=default_backend()
                            )
public_key = private_key.public_key()


sthread = SendThread(clients, username)
#print(clients, username)
sthread.start()

rthread = RecieveThread(clientr, username)
rthread.start()
