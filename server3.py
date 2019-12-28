import socket, threading
import base64
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import dsa, rsa ,padding
from cryptography.hazmat.primitives import serialization ,hashes

global name_s
global name_r
global name_pk

class ClientThread(threading.Thread):

    def __init__(self,clientAddress,clientsocket):
        threading.Thread.__init__(self)
        self.csocket = clientsocket
        self.username = ''
        # self.public_key = b''
        print ("New connection added: ", clientAddress)

    def run(self):
        print ("Connection request from : ", clientAddress)
        #self.csocket.send(bytes("Hi, This is from Server..",'utf-8'))

        in_data =  self.csocket.recv(2048)
        # work start
        in_data = base64.b64decode(in_data)
        in_data = in_data.decode()
        # in_data = in_data.split('\n',2)
        if in_data[:16] == "REGISTER TOSEND " and in_data[-2:] == "\n\n":
            username = in_data[16:-2]
            self.username = username
            # found = False
            for tempname in name_s:
                if tempname.username == username:
                    self.csocket.send(bytes("ERROR 101 username taken\n\n",'UTF-8'))
                    # print("ERROR 101 username ", username, " taken, connection closed")
                    return

            name_s.insert(0, self)
            # print(self.username)
            print("REGISTERED TOSEND " + username)
            self.csocket.send(bytes("REGISTERED TOSEND " + username + "\n",'UTF-8'))
            while True:
                rcv = self.csocket.recv(2048)
                rcv = base64.b64decode(rcv)
                msg = rcv.decode()
                if msg=="" or msg =="UNREGISTER\n":
                    print("socket is closed for " , self.username)
                    self.csocket.send(bytes("UNREGISTERED User "+ username +"\n",'UTF-8'))
                    self.csocket.close()
                    return
                # print("msg is is : ",msg)
                if msg[:8] == "FETCHKEY":
                    rsvrName = msg[9:-1]
                    p_k = [item for item in name_pk if item[0] == rsvrName]
                    if len(p_k) == 0 :
                        self.csocket.send(bytes("RECVR NOT FOUND\n",'UTF-8'))
                        continue
                    # print(p_k[0])
                    publickey = p_k[0][1]
                    publickey = base64.b64encode(publickey)
                    # print("pk type ",type(publickey))
                    self.csocket.send(publickey)
                    continue
                
                msgpart = msg.split('\n', 3)
                recvr_name = msgpart[0][5:]
                msg_len = int(msgpart[1][16:])
                msg_bdy = msgpart[3]

                if msg_len != len(bytes(msg_bdy,'UTF-8')):
                    self.csocket.send(bytes("ERROR 103 Header incomplete\n\n",'UTF-8'))
                    continue
                # else:
                #     print("Packet size good ->", msg_len)
                
                fd = False
                for skts in name_r:
                    if skts.username == recvr_name:
                        fd = True
                        # print('msg bdy \n',msg_bdy)
                        msg_fwd = bytes("FORWARD " + self.username + "\nContent-length: " + str(len(msg_bdy.encode())) + "\n\n",'UTF-8') + msg_bdy.encode()
                        msg_fwd = base64.b64encode(msg_fwd)
                        skts.csocket.send(msg_fwd)
                        respond = skts.csocket.recv(1024)

                        if respond.decode()[:8] == "FETCHKEY":
                            p_k = [item for item in name_pk if item[0] == self.username]
                            if len(p_k) == 0 :
                                skts.csocket.send(bytes("sender's public key NOT FOUND\n",'UTF-8'))
                            elif len(p_k) != 0:
                                publickey = p_k[0][1]
                                publickey = base64.b64encode(publickey)
                                # print('public key \n',publickey)
                                skts.csocket.send(publickey)
                        elif respond.decode() =="ERROR 103 Header incomplete\n\n":
                            self.csocket.send(respond)
                        
                        ack = skts.csocket.recv(1024)
                        if ack.decode() == "RECEIVED " + self.username + "\n\n":
                            self.csocket.send(bytes("SENT " + recvr_name + "\n\n", 'UTF-8'))
                            break

                        elif ack.decode() == "SVP : incorrect sender's public key\n\n":
                            svrshow = self.username + "->" + recvr_name + " :: SVP : incorrect sender's public key\n"
                            print(svrshow)
                            self.csocket.send(bytes("ERROR 102 Unable to send\n", 'UTF-8'))
                            break

                        elif ack.decode() == "E:signature verification failed \n\n":
                            svrshow = self.username + "->" + recvr_name + " :: E:signature verification failed\n"
                            print(svrshow)
                            self.csocket.send(bytes("ERROR 102 Unable to send\n", 'UTF-8'))
                            break

                        else:
                            self.csocket.send(bytes("ERROR 102 Unable to send\n", 'UTF-8'))
                            break

                if fd:
                    continue

                print("ERROR 102 Unable to send (User not found)")
                self.csocket.send(bytes("ERROR 102 Unable to send\n",'UTF-8'))
                #print ("from client", msg)
                #self.csocket.send(bytes(msg,'UTF-8'))

            return

        #in_data =  self.csocket.recv(2048)


        if in_data[:16] == "REGISTER TORECV ":
            msg = in_data.split('\n',2)
            username = msg[0][16:]
            self.username = username
            for tempname in name_r:
                if tempname.username == username:
                    self.csocket.send(bytes("ERROR 101 username taken\n\n",'UTF-8'))
                    # print("ERROR 101 username ", username, " taken, connection closed")
                    return
            name_r.insert(0, self)
            name_pk.insert(0, (username,msg[2].encode()))

            print("REGISTERED TORECV " + username)
            #name.insert(0,in_data[16:-2])
            self.csocket.send(bytes("REGISTERED TORECV " + username + "\n",'UTF-8'))

LOCALHOST = "127.0.0.1"
PORT = 8087
server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
server.bind((LOCALHOST, PORT))
name_s = []
name_r = []
name_pk = []
print("Server started")
print("Waiting for client request..")
while True:
    server.listen(1)
    clientsock, clientAddress = server.accept()
    newthread = ClientThread(clientAddress, clientsock)
    newthread.start()