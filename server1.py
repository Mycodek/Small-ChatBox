import socket, threading

class ClientThread(threading.Thread):

    def __init__(self,clientAddress,clientsocket):
        threading.Thread.__init__(self)
        self.csocket = clientsocket
        self.username = ''
        print ("New connection added: ", clientAddress)

    def run(self):
        print ("Connection request from : ", clientAddress)
        #self.csocket.send(bytes("Hi, This is from Server..",'utf-8'))
        global name_s
        global name_r

        in_data =  self.csocket.recv(2048)


        if in_data.decode()[:16] == "REGISTER TOSEND " and in_data.decode()[-2:] == "\n\n":
            username = in_data.decode()[16:-2]
            self.username = username
            # found = False
            for tempname in name_s:
                if tempname.username == username:
                    self.csocket.send(bytes("ERROR 101 username taken\n\n",'UTF-8'))
                    print("ERROR 101 username ", username, " taken, connection closed")
                    return

            name_s.insert(0, self)
            print(self.username)
            print("REGISTERED TOSEND " + username)
            self.csocket.send(bytes("REGISTERED TOSEND " + username + "\n",'UTF-8'))
            while True:
                data = self.csocket.recv(2048)
                i = 0
                for temps in name_s:
                    print(i, " -> ", temps.username)
                    i += 1
                msg = data.decode()
                # if msg=='bye':
                  # break
                msgpart = msg.split('\n', 3)
                recvr_name = msgpart[0][5:]
                msg_len = int(msgpart[1][16:])
                msg_bdy = msgpart[3]

                if msg_len != len(bytes(msg_bdy,'UTF-8')):
                    print("Packet corrupted:expected bdy-> ", msg_len," actual -> ",len(bytes(msg_bdy,'UTF-8')))
                    self.csocket.send(bytes("Packet corrupted:expected bdy-> " + msg_len +" actual -> " + len(bytes(msg_bdy,'UTF-8')),'UTF-8'))
                    continue
                else:
                    print("Packet size good ->", msg_len)

                fd = False
                for skts in name_r:
                    if skts.username == recvr_name:
                        fd = True
                        print("username found")
                        msg_fwd = "FORWARD " + self.username + "\nContent-length: " + str(len(msg_bdy.encode('utf-8'))) + "\n\n" + msg_bdy
                        skts.csocket.send(bytes(msg_fwd, 'UTF-8'))
                        print(1)
                        ack = skts.csocket.recv(2048)
                        print(2)
                        print("Ack from reciever :", ack.decode())
                        if ack.decode() == "RECEIVED " + self.username + "\n\n":
                            self.csocket.send(bytes("SENT " + recvr_name + "\n\n", 'UTF-8'))
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


        if in_data.decode()[:16] == "REGISTER TORECV " and in_data.decode()[-2:] == "\n\n":
            username = in_data.decode()[16:-2]
            self.username = username
            for tempname in name_r:
                if tempname.username == username:
                    self.csocket.send(bytes("ERROR 101 username taken\n\n",'UTF-8'))
                    print("ERROR 101 username ", username, " taken, connection closed")
                    return

            name_r.insert(0, self)
            print("REGISTERED TORECV " + username)
            #name.insert(0,in_data.decode()[16:-2])
            self.csocket.send(bytes("REGISTERED TORECV " + username + "\n",'UTF-8'))
            i = 0
            for temps in name_r:
                print(i, " -> ", temps.username)
                i += 1
'''
        msg = ''
        while True:
            data = self.csocket.recv(2048)
            msg = data.decode()
            if msg=='bye':
              break
            print ("from client", msg)
            self.csocket.send(bytes(msg,'UTF-8'))
        print ("Client at ", clientAddress , " disconnected...")
'''
LOCALHOST = "127.0.0.1"
PORT = 8080
server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
server.bind((LOCALHOST, PORT))
name_s = []
name_r = []
print("Server started")
print("Waiting for client request..")
while True:
    server.listen(1)
    clientsock, clientAddress = server.accept()
    newthread = ClientThread(clientAddress, clientsock)
    newthread.start()
