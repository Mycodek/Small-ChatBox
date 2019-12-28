import socket, threading

class SendThread(threading.Thread):

    def __init__(self, sendsocket, username):
        threading.Thread.__init__(self)
        #print("called")
        self.csock = sendsocket
        self.username = username
        #print("username -> ", self.username)

    def run(self):
        #print("Send message : REGISTER TOSEND ")
        self.csock.sendall(bytes("REGISTER TOSEND " + username + "\n\n",'UTF-8'))
        in_data =  self.csock.recv(1024)
        if in_data.decode() == "REGISTERED TOSEND " + username + "\n":
            print("Send connection established")

            while True:
                out_data = input(">>")
                if len(out_data) == 0:
                    print("Write something")
                    continue

                if out_data[0] != '@':
                    print("Insert @username at starting ")
                    continue

                loc = -1
                ind = 0
                for chr in out_data:
                    if chr == ':':
                        loc = ind
                        break
                    ind += 1

                if loc == -1 or loc == 1:
                    print("No reciever found")
                    continue

                recvr_name = out_data[1: loc]
                recvr_msg = out_data[loc + 1: ]

                recvr_combine = "SEND " + recvr_name + "\nContent-length: " + str(len(recvr_msg.encode('utf-8'))) + "\n\n" + recvr_msg

                self.csock.sendall(bytes(recvr_combine, 'UTF-8'))
                in_data = self.csock.recv(1024)
                print("From Server :" ,in_data.decode())
                # if out_data=='bye':
                    # break

        elif in_data.decode() == "ERROR 100 Malformed username\n\n":
            print("Change username")
            self.csock.close()
            return

        elif in_data.decode() == "ERROR 101 username taken\n\n":
            print("ERROR 101 username taken")
            self.csock.close()
            return

        else:
            print("Unknown error")
            self.csock.close()
            return

class RecieveThread(threading.Thread):

    def __init__(self, recsocket, username):
        threading.Thread.__init__(self)
        #print("called")
        self.rsock = recsocket
        self.username = username
        #print("||username -> ", self.username)

    def run(self):
        #print("||Send message : REGISTER TORECV ")
        self.rsock.sendall(bytes("REGISTER TORECV " + username + "\n\n",'UTF-8'))
        in_datar =  self.rsock.recv(1024)
        #print("||-> ", in_datar.decode())
        if in_datar.decode() == "REGISTERED TORECV " + username + "\n":
            print("Recieve connection established")

            while True:
                in_datar = self.rsock.recv(1024)
                msgr = in_datar.decode()
                msgrpart = msgr.split('\n', 3)
                sndr_name = msgrpart[0][8:]
                msgr_len = int(msgrpart[1][16:])
                msgr_bdy = msgrpart[3]

                if msgr_len != len(bytes(msgr_bdy,'UTF-8')):
                    print("Packet corrupted:expected bdy-> ", msgr_len," actual -> ",len(bytes(msgr_bdy,'UTF-8')))
                    self.rsock.sendall(bytes("ERROR 103 Header incomplete\n\n",'UTF-8'))
                    continue
                else:
                    print("Packet size good ->", msgr_len)

                print("#",sndr_name,":",msgr_bdy)
                self.rsock.sendall(bytes("RECEIVED " + sndr_name + "\n\n", 'UTF-8'))



        elif in_datar.decode() == "ERROR 100 Malformed username\n\n":
            print("Change username")
            self.rsock.close()
            return

        elif in_datar.decode() == "ERROR 101 username taken\n\n":
            print("ERROR 101 username taken")
            self.rsock.close()
            return

        else:
            print("Unknown error")
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
