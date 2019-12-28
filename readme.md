## How to run
### Part 1
Part 1 belives that there isn't any kinda of privacy problem in network. So it doesn't provide any additional encoding to sending text.

to run server
```bash
python server1.py
```
to run client
```bash
python client1.py
```
Username for client is taken as input by user

### Part 2
Part 2 belives that there can be privacy issues with users. So it provides RSA encryption to sending text.

to run server
```bash
python server2.py
```
to run client
```bash
python client2.py
```
Username for client is taken as input by user

### Part 3
Part 3 belives that same as part 2 but it also provide signature of sender to a sending text so that reciver can cross verify.

to run server
```bash
python server3.py
```
to run client
```bash
python client3.py
```
Username for client is taken as input by user
