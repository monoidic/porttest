# porttest

This is a tool for testing for and identifying blocked TCP/UDP ports between a client and a server (e.g a corporate firewall between the two hosts). For this, it attempts to send packets on all TCP and UDP ports to the target IP. After exhausting the port list, it will retry any ports that failed to connect (e.g due to random connectivity issues) until the number of ports does not decrease.

 `cap_net_admin` and `cap_net_raw` capabilities are required on the server.

To use it, you need to run the server utility on the server being tested (elevated privileges required) and the client utility on the client.

Explicit support is given for sending control messages between the server and client on a different IP on the same host (e.g unblocked VPN / ssh-tunneled TCP) than the one being tested (e.g global IP).

## Server
```sh
./server -ip 10.240.5.5:57005 -netif eth0
```
The server binds to an IP:port on which it listens for control messages from the client, and a network device on which to watch for packets after a client connects.

## Client
```sh
./client -server_ip 10.246.5.5:57005 -src_ip $(curl -4s https://icanhazip.com) -target_ip $(dig +short A example.com) -result_name example
```
The client has to specify its source IP for connection attempts and the target IP to send connection attempts to. The server IP:port to send control messages to should also be specified, though it defaults to port 57005 on the target IP.

Results will be saved to `results/${result_name}.txt`, with the default `result_name` of `result`.

## Warning

Do not run this service without proper access control on the control port via firewalling and/or only having the control message port listen on a secure VPN connection, as it can otherwise lead to information leaks.