# iperf
Used to measure the maximum network throughput between us and a server.
## 1.1 TCP CLIENT AND SERVER
server:

    iperf -s
client:

    iperf -c iperf_server_ip_address -p port_number

## 1.2 UDP CLIENT AND SERVER
server:

    iperf -s -u
client: 

    iperf -c iperf_server_ip_address -u
    
