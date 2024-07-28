
from mininet.topo import Topo
from mininet.net import Mininet
from mininet.node import Switch
from mininet.cli import CLI
from mininet.node import RemoteController
from mininet.node import OVSSwitch
from topology import *
import testing
import subprocess



topos = {'mytopo': (lambda: MyTopo())}


def run_tests(net):
    # You can automate some tests here

    # Get the hosts
    h1 = net.get('h1')
    h2 = net.get('h2')
    h3 = net.get('h3')
    h4 = net.get('h4')
    ws1 = net.get('ws1')
    ws2 = net.get('ws2')
    ws3 = net.get('ws3')

    # Define the hosts
    hosts = [h1, h2, h3, h4, ws1, ws2, ws3]

    # Create a dictionary to map hosts to numbers
    host_to_number = {host: i for i, host in enumerate(hosts)}

    hosts_str = ['  h1:  ', '  h2:  ', '  h3:  ', '  h4:  ', '  ws1: ', '  ws2: ', '  ws3: ']

    # Launch some tests

    # Ping tables for each host, order is h1, h2, h3, h4, ws1, ws2, ws3, and the missing index is always the host itself
    ping_table_h1 = [True, False, False, False, False, False]
    ping_table_h2 = [True, False, False, False, False, False]
    ping_table_h3 = [True, True, True, False, False, False]
    ping_table_h4 = [True, True, True, False, False, False]
    ping_table_ws1 = [False, False, False, False, True, True]
    ping_table_ws2 = [False, False, False, False, True, True]
    ping_table_ws3 = [False, False, False, False, True, True]

    ping_tables = {
    h1: ping_table_h1,
    h2: ping_table_h2,
    h3: ping_table_h3,
    h4: ping_table_h4
    }
    
    lb_hosts = [h1, h2, h3, h4]
    ping_table_lb = [True, True, True, True]

    # Curl tables for each host, order is h1, h2, h3, h4, ws1, ws2, ws3, and the missing index is always the host itself
    curl_table_h1 = [False, False, False, True, True, True]
    curl_table_h2 = [False, False, False, True, True, True]
    curl_table_h3 = [False, False, False, True, True, True]
    curl_table_h4 = [False, False, False, True, True, True]

    curl_tables = {
    h1: curl_table_h1,
    h2: curl_table_h2,
    h3: curl_table_h3,
    h4: curl_table_h4
    }

    # Ping and curl matrix initialization

    matrix_size = 8
    ping_matrix = [[0 for i in range(matrix_size)] for j in range(matrix_size)]
    curl_matrix = [[0 for i in range(matrix_size)] for j in range(matrix_size)]

    # Generate the matrix
    for i in range (0, matrix_size):
        for j in range (0, matrix_size):
            if i == j:
                ping_matrix[i][j] = "   -   "
                curl_matrix[i][j] = "   -   "
            elif i==0:
                ping_matrix[i][j] = hosts_str[j-1]
                curl_matrix[i][j] = hosts_str[j-1]
            elif j==0:
                ping_matrix[i][j] = hosts_str[i-1]
                curl_matrix[i][j] = hosts_str[i-1]
            else:
                ping_matrix[i][j] = "  n/a  "
                curl_matrix[i][j] = "  n/a  "

    # Function to run ping tests for a given host
    def run_ping_tests(host):
        print(f"********** Tests results, pings from {host} (Passed means the expected behaviour is happening): \n")
        ping_results = []
        hosts_str = ['h1', 'h2', 'h3', 'h4', 'ws1', 'ws2', 'ws3']
        current_target = [h1, h2, h3, h4, ws1, ws2, ws3]
        current_target.pop(host_to_number[host])
        hosts_str.pop(host_to_number[host]) 
        for i, dest_host in enumerate(current_target):
            if host != dest_host: 
                ping_results.append(testing.ping(host, dest_host, ping_table[i]))
        for i, result in enumerate(ping_results):
            print(f"Test {host} ping {hosts_str[i]}: {'Passed' if result else 'Failed'}")
            traffic_allowed = "  n/a  "
            index = i+1 if i<host_to_number[host] else i+2
            if ping_table[i] and result:
                traffic_allowed = "Allowed"
            elif result and not ping_table[i]:
                traffic_allowed = "Blocked"
            ping_matrix[host_to_number[host]+1][index] = traffic_allowed
        print()

    # Run ping tests for each host
    for host, ping_table in ping_tables.items():
        run_ping_tests(host)

    # Function to run curl tests for a given host
    def run_curl_tests(host):
        print(f"********** Tests results, curls from {host} (Passed means the expected behaviour is happening): \n")
        curl_results = []
        hosts_str = ['h1', 'h2', 'h3', 'h4', 'ws1', 'ws2', 'ws3']
        current_target = [h1, h2, h3, h4, ws1, ws2, ws3]
        current_target.pop(host_to_number[host])
        hosts_str.pop(host_to_number[host]) 
        for i, dest_host in enumerate(current_target):
            if host != dest_host: 
                curl_results.append(testing.curl(host, "100.0.0.45", expected=curl_table[i]))
        for i, result in enumerate(curl_results):
            print(f"Test {host} curl {hosts_str[i]}: {'Passed' if result else 'Failed'}")
            traffic_allowed = "  n/a  "
            index = i+1 if i<host_to_number[host] else i+2
            if curl_table[i] and result:
                traffic_allowed = "Allowed"
            elif result and not curl_table[i]:
                traffic_allowed = "Blocked"
            curl_matrix[host_to_number[host]+1][index] = traffic_allowed
        print()

    # Run curl tests for each host
    for host, curl_table in curl_tables.items():
        run_curl_tests(host)
    
    print("********** Tests results, ping to virtual IP: 100.0.0.45")
    lb_hosts = [h1, h2, h3, h4]
    ping_table_lb = [True, True, True, True]
    lb_result = []
    
    for i, client in enumerate(lb_hosts):
        lb_result.append(testing.ping(client, "100.0.0.45", ping_table_lb[i]))
        
    for i, result in enumerate(lb_result):
        if result == lb_result[i]:
            print(f"Test {lb_hosts[i]} ping 100.0.0.45: {'Passed' if result else 'Failed'}")
    
    print("\n")
            
    # Print the ping matrix
    print("Ping matrix (read first column host can/cannot contact the other column hosts, n/a means untested behaviour or uncorrect behaviour): ")
    for row in ping_matrix:
        print(row)
    
    print("\n")

    # Print the curl matrix
    print("Curl matrix (read first column host can/cannot contact the other column hosts, n/a means untested behaviour or uncorrect behaviour): ")
    for row in curl_matrix:
        print(row)
    
    print("\n")
    

    def ids_curl_tests(host):
        http_methods = ['GET', 'POST', 'PUT', 'DELETE','TRACE', 'OPTIONS', 'CONNECT', 'HEAD']
        put_payload = ['cat /etc/passwd', 'cat /var/log/', 'UPDATE','INSERT','DELETE']
        http_expected = [False, True,True,False,False,False,False,False]
        put_expected = [False, False, False, False, False]
        for i, method in enumerate(http_methods):
            result = testing.curl_ids(host, ws1, method, "", 80, http_expected[i])
            print(f"Test {host} curl {ws1} with method {method}: {'Passed' if result else 'Failed'}")
        for i, payload in enumerate(put_payload):
            result = testing.curl_ids(host, ws1, "PUT", payload, 80, put_expected[i])
            print(f"Test {host} curl {ws1} with payload {payload}: {'Passed' if result else 'Failed'}")
    
    ids_curl_tests(h1)

        

topos = {'mytopo': (lambda: MyTopo())}

if __name__ == "__main__":
    # Create topology
    topo = MyTopo()
    ctrl = RemoteController("c0", ip="127.0.0.1", port=6633)

    # Create the network
    net = Mininet(topo=topo,
                  switch=OVSSwitch,
                  controller=ctrl,
                  autoSetMacs=True,
                  autoStaticArp=True,
                  build=True,
                  cleanup=True)

    startup_services(net)
    # Start the network

    # Needed to set the default gateway for the private hosts
    net.get("h3").cmd("ip route add default via 10.0.0.1")
    net.get("h4").cmd("ip route add default via 10.0.0.1")

    net.start()
    # Run all the tests

    run_tests(net)

    subprocess.check_output("sudo killall -SIGTERM click || true", shell=True)

    
    # You may need some commands before stopping the network! If you don't, leave it empty
    
    ### COMPLETE THIS PART ###
        
    net.stop()
