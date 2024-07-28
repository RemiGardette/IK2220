import topology
from time import sleep

def ping(client, server, expected, count=1, wait=1):
    
    if (isinstance(server, str) == 0):
            server_ip = str(server.IP())
    else:
            # If it's a string it should be the IP address of the node (e.g., the load balancer)
            server_ip = server
    
    cmd = f"ping {server_ip} -c {count} >/dev/null 2>&1; echo $?"
    print(f"`{cmd}` on {client} to {server} with expected={expected}")
    # 0 is successful, 1 is unsuccessful, 2 is incorrect usage
    ret = client.cmd(cmd)
    # return true if ret=0 and expected is true or ret=1 and expected is false
    return (int(ret) == 0 and expected) or (int(ret) == 1 and not expected)

def curl(client, server, method="GET", payload="", port=80, expected=True):
        """
        run curl for HTTP request. Request method and payload should be specified
        Server can either be a host or a string
        return True in case of success, False if not
        """

        if (isinstance(server, str) == 0):
            server_ip = str(server.IP())
        else:
            # If it's a string it should be the IP address of the node (e.g., the load balancer)
            server_ip = server

        # TODO: Specify HTTP method
        # TODO: Pass some payload (a.k.a. data). You may have to add some escaped quotes!
        # The magic string at the end reditect everything to the black hole and just print the return code

        # For now we left it as is, as the HTTP protocol will have no impact on the networking here
        cmd = f"curl --connect-timeout 50 --max-time 100 -X {method} -s {server_ip}:{port} > /dev/null 2>&1; echo $?"
        ret = client.cmd(cmd).strip()
        expected_int = 0 if expected else "> 0"
        print(f"`{cmd}` on {client} returned {ret}, expected {expected_int}")

        # 0 means success, not 0 means something went wrong
        return (int(ret) == 0 and expected) or (int(ret) !=0 and not expected) # True means "everyhing went as expected"

def curl_ids(client, server="", method="", payload="", port=80, expected=True):
        """
        run curl for HTTP request. Request method and payload should be specified
        Server can either be a host or a string
        return True in case of success, False if not
        """

        if (isinstance(server, str) == 0):
            server_ip = str(server.IP())
        else:
            # If it's a string it should be the IP address of the node (e.g., the load balancer)
            server_ip = server
        cmd = f'curl --connect-timeout 50 --max-time 100 -X "{method}" -d "{payload}" -s {"100.0.0.45"}:{port} > /dev/null 2>&1; echo $?'
        ret = client.cmd(cmd).strip()
        expected_int = 0 if expected else "> 0"
        print(f"`{cmd}` on {client} returned {ret}, expected {expected_int}")

        # 0 means success, not 0 means something went wrong
        return (int(ret) == 0 and expected) or (int(ret) !=0 and not expected) # True means "everyhing went as expected"

