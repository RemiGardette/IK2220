## SDN and NFV Project - IK2220 - KTH

This project was done by a group of three students at KTH. 
It aims to deploy a small network where basic functions (L2 and L3 routing, firewalls) are done through Software Defined Networking, and more complex functions lLoad balancing, intrusion detection and network address translation) are done using network functions virtualization.

## How to run the project

**make topo:**

Starts mininet topology (it is defined at ./topology/topology.py)


**make app:**

Starts the controller.
The default pox directory is set to '/opt/pox/'.
However one should be able to overwrite it using make input.

Example:
`$ make poxdir=/pox/base/directory/ app`

**make test:**

Restarts topology, and the sdn controller. Then it runs provided test scenarios.

The tests scenarios include: 
- pings from all hosts to all hosts 
- curl from all clients (h1 to h4) to all servers (ws1 to ws3)

The tests will generate the following dated test results files int the /results directory:
- controller_logs: all the logs from the controller, show how the packets are handled by the firewalls
- results: show the different tests with the respective command and result (Passed/Failed), and a connectivity matrix summarizing the results

The tests can be found in ./topology/topology_test.py, and the test functions can be found in ./topology/test.py. An example of the results we got will be included in the submission.

Launching the tests might create some graphical bugs in the terminal interface. They will disappear once the tests are done (it usually takes a few minutes).


**make clean:**

Removes all junks added to different directories to run the application.

**make clean_results:**

Remove all the files in ./results
