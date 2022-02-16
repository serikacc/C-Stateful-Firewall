# C-Stateful-Firewall
A C-based stateful firewall on Linux.
## Environment
VMware 12.5.9 build-7535481
Ubuntu 12.0.4
## Simple Principle
### Linux Netfilter
![image](https://user-images.githubusercontent.com/66781521/154284068-179adbb7-5a2d-480a-89e0-e55b320940bc.png)
|Hook point|Time to call|
|  ----  | ----  |
|NF_IP_PRE_ROUTING|The packets that just enter the network layer pass through this point, and the destination address translation takes place at this point.|
|NF_IP_LOCAL_IN|After the route is searched, the packets sent to the local machine passes this point, and the INPUT packet filtering is performed at this point.|
|NF_IP_FORWARD|The packets to be forwarded pass through this point, and FORWARD packet filtering is performed at this point.|
|NF_IP_LOCAL_OUT|The packets sent by the local process pass this point, and the OUTPUT packet filtering is performed at this point.|
|NF_IP_POST_ROUTING|All packets that are about to go out through the network device pass through this point, and the built-in source address translation function is performed at this point.|
### Two Modules
The firewall system consists of two parts, one is the firewall kernel module and the other is the application module.
#### Kernel module
The kernel module is used to intercept the packets passing through the firewall, perform rule filtering, and decide whether to prohibit or allow according to the rules. Rules are written by the application through the interface with the kernel.
#### Application module
The application module is used to set the rules (write to the kernel module), view the log (obtained from the kernel module, the kernel module should not write files directly, which is inefficient), check the connection (obtained from the kernel module) and other operations, which need to be communicated with the kernel module. Data is exchanged through a certain interface.
