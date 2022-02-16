# C-Stateful-Firewall
A C-based stateful firewall on Linux.
## Environment
VMware 12.5.9 build-7535481
Ubuntu 12.0.4
## Simple Principle
### Linux Netfilter
![image](https://user-images.githubusercontent.com/66781521/154284068-179adbb7-5a2d-480a-89e0-e55b320940bc.png)
|Hook点|调用的时机|
|NF_IP_PRE_ROUTING|刚刚进入网络层的数据包通过此点（刚刚进行完版本号、校验和等检测），目的地址转换在此点进行|
|NF_IP_LOCAL_IN|经路由查找后，送往本机的通过此检查点，INPUT包过滤在此点进行|
|NF_IP_FORWARD|要转发的包经过此检测点，FORWARD包过滤在此点进行|
|NF_IP_LOCAL_OUT|本机进程发出的包通过此检测点，OUTPUT包过滤在此点进行|
|NF_IP_POST_ROUTING|所有马上便要通过网络设备出去的包通过此检测点，内置的源地址转换功能（包括地址伪装）在此点进行|
