#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/icmp.h>
#include <linux/types.h>
#include <linux/sched.h>
#include <net/sock.h>
#include <linux/netlink.h>
#include <linux/string.h>
#include <linux/init.h>
#include <linux/version.h>
#include <linux/timer.h>
#include <linux/delay.h>

#define STATUS_MAXNUM 1000
#define NETLINK_TEST 17
#define MAX_LIFE 5

// Struct for holding each rule
struct rule
{
	unsigned long int sip;
	unsigned long int smask;
	unsigned long int dip;
	unsigned long int dmask;
	int sport;
	int dport;
	int protocol;
	char log;
	char nattype;
	unsigned long int cip;
	int cport;
	int ltime;
};

struct { __u32 pid; }user_process;
struct timer_list sln_timer;
static struct sock *netlinkfd = NULL;
// Hook Options structures
static struct nf_hook_nattype input_filter;		// NF_INET_PRE_ROUTING - for incoming packets
static struct nf_hook_nattype output_filter;	// NF_INET_POST_ROUTING - for outgoing packets
// Array of rules
static struct rule rules[200];
static int numRules = 0;
static struct rule status_table[STATUS_MAXNUM];//按照源ip、目的ip、源端口、目的端口升序排列，二分查找 
static int num_status = 0;
static unsigned int default_mode = NF_DROP;

int dealinfo(char input[]);
int send_to_user(char *info);
void print_IP(unsigned long int sip);
void sprint_IP(char output[], unsigned long int sip);

int cmp_status(struct rule r1, struct rule r2)//比较函数 
{
	if(r1.sip == r2.sip)
	{
		
		if(r1.dip == r2.dip)
		{
			if(r1.sport == r2.sport)
			{
				return r1.dport - r2.dport;
			}
			else 
				return r1.sport - r2.sport;
		}
		else
			return r1.dip - r2.dip;
	}
	else
		return r1.sip - r2.sip;
}

int find_status(long int sip, long int dip, int sport, int dport)//二分查找
{
	int m;
	int x = 0;
	int y = num_status - 1;
	struct rule v;
	v.dip = dip;
	v.dport = dport;
	v.sip = sip;
	v.sport = sport;
	while(x < y)
	{
		m = x + (y - x)/2;
		if(cmp_status(status_table[m], v)==0)
		{
			status_table[m].ltime = MAX_LIFE;
			return m;
		}
		else if(cmp_status(status_table[m], v)>0)
			y = m;
		else
			x = m + 1;
	}
	return -1;
}

int insert_status(long int sip, long int dip, int sport, int dport)//二分插入 
{
	struct rule v;
	v.dip = dip;
	v.dport = dport;
	v.sip = sip;
	v.sport = sport;
	v.ltime = MAX_LIFE;
	int i=0;
	for(i = num_status;i>0;i--)
	{
		if(cmp_status(status_table[i-1], v)>=0)
			status_table[i] = status_table[i-1];
		else
			break;
	}
	status_table[i]=v;
	num_status++;
	return i;
}

void delete_status(int m)//二分删除 
{
	int i = 0;
	for(i=m;i<num_status-1;i++)
	{
		status_table[i] = status_table[i+1];
	}
	num_status--;
	return;
}

void print_status()
{
	int i=0;
	char output[2000];
	char id_add[20];
	sprintf(output, "\nCurrent status number: %d\n", num_status);
	for(;i<num_status;i++)
	{
		sprint_IP(id_add, status_table[i].sip);
		strcat(output, id_add);
		sprintf(id_add, ":%d -> ", status_table[i].sport);
		strcat(output, id_add);
		sprint_IP(id_add, status_table[i].dip);
		strcat(output, id_add);
		sprintf(id_add, ":%d\n", status_table[i].dport);
		strcat(output, id_add);
	}
	send_to_user(output);
}

int checkRule(struct rule *curr_rule, struct sk_buff *skb){
    
	// The Network Layer Header
	struct iphdr *ip_header;

	// The Transport Layer Header
	struct udphdr *udp_header;
	struct tcphdr *tcp_header;

	if ( !skb ) {
		return 0;
	}

	
	ip_header = (struct iphdr *)skb_network_header(skb);

	if ( !ip_header ) {
		return 0;
	}
    
	unsigned long int sip_real_area = (unsigned long int) (ntohl(ip_header->saddr));
	unsigned long int dip_real_area = (unsigned long int) (ntohl(ip_header->daddr));
	int real_sport = 0;
	int real_dport = 0;
        char real_protocol = 0;

	unsigned long int sip_expected_area = curr_rule->sip;
        unsigned long int dip_expected_area = curr_rule->dip;
	int expected_sport = curr_rule->sport;
	int expected_dport = curr_rule->dport;
	char expected_protocol = curr_rule->protocol;

	if ( ip_header->protocol == 6 )	// TCP
        {
                tcp_header = tcp_hdr(skb);
                real_sport = ntohs(tcp_header->source);
                real_dport = ntohs(tcp_header->dest);
                real_protocol=0;

		if(find_status(sip_real_area, dip_real_area, real_sport, real_dport) != -1 || 
			find_status(dip_real_area, sip_real_area, real_dport, real_sport) != -1)
		{
			printk("status match!\n");
			return 0;
		}
			
		else
		{
		}
        }
        else if( ip_header->protocol == 17 )	// UDP
        {
                udp_header = udp_hdr(skb);
                real_sport = ntohs(udp_header->source);
                real_dport = ntohs(udp_header->dest);
                real_protocol=1;
        }
        else if ( ip_header->protocol == 1 )	// ICMP
        {
		real_protocol=2;
        }

	int tcp_bool = ((sip_expected_area & curr_rule->smask) == (sip_real_area & curr_rule->smask) &&
			(dip_expected_area & curr_rule->dmask) == (dip_real_area & curr_rule->dmask) &&
			(expected_sport == real_sport || expected_sport == -1) &&
			(expected_dport == real_dport || expected_dport == -1) &&
			(expected_protocol == -1 || expected_protocol == 0) && real_protocol == 0 );
	int udp_bool = ((sip_expected_area & curr_rule->smask) == (sip_real_area & curr_rule->smask) &&
			(dip_expected_area & curr_rule->dmask) == (dip_real_area & curr_rule->dmask) &&
			(expected_sport == real_sport || expected_sport == -1) &&
			(expected_dport == real_dport || expected_dport == -1) &&
			(expected_protocol == -1 || expected_protocol == 1) && real_protocol == 1 );
	int icmp_bool = ((sip_expected_area & curr_rule->smask) == (sip_real_area & curr_rule->smask) &&
			(dip_expected_area & curr_rule->dmask) == (dip_real_area & curr_rule->dmask) &&
			(expected_protocol == -1 || expected_protocol == 2) && real_protocol == 2 );

	if(tcp_bool || udp_bool || icmp_bool)
	{
print_IP(sip_real_area);
printk(":%d -> ",real_sport);
print_IP(dip_real_area);
printk(":%d    protocol:%d operation:%d\n",real_dport,real_protocol, curr_rule->nattype);
		if( tcp_bool && curr_rule->nattype == 0 )
		{
			insert_status(sip_real_area, dip_real_area, real_sport, real_dport);
		}
		return curr_rule->nattype;
	}
	else
	{
		return -1;
	}
	
}

void snat(struct rule *curr_rule, struct sk_buff *skb)
{
	struct iphdr *ip_header;
	struct tcphdr *tcp_header;
	ip_header = (struct iphdr *)ip_hdr(skb);
	ip_header->saddr = curr_rule->cip;

	tcp_header = tcp_hdr(skb);
	tcp_header->source = curr_rule->cport;
}

void dnat(struct rule *curr_rule, struct sk_buff *skb)
{
	struct iphdr *ip_header;
	struct tcphdr *tcp_header;
	ip_header = (struct iphdr *)ip_hdr(skb);
	ip_header->daddr = curr_rule->cip;

	tcp_header = tcp_hdr(skb);
	tcp_header->dest = curr_rule->cport;
}

// Function that will perform filtering on incoming and outgoing packets
unsigned int hookfn(
		unsigned int hooknum,
		struct sk_buff *skb,
		const struct net_device *in, 
		const struct net_device *out,         
		int (*okfn)(struct sk_buff *)
		){
	// Loop through the array of rules and filter packets
	int i = 0;
	struct rule curr_rule;
	for (i = 0 ; i < numRules ; i++){
		curr_rule = rules[i];
		switch(checkRule(&curr_rule, skb))
		{
			case -1: break;
			case 0 :return NF_ACCEPT;
            case 1 :return NF_DROP;
            case 2 :return NF_ACCEPT;//snat
            case 3 :return NF_ACCEPT;//dnat
		}
	}
	return default_mode;
}

long int convertIP(unsigned char ip[])
{
	long int result = (long int)ip[0]*256*256*256 + (long int)ip[1]*256*256 + (long int)ip[2]*256 + (long int)ip[3];
	printk("IP %d.%d.%d.%d = %ld", ip[0], ip[1], ip[2], ip[3], result);
	return result;
}

void print_IP(unsigned long int sip)
{
	unsigned char src_i[4];
	src_i[3] = sip%256; sip /= 256;
	src_i[2] = sip%256; sip /= 256;
	src_i[1] = sip%256; sip /= 256;
	src_i[0] = sip%256; sip /= 256;
	printk("%d.%d.%d.%d", src_i[0],src_i[1],src_i[2],src_i[3]);
}

void sprint_IP(char output[], unsigned long int sip)
{
	unsigned char src_i[4];
	src_i[3] = sip%256; sip /= 256;
	src_i[2] = sip%256; sip /= 256;
	src_i[1] = sip%256; sip /= 256;
	src_i[0] = sip%256; sip /= 256;
	sprintf(output, "%d.%d.%d.%d", src_i[0],src_i[1],src_i[2],src_i[3]);
}

int send_to_user(char *info)
{
	int size;
	char input[1000];
	memset(input, '\0', 1000*sizeof(char));
	memcpy(input, info, strlen(info));
	struct sk_buff *skb;
	unsigned char *old_tail;
	struct nlmsghdr *nlh;
	int retval;
	size = NLMSG_SPACE(strlen(input));
	skb = alloc_skb(size, GFP_ATOMIC);
    nlh = nlmsg_put(skb, 0, 0, 0, NLMSG_SPACE(strlen(input))-sizeof(struct nlmsghdr), 0); 
	old_tail = skb->tail;
	memcpy(NLMSG_DATA(nlh), input, strlen(input));
	nlh->nlmsg_len = skb->tail - old_tail;
	NETLINK_CB(skb).pid = 0;
	NETLINK_CB(skb).dst_group = 0;
	retval = netlink_unicast(netlinkfd, skb, user_process.pid, MSG_DONTWAIT);
	printk(KERN_DEBUG "[kernel space] netlink_unicast return: %d\n", retval);
	return 0;
}

void kernel_receive(struct sk_buff *__skb)
{
	struct sk_buff *skb;
	struct nlmsghdr *nlh = NULL;

	char *data = "This is eric's test message from kernel.";
    skb = skb_get(__skb);
	if(skb->len >= sizeof(struct nlmsghdr)){
		nlh = (struct nlmsghdr *)skb->data;
		if((nlh->nlmsg_len >= sizeof(struct nlmsghdr))
		&& (__skb->len >= nlh->nlmsg_len)){
			user_process.pid = nlh->nlmsg_pid;
			dealinfo((char *)NLMSG_DATA(nlh));
		}
	}else{
		dealinfo((char *)NLMSG_DATA(nlmsg_hdr(__skb)));
	}
	kfree_skb(skb);
}

int find_char(char input[], char split, int start)
{
	int length = strlen(input);
	int i;
	for(i=start;i<length;i++)
	{
		if(split == input[i])
			return i;
	}
	return -1;
}

int dealinfo(char input[])
{
	char strin[100];
	strcpy(strin, input);
	char p[100];
	int i = 0;
	struct rule tmp;
	int operation;//0 插入， 1 删除， 2 查找， 3 save
	int index;//索引 
	unsigned char sip[4] = {0};
	unsigned char dip[4] = {0};
	unsigned char cip[4] = {0};
	
	int start = 0;
	int old;
	do
	{
		old = start;
		if((start = find_char(input, ' ', start))==-1)
		{
			start = strlen(input);
		}
		start++;
		memset(p, 0, 100*sizeof(char));
		memcpy(p, input+old, (start-old-1)*sizeof(char));
		//printk("-%s-\n", p);
		switch(i)
		{
			case 0: 
				if(p[0]=='i')
					operation = 0;
				else if(p[0]=='d')
					operation = 1;
				else if(p[0]=='r')
					operation = 2;
				else if(p[0]=='s')
					operation = 4;
				else
					return -1;
				break;
			case 1:
				index = simple_strtol(p, NULL, 10);
				break;
			case 2:
				sip[0] = simple_strtol(p, NULL, 10);
				break;
			case 3:
				sip[1] = simple_strtol(p, NULL, 10);
				break;
			case 4:
				sip[2] = simple_strtol(p, NULL, 10);
				break;
			case 5:
				sip[3] = simple_strtol(p, NULL, 10);
				tmp.sip = convertIP(sip);
				break;
			case 6:
				tmp.smask = 0xffffffff<<(simple_strtol(p, NULL, 10));
				break;
			case 7:
				tmp.sport = simple_strtol(p, NULL, 10);
				break;
				
			case 8:
				dip[0] = simple_strtol(p, NULL, 10);
				break;
			case 9:
				dip[1] = simple_strtol(p, NULL, 10);
				break;
			case 10:
				dip[2] = simple_strtol(p, NULL, 10);
				break;
			case 11:
				dip[3] = simple_strtol(p, NULL, 10);
				tmp.dip = convertIP(dip);
				break;
			case 12:
				tmp.dmask = 0xffffffff<<(simple_strtol(p, NULL, 10));
				break;
			case 13:
				tmp.dport = simple_strtol(p, NULL, 10);
				break;
				
			case 14:
				if(p[0]=='a')
					tmp.protocol = -1;
				else if(p[0]=='t')
					tmp.protocol = 0;
				else if(p[0]=='u')
					tmp.protocol = 1;
				else if(p[0]=='i')
					tmp.protocol = 2;
				else
					return -1;
				break;
			case 15:
				if(p[0]=='y')
					tmp.log = 1;
				else if(p[0]=='n')
					tmp.log = 0;
				else
					return -1;
				break;
			case 16:
				if(p[0]=='p')
					tmp.nattype = 0;
				else if(p[0]=='r')
					tmp.nattype = 1;
				else if(p[0]=='s')
					tmp.nattype = 2;
				else if(p[0]=='d')
					tmp.nattype = 3;
				else
					return -1;
				break;
			
			case 17:
				cip[0] = simple_strtol(p, NULL, 10);
				break;
			case 18:
				cip[1] = simple_strtol(p, NULL, 10);
				break;
			case 19:
				cip[2] = simple_strtol(p, NULL, 10);
				break;
			case 20:
				cip[3] = simple_strtol(p, NULL, 10);
				tmp.cip = convertIP(cip);
				break;
			case 21:
				tmp.cport = simple_strtol(p, NULL, 10);
				break;
		}
		i++;
	}while(start < strlen(input));
	if(operation == 0)
	{
		i=0;
		if(index>numRules || index<0 )
			return -1; 
		for(i = numRules;i>0;i--)
		{
			if(i>index)
				rules[i] = rules[i-1];
			else
				break;
		}
		rules[i] = tmp;
		numRules++;
printk("inserted.");
send_to_user("inserted.");
	}
	if(operation == 1)
	{
		i = 0;
		if(index>=numRules || index<0 )
			return -1; 
		for(i= index ;i<numRules-1;i++)
		{
			rules[i] = rules[i+1];
		}
		numRules--;
printk(" deleted.");
send_to_user("deleted.");
	}
	if(operation == 2)
	{
		i=0;
		char output[100] = {0};
		char all[1000] = {0};
                struct rule rulesi;
		for(i=0;i<numRules;i++)
		{
            rulesi = rules[i];
			sip[3] = rulesi.sip%256; rulesi.sip /= 256;
			sip[2] = rulesi.sip%256; rulesi.sip /= 256;
			sip[1] = rulesi.sip%256; rulesi.sip /= 256;
			sip[0] = rulesi.sip%256; rulesi.sip /= 256;
			dip[3] = rulesi.dip%256; rulesi.dip /= 256;
			dip[2] = rulesi.dip%256; rulesi.dip /= 256;
			dip[1] = rulesi.dip%256; rulesi.dip /= 256;
			dip[0] = rulesi.dip%256; rulesi.dip /= 256;
			cip[3] = rulesi.cip%256; rulesi.cip /= 256;
			cip[2] = rulesi.cip%256; rulesi.cip /= 256;
			cip[1] = rulesi.cip%256; rulesi.cip /= 256;
			cip[0] = rulesi.cip%256; rulesi.cip /= 256;
			char pro[10];
			switch(rules[i].protocol)
			{
				case -1: strcpy(pro, "any"); break;
				case 0: strcpy(pro, "tcp"); break;
				case 1: strcpy(pro, "udp"); break;
				case 2: strcpy(pro, "icmp"); break;
			}
			char nattype[10];
			switch(rules[i].nattype)
			{
				case 0: strcpy(nattype, "permit"); break;
				case 1: strcpy(nattype, "reject"); break;
				case 2: strcpy(nattype, "snat"); break;
				case 3: strcpy(nattype, "dnat"); break;
			}
			char log[10];
			switch(rules[i].log)
			{
				case 0: strcpy(log, "no"); break;
				case 1: strcpy(log, "yes"); break;
			}
			sprintf(output, "%d  %d.%d.%d.%d %x port:%d -> %d.%d.%d.%d %x port:%d %s %s %s ", i, sip[0], sip[1], sip[2], sip[3], rules[i].smask, rules[i].sport, dip[0], dip[1], dip[2], dip[3], rules[i].dmask, rules[i].dport, pro, log, nattype);
			strcat(all, output);
			if(rules[i].nattype == 2 || rules[i].nattype == 3)
			{
				sprintf(output, "%d.%d.%d.%d port:%d\n", cip[0], cip[1], cip[2], cip[3], rules[i].cport);
				strcat(all, output);
			}
			else
			{
				strcat(all, "\n");
			}
		}
printk(all);
send_to_user(all);
	}
	if(operation == 4)
	{
		print_status();
	}
	return 0;
}

void sln_timer_do(unsigned long l)
{
	mod_timer(&sln_timer, jiffies + HZ);//HZ为1秒，在此时间之后继续执行
	int i = 0;
	for(;i<num_status;i++)
	{
		status_table[i].ltime --;
		if(status_table[i].ltime == 0)
		{
			delete_status(i);
		}
	}
}

//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
int init_module()
{	
	// Initialize Pre-Routing Filter
	printk("\nStarting CWall\n");
	input_filter.hook	= (nf_hookfn *)&hookfn;		// Hook Function
	input_filter.pf		= PF_INET;			// Protocol Family
	input_filter.hooknum	= NF_INET_PRE_ROUTING;		// Hook to be used
	input_filter.priority	= NF_IP_PRI_FIRST;		// Priority of our hook (makes multiple hooks possible)

	// Initialize Post-Routing Filter
	output_filter.hook	= (nf_hookfn *)&hookfn2;	// Hook Function
	output_filter.pf	= PF_INET;			// Protocol Family
	output_filter.hooknum	= NF_INET_POST_ROUTING;		// Hook to be used
	output_filter.priority	= NF_IP_PRI_FIRST;		// Priority of our hook (makes multiple hooks possible)
	
	// Register our hooks
	nf_register_hook(&input_filter);
	nf_register_hook(&output_filter);

	init_timer(&sln_timer);//初始化定时器
	sln_timer.expires = jiffies + HZ;   //1s后执行
	sln_timer.function = sln_timer_do;    //执行函数
	add_timer(&sln_timer);    //向内核注册定时器

	netlinkfd = netlink_kernel_create(&init_net, NETLINK_TEST, 0, kernel_receive, NULL, THIS_MODULE);
	if(!netlinkfd)
	{
		printk(KERN_ERR "Can not create a netlink socket.\n");
		return -1;
	}
	return 0;

}

void cleanup_module()
{
	// Unregister our hooks
	nf_unregister_hook(&input_filter);
	nf_unregister_hook(&output_filter);

	del_timer(&sln_timer);//删除定时器

	sock_release(netlinkfd->sk_socket);
	printk("\nStopping CWall");
}
