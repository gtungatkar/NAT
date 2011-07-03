 #include <linux/kernel.h>

#include <linux/module.h>

#include <linux/netfilter.h>

#include <linux/netfilter_ipv4.h>
#include <linux/socket.h>
#include <net/sock.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/net.h>
#include <linux/string.h>
#include <linux/in.h>
#include <linux/time.h>
#include <net/tcp.h>
#define MAX_NAT_ENTRIES 65535
#define SET_ENTRY 133
#define RWPERM 0644

/* NAT table entry*/
struct nat_entry {
	__be32 lan_ipaddr;
	__be16 lan_port;
//	__be16 nat_port;
	unsigned long sec;	/*timestamp in seconds*/
	u_int8_t valid;
};

/*the NAT table is indexed by the translated port i.e. source port after NAT for outgoing packet*/
static struct nat_entry nat_table[MAX_NAT_ENTRIES];

static __be32 myip;
static __be32 priv_ip_mask;
static __be32 priv_ip_first;
static int start = 0;
static int timeout = 60;
static char lanstr[20] = "192.168.56.0/24";
static u_int16_t port = 10000;
module_param(start, int, S_IRUSR|S_IWUSR|S_IRGRP|S_IWGRP);

/*proc fs entries */
static struct proc_dir_entry *knat;
static struct proc_dir_entry *proc_ip, *proc_lan, *proc_timeout;

/*helper routines for IP address conversion*/
unsigned long ip_asc_to_int(char *strip) 
{
	unsigned long ip;
        unsigned int a[4];

        sscanf(strip, "%u.%u.%u.%u", &a[0], &a[1], &a[2], &a[3]);
        ip = (a[0] << 24)+(a[1] << 16)+(a[2] << 8)+a[3] ;
	return ip;
}

void inet_ntoa(char *tmp, u_int32_t int_ip)
{

	sprintf(tmp, "%d.%d.%d.%d",  (int_ip) & 0xFF,									(int_ip >> 8 ) & 0xFF,(int_ip >> 16) & 0xFF,(int_ip >> 24) & 0xFF);
	return; 
}

/*proc fs read write*/

static int proc_read_ip(char *page, char **start,
			off_t off, int count,
			int *eof, void *data)
{
	char tmp[16];
	int len;
	if(off > 0)
	{	
		*eof = 1;
		return 0;
	}
	inet_ntoa(tmp, myip);
	len = sprintf(page, "%s\n",  tmp);
	return len;
}
static int proc_write_ip(struct file *file,
			const char *buffer,
			unsigned long count,
			void *data)
{

	char tmp[16];
	if(count > 15)	
	{
		//don't try to convert that string.
		return -ENOSPC;
	}
		
	if(copy_from_user(tmp, buffer, count)){
		return -EFAULT;
	}
	tmp[count] = '\0';
	myip = htonl(ip_asc_to_int(tmp));
	return count;
}
static int proc_read_timeout(char *page, char **start,
			off_t off, int count,
			int *eof, void *data)
{
	int len;
	if(off > 0)
	{	
		*eof = 1;
		return 0;
	}
	len = sprintf(page, "%u\n",  timeout);
	return len;
}
static int proc_write_timeout(struct file *file,
			const char *buffer,
			unsigned long count,
			void *data)
{

#define MAX_TIMEOUT_LEN_CHARS 6 
	char tmp[10];
	if(count > MAX_TIMEOUT_LEN_CHARS)	
	{
		//don't try to convert that string.
		return -EFAULT;
	}
		
	if(copy_from_user(tmp, buffer, count)){
		return -EFAULT;
	}
	tmp[count] = '\0';
	timeout = simple_strtoul(tmp, NULL, 10);
	return count;
}
static int proc_read_lan(char *page, char **start,
			off_t off, int count,
			int *eof, void *data)
{
	int len;
	if(off > 0)
	{	
		*eof = 1;
		return 0;
	}
	len = sprintf(page, "%s\n",  lanstr);
	return len;
}
static int proc_write_lan(struct file *file,
			const char *buffer,
			unsigned long count,
			void *data)
{

	int  mask, i; 
	char tmp[20];
	char *s;
	u_int32_t le_mask = 0;
	if(count > 20)	
	{
		//don't try to convert that string.
		return -EFAULT;
	}
		
	if(copy_from_user(lanstr, buffer, count)){
		return -EFAULT;
	}
	lanstr[count] = '\0';
	strncpy(tmp, lanstr, count+1);
	s = strstr(tmp, "/");
	if(s == NULL)
	{
		return -EFAULT;
	}
	*s = '\0';
	s++;
	
	priv_ip_first = htonl(ip_asc_to_int(tmp));
	mask  = (simple_strtoul(s, NULL, 10));
	for(i = 0; i < mask; i++)
	{
		le_mask = le_mask << 1;
		le_mask = le_mask | 1;
	}
	priv_ip_mask = le_mask;
	return count;
}

/* update the checksums for tcp and ip*/
void update_tcp_ip_checksum(struct sk_buff *skb, struct tcphdr *tcph, 
	struct iphdr *iph)
{
		
	int len;
	if (!skb || !iph || !tcph) return ;
	len = skb->len;
	
/*update ip checksum*/
	iph->check = 0;
	iph->check = ip_fast_csum((unsigned char *)iph, iph->ihl);
/*update tcp checksum */
	tcph->check = 0;
	tcph->check = tcp_v4_check(
			len - 4*iph->ihl,
			iph->saddr, iph->daddr,
			csum_partial((char *)tcph, len-4*iph->ihl,
				0));
	return;
	
}

/*find the nat table entry for given lan port. 
@sport = source port as obtained from packet from lan*/
__be16 find_nat_entry(__be32 saddr, __be16 sport)
{
	int i = 0;
	unsigned int t = 0;
	for(i = 0; i < MAX_NAT_ENTRIES; i++)
	{
		if((nat_table[i].lan_ipaddr == saddr) && (nat_table[i].lan_port == sport) && nat_table[i].valid)
		{
			t = (get_seconds() - nat_table[i].sec);
			if(t > timeout)
			{
				printk("NAT Entry timeout\n");
				nat_table[i].valid = 0;
				return 0;
			}	
			return i;
		}
	}
	return 0;
}
static struct nf_hook_ops netfilter_ops_in, netfilter_ops_pre;

/*PRE ROUTING Hook: In this we do DNAT
For packets coming from WAN, destination IP and port are changed to lan ip and port from NAT Table entries */

unsigned int main_hook_pre(unsigned int hooknum,

		struct sk_buff *skb,

		const struct net_device *in,

		const struct net_device *out,

		int (*okfn)(struct sk_buff*))

{

	struct iphdr *iph;
	struct tcphdr *tcph;
	__be16 lan_port;
	

	if(start == 0)
		return NF_ACCEPT;
	if (!skb) return NF_ACCEPT;

	printk("PRE ROUTING");


	iph = ip_hdr(skb);

	if (!iph) return NF_ACCEPT;


	if (iph->protocol==IPPROTO_TCP)
	{
		if(iph->daddr == myip)
		{
			tcph = (struct tcphdr*)((char *)iph + iph->ihl*4);
			if(!tcph) return NF_ACCEPT;
			if(nat_table[tcph->dest].valid == SET_ENTRY)
			{
				/*lazy checking of stale entries*/
				if((get_seconds() - nat_table[tcph->dest].sec) > timeout)
				{
					/*stale entry which means we do not have a NAT entry for this packet*/
					nat_table[tcph->dest].valid = 0;
					return NF_ACCEPT;
				}
				/*translate ip addr and port*/
				lan_port = nat_table[tcph->dest].lan_port;
				iph->daddr = nat_table[tcph->dest].lan_ipaddr;
				tcph->dest = lan_port;
				//re-calculate checksum
				update_tcp_ip_checksum(skb, tcph, iph);
			}
		}
	}


	return NF_ACCEPT;

}

/*POST ROUTING hook: We do SNAT here.
Packets from LAN - source IP and port are translated to public IP and sent out*/

unsigned int main_hook_post(unsigned int hooknum,

		struct sk_buff *skb,

		const struct net_device *in,

		const struct net_device *out,

		int (*okfn)(struct sk_buff*))

{

	struct iphdr *iph;
	struct tcphdr *tcph;
	__be32 oldip, newip;
	__be16  newport;
	int len = 0;

	if(start == 0)
		return NF_ACCEPT;
	if (!skb) return NF_ACCEPT;

	printk("POST ROUTING");


	iph = ip_hdr(skb);
	len = skb->len;
	if (!iph) return NF_ACCEPT;


	if (iph->protocol==IPPROTO_TCP)
	{
		oldip = iph->saddr;
		/*Is this packet from given LAN range*/
		if((oldip & priv_ip_mask) == priv_ip_first)
		{
			tcph = (struct tcphdr*)((char *)iph + iph->ihl*4);
			if(!tcph) return NF_ACCEPT;
			newport = find_nat_entry(iph->saddr, tcph->source);
			if(newport)
			{
				/*NAT entry already exists*/
				tcph->source = newport;
			}
			else
			{
				/*Make a new NAT entry choose port numbers > 10000*/
				newport = htons(port++);
				if(port == 0) port = 10000;
				nat_table[newport].valid = SET_ENTRY;
				nat_table[newport].lan_ipaddr = iph->saddr;
				nat_table[newport].lan_port = tcph->source;
				nat_table[newport].sec = get_seconds();
				tcph->source = newport;
				
			}
			iph->saddr = myip;	
			newip = iph->saddr;
			update_tcp_ip_checksum(skb, tcph, iph);	
		}

	}


	return NF_ACCEPT;

}



static int __init init(void)

{
	int mask = 24;
	int i = 0, rv = 0;
	u_int32_t le_mask = 0;
	for(i = 0; i < mask; i++)
	{
		le_mask = le_mask << 1;
		le_mask = le_mask | 1;
	}
	//le_mask = le_mask << zeroes;
	priv_ip_mask = le_mask;
	priv_ip_first = htonl(ip_asc_to_int("192.168.56.0"));
	myip = htonl(ip_asc_to_int("192.168.2.10"));
	netfilter_ops_in.hook = main_hook_post;

	netfilter_ops_in.pf = PF_INET;

	netfilter_ops_in.hooknum = NF_INET_POST_ROUTING;

	netfilter_ops_in.priority = NF_IP_PRI_FIRST;
	netfilter_ops_pre.hook = main_hook_pre;

	netfilter_ops_pre.pf = PF_INET;

	netfilter_ops_pre.hooknum = NF_INET_PRE_ROUTING;

	netfilter_ops_pre.priority = NF_IP_PRI_FIRST;

	knat = proc_mkdir("knat", NULL);
	if(knat == NULL){
		rv = -ENOMEM;
		goto out;
	}
	
	proc_ip = create_proc_entry("ip", RWPERM, knat);
	if(proc_ip == NULL){
		rv = -ENOMEM;
		goto out;
	}
	proc_ip->read_proc = proc_read_ip;
	proc_ip->write_proc = proc_write_ip;

	proc_timeout = create_proc_entry("timeout", RWPERM, knat);
	if(proc_timeout == NULL){
		rv = -ENOMEM;
		goto out;
	}
	proc_timeout->read_proc = proc_read_timeout;
	proc_timeout->write_proc = proc_write_timeout;

	proc_lan = create_proc_entry("lan", RWPERM, knat);
	if(proc_lan == NULL){
		rv = -ENOMEM;
		goto out;
	}
	proc_lan->read_proc = proc_read_lan;
	proc_lan->write_proc = proc_write_lan;

	nf_register_hook(&netfilter_ops_pre);
	nf_register_hook(&netfilter_ops_in);

	return 0;
out:
	return rv;
}



static void __exit cleanup(void)
{

	remove_proc_entry("ip", knat);
	remove_proc_entry("lan", knat);
	remove_proc_entry("timeout", knat);
	remove_proc_entry("knat", NULL);
	nf_unregister_hook(&netfilter_ops_in);
	nf_unregister_hook(&netfilter_ops_pre);

}



module_init(init);

module_exit(cleanup);



MODULE_LICENSE("GPL");
