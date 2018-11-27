#include "fill_packet.h"
#include <arpa/inet.h>
#include <unistd.h>
#include <sys/types.h>

void fill_iphdr(struct ip *ip_hdr, const char* src_ip, const char* dst_ip)
{
	ip_hdr->ip_v = 4;
	ip_hdr->ip_hl = 5;
	ip_hdr->ip_tos = 0;
	ip_hdr->ip_len = htons(84);
	ip_hdr->ip_id = htons(0);
	ip_hdr->ip_off = htons(IP_DF);
	ip_hdr->ip_ttl = 1;
	ip_hdr->ip_p = 1;
	ip_hdr->ip_src.s_addr = inet_addr(src_ip);
	ip_hdr->ip_dst.s_addr = inet_addr(dst_ip);
}

void fill_icmphdr(struct icmphdr *icmp_hdr, pid_t pid, int countseq)
{
	icmp_hdr->type = 8;
	icmp_hdr->code = 0;
	icmp_hdr->checksum = 0;
	icmp_hdr->un.echo.id = htons(pid);
	icmp_hdr->un.echo.sequence = htons(countseq);
}

u16 fill_cksum(struct icmphdr* hdr)
{
	return (u16)in_cksum((unsigned short *)hdr, ICMP_PACKET_SIZE);
}
unsigned short in_cksum(unsigned short *addr, int len)
{
	unsigned long chsum=0;
	while(len>1)
	{
		chsum+=*addr++;
		len-=2;
	}
	if(len==1)
	{
		chsum+=*(unsigned char *)addr;
	}
	chsum=(chsum>>16)+(chsum&0xffff);
	chsum+=(chsum>>16);
	return (unsigned short)(~chsum);
}