#include "fill_packet.h"
#include <arpa/inet.h>
#include <unistd.h>
#include <sys/types.h>

// extern pid_t pid;
// extern int countseq; 
void fill_iphdr ( struct ip *ip_hdr , const char* dst_ip)
{
	ip_hdr->ip_v = 4;
	ip_hdr->ip_hl = 5;
	ip_hdr->ip_tos = 0;
	ip_hdr->ip_len = htons(84);
	ip_hdr->ip_id = htons(0);
	ip_hdr->ip_off = htons(IP_DF);
	ip_hdr->ip_ttl = 1;
	ip_hdr->ip_p = 1;
	ip_hdr->ip_dst.s_addr = inet_addr(dst_ip);
}

void fill_icmphdr (struct icmphdr *icmp_hdr)
{
	icmp_hdr->type = ICMP_ECHO;
	icmp_hdr->code = 0;
	icmp_hdr->checksum = 0;
	// icmp_hdr->un.echo.id = htons(pid);
	// icmp_hdr->un.echo.sequence = htons(countseq);
}

u16 fill_cksum(struct icmphdr* icmp_hdr)
{
	return htons(123);
}