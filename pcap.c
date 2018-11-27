#include "pcap.h"
#include <sys/types.h>
#include <pcap/pcap.h>
#include <netinet/in.h>
#include <string.h>


extern pid_t pid;
extern u16 icmp_req;

static const char* dev = "enp0s3";
static char* net;
static char* mask;

static char filter_string[FILTER_STRING_SIZE] = "";

static pcap_t *p;
static struct pcap_pkthdr hdr;

/*
 * This function is almost completed.
 * But you still need to edit the filter string.
 */
void pcap_init( const char* dst_ip ,int timeout )
{	
	int ret;
	char errbuf[PCAP_ERRBUF_SIZE];//256bit
	char tempfilter[FILTER_STRING_SIZE] = "(icmp[icmptype] == icmp-echo or icmp[icmptype] == icmp-echoreply) and host ";
	strcat(tempfilter,dst_ip);
	strcpy(filter_string,tempfilter);

	bpf_u_int32 netp;
	bpf_u_int32 maskp;

	struct in_addr addr;

	struct bpf_program fcode;

	ret = pcap_lookupnet(dev, &netp, &maskp, errbuf);
	if(ret == -1)
	{
		fprintf(stderr,"%s\n",errbuf);
		exit(1);
	}

	addr.s_addr = netp;
	net = inet_ntoa(addr);	
	if(net == NULL)
	{
		perror("inet_ntoa");
		exit(1);
	}

	addr.s_addr = maskp;
	mask = inet_ntoa(addr);
	if(mask == NULL)
	{
		perror("inet_ntoa");
		exit(1);
	}


	p = pcap_open_live(dev, 8000, 1, timeout, errbuf);
	if(!p)
	{
		fprintf(stderr,"%s\n",errbuf);
		exit(1);
	}

	/*
	 *    you should complete your filter string before pcap_compile
	 */


	if(pcap_compile(p, &fcode, filter_string, 0, maskp) == -1)
	{
		pcap_perror(p,"pcap_compile");
		exit(1);
	}

	if(pcap_setfilter(p, &fcode) == -1)
	{
		pcap_perror(p,"pcap_setfilter");
		exit(1);
	}
}


int pcap_get_reply()
{
	// const u_char *ptr;
	// u_int16_t id;
	// u_int16_t seq;
	// struct in_addr gwip,dstip;
	// ptr = pcap_next(p, &hdr);
	// if (ptr == NULL)
	// {
	// 	printf("No packets\n");
	// 	return -1;
	// }
	// memcpy(&gwip, ptr+37,4);
	// memcpy(&dstip,ptr+26,4);
	// memcpy(&id, ptr+46, 2);
	// memcpy(&seq, ptr+48, 2);
	// if(id != htons(pid))
	// {
	// 	printf("identifier error\n");
	// 	exit(1);
	// }
	// if(seq != htons(countseq))
	// {
	// 	printf("sequence error\n");
	// 	exit(1);
	// }
	// printf("Reply from %s: time = %0.3fms\n",inet_ntoa(dstip),hdr.ts.tv_usec/1000000.0);
	// printf("\tRoute: %s\n",inet_ntoa(gwip));
	// /*
	//  * google "pcap_next" to get more information
	//  * and check the packet that ptr pointed to.
	//  */	
	// return 0;
}