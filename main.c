#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <netinet/in.h>
#include <netdb.h>
#include <unistd.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <sys/time.h>

#include "fill_packet.h"
#include "pcap.h"


pid_t pid;
int countseq;

void usage();
char* get_locol_IP(char *iface);
char* int2str(int num);
int main(int argc, char* argv[])
{
	int sockfd;
	int on = 1;
	
	
	pid = getpid();
	countseq = 0;
	struct sockaddr_in dst;
	in_addr_t target_ip;
	myicmp *packet = (myicmp*)malloc(PACKET_SIZE);
	int count = DEFAULT_SEND_COUNT;
	int timeout = DEFAULT_TIMEOUT;
	
	char *ID = calloc(10, sizeof(char));
	strcpy(ID, "M073040009");

	if(geteuid() != 0)
		printf("ERROR: You must be root to use this tool!\n");
	else{
		if(argc != 5 || strcmp(argv[1], "-i") || strcmp(argv[3], "-t"))
			usage();
		else{
			int i, j;
			char *local_IP = calloc(16, sizeof(char));
			strcpy(local_IP, get_locol_IP(argv[2]));
			char temp_IP[16];	//copy for slice
			int ip_Subnet[4];
			char *destination_IP;

			strcpy(temp_IP, local_IP);
			
			// local ip slicing
			ip_Subnet[0] = atoi(strtok(temp_IP, "."));
			for(i=1; i<4; i++)
				ip_Subnet[i] = atoi(strtok(NULL, "."));


			if((sockfd = socket(AF_INET, SOCK_RAW , IPPROTO_RAW)) < 0){
					perror("socket");
					exit(1);
				}

			if(setsockopt( sockfd, IPPROTO_IP, IP_HDRINCL, &on, sizeof(on)) < 0){
				perror("setsockopt");
				exit(1);
			}
			//1~254
			for(i=1; i<255; i++){		//subnet4
				countseq++;
				destination_IP = calloc(16, sizeof(char));
				// merge as destination IP
				for(j=0; j<3; j++){
					
					strcat(destination_IP, int2str(ip_Subnet[j]));
					strcat(destination_IP, ".");
				}
				strcat(destination_IP, int2str(i));

				if (!strcmp(destination_IP, local_IP))
					continue;

				timeout = atoi(argv[4]);

				bzero(&dst, sizeof(dst));
				dst.sin_family = AF_INET;
				dst.sin_addr.s_addr = inet_addr(destination_IP);

				pcap_init(destination_IP, timeout);

				// fill icmp packet
				fill_iphdr(&(packet->ip_hdr), local_IP, destination_IP);
				fill_icmphdr(&(packet->icmp_hdr), pid, countseq);
				memcpy(packet->data, ID, sizeof(packet->data));
				(packet->icmp_hdr).checksum = fill_cksum(&(packet->icmp_hdr));

				printf("Ping %s (data size = %d, id = 0x%x, seq = %d, timeout = %d ms)\n",destination_IP, sizeof(packet->data), pid, countseq, timeout);

				//timer start
				struct timeval tv;
				gettimeofday(&tv, NULL);
				long int sendTime = tv.tv_sec*1000+tv.tv_usec/100;
				if(sendto(sockfd, packet, PACKET_SIZE, 0, (struct sockaddr *)&dst, sizeof(dst)) < 0){
					perror("sendto");
					exit(1);
				}
				
				int sockfd_recv = 0;
				int recvlen;
				myicmp rcv_pak;
				int ret;

				if((sockfd_recv = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP)) < 0){
					perror("open recv socket error");
					exit(1);
				}

				if((recvlen = recvfrom( sockfd_recv, (void *)&rcv_pak, sizeof(rcv_pak), 0, NULL, NULL))<0){	
					perror("recvfrom");
					exit(1);
				}

				//timer end
				gettimeofday(&tv, NULL);
				long int recvTime = tv.tv_sec*1000+tv.tv_usec/100;
				long int RTT = recvTime-sendTime;
				if(RTT < timeout && rcv_pak.icmp_hdr.type == htons(0))
					printf("Reply from : %s , time : %ld ms\n", destination_IP, recvTime-sendTime);
				else
					printf("Destination unreachable\n");

				fflush(stdout);
				free(destination_IP);
			}
			
		}
			
	}

	return 0;
}

void usage(){
	printf("sudo ./ipscanner -i [Network Interface Name] -t [timeout(ms)]\n");
}
char* get_locol_IP(char *iface){
	int fd;
	struct ifreq ifr;

	fd = socket(AF_INET, SOCK_DGRAM, 0);
	ifr.ifr_addr.sa_family = AF_INET;
	strncpy(ifr.ifr_name, iface, IFNAMSIZ-1);

	ioctl(fd, SIOCGIFADDR, &ifr);
	close(fd);

	return inet_ntoa(((struct sockaddr_in *)&ifr.ifr_addr)->sin_addr);
}
char* int2str(int num){
	char* str = malloc(sizeof(char)*sizeof(int)*3+1);
	sprintf(str, "%d", num);
	return str;
}