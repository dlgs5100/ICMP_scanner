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
			

			ip_Subnet[0] = atoi(strtok(temp_IP, "."));
			for(i=1; i<4; i++)
				ip_Subnet[i] = atoi(strtok(NULL, "."));

			for(i=1; i<6; i++){		//subnet4
				countseq++;
				destination_IP = calloc(16, sizeof(char));
				for(j=0; j<3; j++){
					strcat(destination_IP, int2str(ip_Subnet[j]));
					strcat(destination_IP, ".");
				}
				strcat(destination_IP, int2str(i));
				// strcpy(destination_IP, "140.117.169.67");
				// printf("%s\n", destination_IP);

				timeout = atoi(argv[4]);

				bzero(&dst, sizeof(dst));
				dst.sin_family = AF_INET;
				dst.sin_addr.s_addr = inet_addr(destination_IP);

				pcap_init(destination_IP, timeout);

				if((sockfd = socket(AF_INET, SOCK_RAW , IPPROTO_RAW)) < 0){
					perror("socket");
					exit(1);
				}

				if(setsockopt( sockfd, IPPROTO_IP, IP_HDRINCL, &on, sizeof(on)) < 0){
					perror("setsockopt");
					exit(1);
				}

				
				

				fill_iphdr(&(packet->ip_hdr), local_IP, destination_IP);
				fill_icmphdr(&(packet->icmp_hdr), pid, countseq);
				memcpy(packet->data, ID, sizeof(packet->data));
				(packet->icmp_hdr).checksum = fill_cksum(&(packet->icmp_hdr));

				printf("Ping %s (data size = %d, id = 0x%x, seq = %d, timeout = %d ms)\n",destination_IP, sizeof(packet->data), pid, countseq, timeout);
				if(sendto(sockfd, packet, PACKET_SIZE, 0, (struct sockaddr *)&dst, sizeof(dst)) < 0){
					perror("sendto");
					exit(1);
				}
				// if(pcap_get_reply()== -1){
				// 	printf("Reply from : %s , time = *\n", destination_IP);
				// }

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
	// char *iface = "enp0s3";

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