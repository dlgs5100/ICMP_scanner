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

void usage();
char* get_locol_IP(char *iface);
char* int2str(int num);
int main(int argc, char* argv[])
{
	int sockfd;
	int on = 1;
	
	
	pid = getpid();
	struct sockaddr_in dst;
	in_addr_t target_ip;
	myicmp *packet = (myicmp*)malloc(PACKET_SIZE);
	int count = DEFAULT_SEND_COUNT;
	int timeout = DEFAULT_TIMEOUT;
	

	if(geteuid() != 0)
		printf("ERROR: You must be root to use this tool!\n");
	else{
		if(argc != 5 || strcmp(argv[1], "-i") || strcmp(argv[3], "-t"))
			usage();
		else{
			int i, j;
			char *local_IP = get_locol_IP(argv[2]);
			char temp_IP[16];	//copy for slice
			int ip_Subnet[4];
			char *destination_IP;

			strcpy(temp_IP, local_IP);
			

			ip_Subnet[0] = atoi(strtok(temp_IP, "."));
			for(i=1; i<4; i++)
				ip_Subnet[i] = atoi(strtok(NULL, "."));

			for(i=1; i<2; i++){		//subnet4
				destination_IP = calloc(16, sizeof(char));
				for(j=0; j<3; j++){
					strcat(destination_IP, int2str(ip_Subnet[j]));
					strcat(destination_IP, ".");
				}
				strcat(destination_IP, int2str(i));
				printf("%s\n", destination_IP);

				pcap_init(destination_IP, timeout);

				if((sockfd = socket(AF_INET, SOCK_RAW , IPPROTO_RAW)) < 0){
					perror("socket");
					exit(1);
				}

				if(setsockopt( sockfd, IPPROTO_IP, IP_HDRINCL, &on, sizeof(on)) < 0){
					perror("setsockopt");
					exit(1);
				}

				// *   Use "sendto" to send packets, and use "pcap_get_reply"(in pcap.c) 
					//  or use the standard socket like the one in the ARP homework
			 	//  *   to get the "ICMP echo response" packets 
				 // *	 You should reset the timer every time before you send a packet.
				

				fill_iphdr(&(packet->ip_hdr), destination_IP);
				if(sendto(sockfd, packet, PACKET_SIZE, 0, (struct sockaddr *)&dst, sizeof(dst)) < 0){
						perror("sendto");
						exit(1);
				}

				free(destination_IP);
			}
			

				
				 
	
				
				

				// free(packet);
			// }
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