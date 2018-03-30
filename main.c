
#include "main.h"

/*
 * Converts struct sockaddr with an IPv4 address to network byte order uin32_t.
 * Returns 0 on success.
 */
int int_ip4(struct sockaddr *addr, uint32_t *ip)
{
    if (addr->sa_family == AF_INET) {
        struct sockaddr_in *i = (struct sockaddr_in *) addr;
        *ip = i->sin_addr.s_addr;
        return 0;
    } else {
        err("Not AF_INET");
        return 1;
    }
}

/*
 * Formats sockaddr containing IPv4 address as human readable string.
 * Returns 0 on success.
 */
int format_ip4(struct sockaddr *addr, char *out)
{
    if (addr->sa_family == AF_INET) {
        struct sockaddr_in *i = (struct sockaddr_in *) addr;
        const char *ip = inet_ntoa(i->sin_addr);
        if (!ip) {
            return -2;
        } else {
            strcpy(out, ip);
            return 0;
        }
    } else {
        return -1;
    }
}

/*
 * Writes interface IPv4 address as network byte order to ip.
 * Returns 0 on success.
 */
int get_if_ip4(int fd, const char *ifname, uint32_t *ip) {
    int err = -1;
    struct ifreq ifr;
    memset(&ifr, 0, sizeof(struct ifreq));
    if (strlen(ifname) > (IFNAMSIZ - 1)) {
        err("Too long interface name");
        goto out;
    }

    strcpy(ifr.ifr_name, ifname);
    if (ioctl(fd, SIOCGIFADDR, &ifr) == -1) {
        perror("SIOCGIFADDR");
        goto out;
    }

    if (int_ip4(&ifr.ifr_addr, ip)) {
        goto out;
    }
    err = 0;
out:
    return err;
}

/*
 * Sends an ARP who-has request to dst_ip
 * on interface ifindex, using source mac src_mac and source ip src_ip.
 */
int send_arp(int fd, int ifindex, const unsigned char *src_mac, uint32_t src_ip, uint32_t dst_ip)
{
    int err = -1;
    unsigned char buffer[BUF_SIZE];
    memset(buffer, 0, sizeof(buffer));

    struct sockaddr_ll socket_address;
    socket_address.sll_family = AF_PACKET;
    socket_address.sll_protocol = htons(ETH_P_ARP);
    socket_address.sll_ifindex = ifindex;
    socket_address.sll_hatype = htons(ARPHRD_ETHER);
    socket_address.sll_pkttype = (PACKET_BROADCAST);
    socket_address.sll_halen = MAC_LENGTH;
    socket_address.sll_addr[6] = 0x00;
    socket_address.sll_addr[7] = 0x00;

    struct ethhdr *send_req = (struct ethhdr *) buffer;
    struct arp_header *arp_req = (struct arp_header *) (buffer + ETH2_HEADER_LEN);
    int index;
    ssize_t ret, length = 0;

    //Broadcast
    memset(send_req->h_dest, 0xff, MAC_LENGTH);

    //Target MAC zero
    memset(arp_req->target_mac, 0x00, MAC_LENGTH);

    //Set source mac to our MAC address
    memcpy(send_req->h_source, src_mac, MAC_LENGTH);
    memcpy(arp_req->sender_mac, src_mac, MAC_LENGTH);
    memcpy(socket_address.sll_addr, src_mac, MAC_LENGTH);

    /* Setting protocol of the packet */
    send_req->h_proto = htons(ETH_P_ARP);

    /* Creating ARP request */
    arp_req->hardware_type = htons(HW_TYPE);
    arp_req->protocol_type = htons(ETH_P_IP);
    arp_req->hardware_len = MAC_LENGTH;
    arp_req->protocol_len = IPV4_LENGTH;
    arp_req->opcode = htons(ARP_REQUEST);

    memcpy(arp_req->sender_ip, &src_ip, sizeof(uint32_t));
    memcpy(arp_req->target_ip, &dst_ip, sizeof(uint32_t));

    ret = sendto(fd, buffer, 42, 0, (struct sockaddr *) &socket_address, sizeof(socket_address));
    if (ret == -1) {
        perror("sendto():");
        goto out;
    }
    err = 0;
out:
    return err;
}

/*
 * Gets interface information by name:
 * IPv4
 * MAC
 * ifindex
 */
int get_if_info(const char *ifname, uint32_t *ip, char *mac, int *ifindex) {
    int err = -1;
    struct ifreq ifr;
    int sd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ARP));
    if (sd <= 0) {
        perror("socket()");
        goto out;
    }
    if (strlen(ifname) > (IFNAMSIZ - 1)) {
        printf("Too long interface name, MAX=%i\n", IFNAMSIZ - 1);
        goto out;
    }

    strcpy(ifr.ifr_name, ifname);

    if (ioctl(sd, SIOCGIFINDEX, &ifr) == -1) {
        perror("SIOCGIFINDEX");
        goto out;
    }
    *ifindex = ifr.ifr_ifindex;

    //Get MAC address of the interface
    if (ioctl(sd, SIOCGIFHWADDR, &ifr) == -1) {
        perror("SIOCGIFINDEX");
        goto out;
    }

    //Copy mac address to output
    memcpy(mac, ifr.ifr_hwaddr.sa_data, MAC_LENGTH);

    if (get_if_ip4(sd, ifname, ip)) {
        goto out;
    }

    err = 0;
out:
    if (sd > 0) {
        close(sd);
    }
    return err;
}

/*
 * Creates a raw socket that listens for ARP traffic on specific ifindex.
 * Writes out the socket's FD.
 * Return 0 on success.
 */
int bind_arp(int ifindex, int *fd)
{
	int ret = -1;
	struct sockaddr_ll sll;

	*fd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ARP));
	if (*fd < 1) {
		perror("socket()");
		goto out;
	}


	memset(&sll, 0, sizeof(struct sockaddr_ll));
	sll.sll_family = AF_PACKET;
	sll.sll_ifindex = ifindex;
	if (bind(*fd, (struct sockaddr*) &sll, sizeof(struct sockaddr_ll)) < 0) {
		perror("bind");
		goto out;
	}

	ret = 0;
	
out:	if (ret && *fd > 0) {
		close(*fd);
	}
	return ret;
}


/*
 *
 * Sample code that sends an ARP who-has request on
 * interface <ifname> to IPv4 address <ip>.
 * Returns 0 on success.
 */
int test_arping(char *ifname, uint32_t ip) {
    int ret = -1;
    uint32_t dst =ip;
    if (dst == 0 || dst == 0xffffffff) {
        printf("Invalid source IP\n");
        return 1;
    }

    int src;
    int ifindex;
    char mac[MAC_LENGTH];
    
    if (get_if_info(ifname, &src, mac, &ifindex)) {
        err("get_if_info failed, interface %s not found or no IP set?", ifname);
        goto out;
    }
    int arp_fd;
    if (bind_arp(ifindex, &arp_fd)) {
        err("Failed to bind_arp()");
        goto out;
    }

    if (send_arp(arp_fd, ifindex, mac, src, dst)) {
        err("Failed to send_arp");
        goto out;
    }
    ret = 0;
out:
    if (arp_fd) {
        close(arp_fd);
        arp_fd = 0;
    }
    return ret;
}

void sendARPpacket(char *ifname, uint32_t ip) {
    int i=test_arping(ifname, ip);
    return;
}

int get_if_info_ip(const char *ifname, uint32_t *ip, char *mac, int *ifindex) {
    int err = -1;
    struct ifreq ifr;
    int sd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (sd <= 0) {
        perror("socket()");
        goto out;
    }
    if (strlen(ifname) > (IFNAMSIZ - 1)) {
        printf("Too long interface name, MAX=%i\n", IFNAMSIZ - 1);
        goto out;
    }

    strcpy(ifr.ifr_name, ifname);

    //Get interface index using name
    if (ioctl(sd, SIOCGIFINDEX, &ifr) == -1) {
        perror("SIOCGIFINDEX");
        goto out;
    }
    *ifindex = ifr.ifr_ifindex;
    //Get MAC address of the interface
    if (ioctl(sd, SIOCGIFHWADDR, &ifr) == -1) {
        perror("SIOCGIFINDEX");
        goto out;
    }

    //Copy mac address to output
    memcpy(mac, ifr.ifr_hwaddr.sa_data, MAC_LENGTH);

    if (get_if_ip4(sd, ifname, ip)) {
        goto out;
    }
    err = 0;
out:
    if (sd > 0) {
        close(sd);
    }
    return err;
}

int send_ip(int fd, int ifindex, const unsigned char *src_mac, uint32_t src_ip, uint32_t dst_ip, uint8_t* packet)
{
	int err = -1;
	unsigned char buffer[BUF_SIZE];
	int index;
	ssize_t ret, length = 0;
	struct sockaddr_ll socket_address;

	memset(buffer, 0, sizeof(buffer));

	
	socket_address.sll_family = AF_PACKET;
	socket_address.sll_protocol = IPPROTO_RAW;
	socket_address.sll_ifindex = ifindex;
	socket_address.sll_hatype = htons(ARPHRD_ETHER);

	socket_address.sll_halen = ETH_ALEN;
	socket_address.sll_addr[6] = 0x00;
	socket_address.sll_addr[7] = 0x00;

	struct sniff_ethernet* tempEthernet = (struct sniff_ethernet*)packet;
	struct sniff_ip* tempIP = (struct sniff_ip*)(packet + sizeof(struct sniff_ethernet));
	int sizePacket = sizeof(struct sniff_ethernet)+ntohs(tempIP->ip_len);

	ret = sendto(fd, packet, sizePacket, 0, (struct sockaddr *) &socket_address, sizeof(socket_address));
	if (ret == -1) {
	perror("sendto():");
	goto out;
	}
	err = 0;
out:	return err;
}

int bind_ip(int ifindex, int *fd) {
    int ret = -1;
    *fd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (*fd < 1) {
        perror("socket()");
        goto out;
    }

    struct sockaddr_ll sll;
    memset(&sll, 0, sizeof(struct sockaddr_ll));
    sll.sll_family = AF_PACKET;
    sll.sll_ifindex = ifindex;
    if (bind(*fd, (struct sockaddr*) &sll, sizeof(struct sockaddr_ll)) < 0) {
        perror("bind");
        goto out;
    }

    ret = 0;
out:
    if (ret && *fd > 0) {
        close(*fd);
    }
    return ret;
}

int test_packet(char *ifname, uint32_t ip, uint8_t* packet) {
    int ret = -1;
    uint32_t dst =ip;
    int src;
    int ifindex;
    char mac[MAC_LENGTH];
    int ip_fd;
    if (dst == 0 || dst == 0xffffffff) {
        printf("Invalid source IP\n");
        return 1;
    }

    if (get_if_info_ip(ifname, &src, mac, &ifindex)) {
        err("get_if_info failed, interface %s not found or no IP set?", ifname);
        goto out;
    }
    
    if (bind_ip(ifindex, &ip_fd)) {
        err("Failed to bind_ip()");
        goto out;
    }

    if (send_ip(ip_fd, ifindex, mac, src, dst, packet)) {
        err("Failed to send_ip");
        goto out;
    }

    ret = 0;
out:
    if (ip_fd) {
        close(ip_fd);
        ip_fd = 0;
    }
    return ret;
}

void sendPacket(char *ifname, uint32_t ip, uint8_t* packet) {
	int i = test_packet(ifname, ip, packet);
}

int isPacketForMe(uint32_t des) {
	int i;
	for(i=0;i<interfaceCount;i++) {
		if(routerInterfaces->interface_ipaddress == des) {	
			return 1;
		}
	}
	return 0;
}

uint16_t cksum (const void *_data, int len) {
	const uint8_t *data = _data;
	uint32_t sum;
	for (sum = 0;len >= 2; data += 2, len -= 2)
	sum += data[0] << 8 | data[1];
	if (len > 0)
	sum += data[0] << 8;
	while (sum > 0xffff)
	sum = (sum >> 16) + (sum & 0xffff);
	sum = htons (~sum);
	return sum ? sum : 0xffff;
}

void
got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet)
{

	static int count = 1;                   /* packet counter */
	int i;
	
	/* declare pointers to packet headers */
	//Const removed
	struct sniff_ethernet *ethernet;  /* The ethernet header [1] */
	struct arp_header *arp;		/* The ARP header */
	struct sniff_ip *ip;              /* The IP header */
	struct sniff_tcp *tcp;            /* The TCP header */
	char *payload;                    /* Packet payload */

	int size_ip;
	int size_tcp;
	int size_payload;
	count++;
	/* define ethernet header */
	ethernet = (struct sniff_ethernet*)(packet);
	
	for(i=0; i < interfaceCount; i++) {
		if(memcmp(ethernet->ether_shost,routerInterfaces[i].interface_macaddress,6)==0) {
			return;
		}
	}	

	if(ethernet->ether_type == etherTypeARP) {
		printf("Received ARP\n");
		arp = (struct arp_header*)(packet+sizeof(struct sniff_ethernet));
		if(arp->opcode == arpTypeReply) {
			struct in_addr sender_a;
			    memset(&sender_a, 0, sizeof(struct in_addr));
			    memcpy(&sender_a.s_addr, arp->sender_ip, sizeof(uint32_t));
			for(i=0; i<countRoute; i++) {
				if(sender_a.s_addr == routingTable[i].next_hop_ip) {
					memcpy(routingTable[i].next_hop_macaddress,ethernet->ether_shost,6);
				}
			}
		} else {
			printf("Ignoring ARP request packet\n");
		}

	} else if (ethernet->ether_type == etherTypeIP) {
		//printf("Received IP\n");
		ip = (struct sniff_ip*)(packet+sizeof(struct sniff_ethernet));
		if (!(isPacketForMe(ip->ip_dst.s_addr))) {
			int foundMatch = 0;
			uint32_t gw = 0;
			uint32_t longestPrefix = 0;
			char interfaceOut[10];
			char nextHopMacAddress[6];
			for(i=0; i<countRoute; i++) {
				if (((ip->ip_dst.s_addr & routingTable[i].genmask) == (routingTable[i].des & routingTable[i].genmask)) && (routingTable[i].genmask > longestPrefix)) {
					foundMatch = 1;
					longestPrefix = routingTable[i].genmask;
					gw = routingTable[i].next_hop_ip;
					strcpy(interfaceOut, routingTable[i].inf);
					memcpy(nextHopMacAddress,routingTable[i].next_hop_macaddress,6);
				} 
			}
			if(ip->ip_ttl == 1) {
				struct ip_hdr* ip2 = (struct ip_hdr*)(packet+sizeof(struct sniff_ethernet));
				//if TTL is 1, send ICMP type 11 to the sender
				/* Send ICMP TTL Exceeded*/
				uint8_t* transmitPacket = (uint8_t*)calloc(1500, sizeof(uint8_t));
		
				/* Setup Ethernet Frame */
				struct ethernet_hdr * transmitEthernetFrame = (struct ethernet_hdr*)transmitPacket;
				memcpy(transmitEthernetFrame->ether_dhost,ethernet->ether_shost,6); /* destination ethernet address */
				memcpy(transmitEthernetFrame->ether_shost,ethernet->ether_dhost,6); /* source ethernet address */
				transmitEthernetFrame->ether_type = ethernet->ether_type;	   /* packet type ID */

				/* Setup IP Packet */
				struct ip_hdr* transmitIPHeader = (struct ip_hdr*)(transmitEthernetFrame+1);
				transmitIPHeader->ip_v = 4; /* IPv4 */
				transmitIPHeader->ip_hl = 5; /* 20 bytes */
				transmitIPHeader->ip_tos = 0;
				transmitIPHeader->ip_len = ntohs(transmitIPHeader->ip_hl*4 + sizeof(struct icmp_no_data_hdr)) + ip2->ip_len;
				transmitIPHeader->ip_id = ip2->ip_id;
				transmitIPHeader->ip_off = ip2->ip_off;
				transmitIPHeader->ip_ttl = 64;
				transmitIPHeader->ip_p = 1;
				transmitIPHeader->ip_dst = ip2->ip_src;
				char interfaceOutTTL[10];
				for (i=0; i<interfaceCount; i++) {
					if(memcmp(transmitEthernetFrame->ether_shost,routerInterfaces[i].interface_macaddress,6)==0) {
						transmitIPHeader->ip_src = routerInterfaces[i].interface_ipaddress;
						strcpy(interfaceOutTTL,routerInterfaces[i].interface_name);
						break;
					}
				}

				//transmitIPHeader->ip_src = ;//routerIF->ip;
				transmitIPHeader->ip_sum = cksum(transmitIPHeader, 20);

				/* Generate ICMP Echo Reply */
				struct icmp_hdr* transmitICMPHeader = (struct icmp_hdr*)(transmitIPHeader+1);
				transmitICMPHeader->icmp_type = 11;
				transmitICMPHeader->icmp_code = 0;			
				int payloadSize = ntohs(ip2->ip_len) + sizeof(struct icmp_no_data_hdr);
				memcpy(transmitICMPHeader->data, ip2, 20);
				memcpy(transmitICMPHeader->data + 20, ip2 + 1, ntohs(ip2->ip_len) - 20);
				transmitICMPHeader->icmp_sum = cksum(transmitICMPHeader, payloadSize);
				sendPacket(interfaceOutTTL, transmitIPHeader->ip_dst, transmitPacket);
				return;
			} else {
				if(foundMatch) {
					//ARP cache Miss
					if(nextHopMacAddress[0]==0 && nextHopMacAddress[1]==0 && nextHopMacAddress[2]==0 && nextHopMacAddress[3]==0 && nextHopMacAddress[4]==0 && nextHopMacAddress[5]==0) {
						sendARPpacket(interfaceOut, gw);

					} 
					//ARP cache Hit	
					else {
						printf("Sending to next hop\n");
						
						memcpy(ethernet->ether_dhost,nextHopMacAddress,6); 
						for(i=0; i < interfaceCount; i++) {
							if(strcmp(interfaceOut,routerInterfaces[i].interface_name)==0) {
								memcpy(ethernet->ether_shost,routerInterfaces[i].interface_macaddress,6); 
								break;
							}
						}
						ip->ip_ttl -= 1;
						ip->ip_sum = 0;
						ip->ip_sum = cksum(ip,20);
						sendPacket(interfaceOut, gw, packet);
					}

				} 
			}

		}
	}	
	return;
}

void *main_sniffex(void *devTemp)
{
	char* dev = devTemp;
	char errbuf[PCAP_ERRBUF_SIZE];		/* error buffer */
	pcap_t *handle;				/* packet capture handle */

	struct bpf_program fp;			/* compiled filter program (expression) */
	bpf_u_int32 mask;			/* subnet mask */
	bpf_u_int32 net;			/* ip */
	int num_packets = 10000;	        /* number of packets to capture */

	printf("dev is %s\n",dev);
	if (pcap_lookupnet(dev, &net, &mask, errbuf) == -1) {
		fprintf(stderr, "Couldn't get netmask for device %s: %s\n",
		    dev, errbuf);
		net = 0;
		mask = 0;
	}
	handle = pcap_open_live(dev, SNAP_LEN, 1, 1, errbuf);
	if (handle == NULL) {
		fprintf(stderr, "Couldn't open device %s: %s\n", dev, errbuf);
		exit(EXIT_FAILURE);
	}
	if (pcap_datalink(handle) != DLT_EN10MB) {
		fprintf(stderr, "%s is not an Ethernet\n", dev);
		exit(EXIT_FAILURE);
	}
	pcap_loop(handle, num_packets, got_packet, NULL);
	pcap_freecode(&fp);
	pcap_close(handle);
	return 0;
}

void getInterfaceInfo(struct interface *inf) {
	struct ifreq ifr;
	strcpy(ifr.ifr_name, inf->interface_name);
	int sd = socket(PF_INET, SOCK_DGRAM, 0);
	inf->interface_index = (ioctl(sd, SIOCGIFINDEX, &ifr) == 0) ? ifr.ifr_ifindex : -1;
	(ioctl(sd, SIOCGIFHWADDR, &ifr) == 0) ? memcpy(inf->interface_macaddress, ifr.ifr_hwaddr.sa_data, 6) : memset(inf->interface_macaddress, 0, 6);
	inf->interface_ipaddress = (ioctl(sd, SIOCGIFADDR, &ifr) == 0) ? ((struct sockaddr_in*) &ifr.ifr_addr)->sin_addr.s_addr : 0;
	inf->interface_netmask = (ioctl(sd, SIOCGIFNETMASK, &ifr) == 0) ? ((struct sockaddr_in*) &ifr.ifr_addr)->sin_addr.s_addr : ~0;
	inf->interface_netaddress = inf->interface_ipaddress & inf->interface_netmask;
	close(sd);
}

void readroute(FILE *fd) {
	char buff[1024];
	char temp1[100], temp2[100], temp3[100];
	struct sockaddr_in antelope1,antelope2,antelope3;
	
	while(fgets(buff,1024,fd)) {
		sscanf(buff,"%s %s %s %s", temp1, temp2, temp3, routingTable[countRoute].inf);
		inet_aton(temp1, &antelope1.sin_addr);
		routingTable[countRoute].des = antelope1.sin_addr.s_addr;
		inet_aton(temp2, &antelope2.sin_addr);
		routingTable[countRoute].genmask = antelope2.sin_addr.s_addr;
		inet_aton(temp3, &antelope3.sin_addr);
		routingTable[countRoute].next_hop_ip = antelope3.sin_addr.s_addr;
		countRoute++;
	}
	fclose(fd);
}

int main(int argc, const char * argv[]) {
	char *interfaces,*inf;
	int i;
	char *token;
	FILE *fd;
	pthread_t snf1Thread, snf2Thread, snf3Thread;
    	
	interfaces = strdup(argv[1]);
    	for (i=0; i<strlen(interfaces); i++) {
        	if (interfaces[i]==',') {
			interfaceCount++;
		}
    	}
   	interfaceCount++;
	routerInterfaces = (struct interface *) malloc(interfaceCount * sizeof(struct interface));
	i=0; 
	inf = strdup(interfaces);
	while ((token = strtok(inf, ",")) != NULL) {
        	strcpy(routerInterfaces[i].interface_name, token);
		getInterfaceInfo(&routerInterfaces[i]);
		if (routerInterfaces[i].interface_index != -1) {
		    i++;	
		}
		inf = NULL;
	}

	fd = fopen(argv[2], "r");
	readroute(fd);

	pthread_create(&snf1Thread, 0, main_sniffex, routerInterfaces[0].interface_name);
	pthread_create(&snf3Thread, 0, main_sniffex, routerInterfaces[1].interface_name);
	pthread_join(snf1Thread, NULL);
	pthread_join(snf3Thread, NULL);	
}
