#include<iostream>
#include<cstdlib>
#include<cstring>
#define __FAVOR_BSD
#include<stdio.h>
#include<sys/socket.h>
#include<netinet/ip.h>
#include<netinet/tcp.h>
#include<netinet/udp.h>
#include<netinet/ip_icmp.h>
#include<arpa/inet.h>
#include<netinet/if_ether.h>
#include<netdb.h>
#include<errno.h>
#include<pcap.h>
#include<string>
#include<ifaddrs.h>
#include<net/if.h>
#ifndef RAW_H
#define RAW_H
#include "raw.h"
#endif
#ifndef   NI_MAXHOST
#define   NI_MAXHOST 1025
#endif

using namespace std;

struct psd_udp {
	struct in_addr src;
	struct in_addr dst;
	unsigned char pad;
	unsigned char proto;
	unsigned short udp_len;
	struct udphdr udp;
};

struct ethernet_h {
	unsigned char destMac[6];
	unsigned char srcMac[6];
	unsigned char etherType[2];
};

struct DNS_packet {
	/*	+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
	 |                     ID                        |
	 +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
	 |QR| Opcode    |AA|TC|RD|RA| Z      |  RCODE    |
	 +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
	 |                   QDCOUNT                     |
	 +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
	 |                   ANCOUNT                     |
	 +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
	 |                   NSCOUNT                     |
	 +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
	 |                   ARCOUNT                     |
	 +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
	 */
	unsigned short id;
	unsigned char rd :1; // recursion desired
	unsigned char tc :1; // truncated message
	unsigned char aa :1; // authoritive answer
	unsigned char opcode :4; // purpose of message
	unsigned char qr :1; // query/response flag
	unsigned char rcode :4; // response code
	unsigned char cd :1; // checking disabled
	unsigned char ad :1; // authenticated data
	unsigned char z :1; // its z! reserved
	unsigned char ra :1;
	unsigned short qn_count;
	unsigned short ans_count;
	unsigned short ns_count;
	unsigned short ar_count;
	char query[1];
	unsigned short qn_type;
	unsigned short qn_class;
};
struct q_param {
	unsigned short qn_type;
	unsigned short qn_class;
};
/* callback function that is passed to pcap_loop(..) and called each time
 * a packet is recieved                                                    */
void my_callbackUDP(u_char *useless, const struct pcap_pkthdr* pkthdr,
		const u_char* packet, short Port) {
	if (packet != NULL) {
		cout << "Pkt Length:" << pkthdr->len << endl;
		cout << "Hdr Length:" << pkthdr->caplen << endl;
		struct ip* ipHeader;
		struct udphdr* udphdr;
		struct icmphdr* icmpHeader;

		ipHeader = (struct ip*) (packet + sizeof(struct ethernet_h));
		struct protoent* protoEntry = getprotobynumber(ipHeader->ip_p);
		string proto;
		if (protoEntry == NULL) {
			cout << "errProto" << endl;
		} else {
			proto = stringUpper(protoEntry->p_name);
			cout << proto << endl;
		}

		cout << Port << endl;
		struct servent * service = getservbyport(htons(Port),
				protoEntry->p_name);

		cout << "\nIP src:\t";
		char ackIp[30];
		string ipToScan = string(
				inet_ntop(AF_INET, &(ipHeader->ip_src), ackIp,
						INET_ADDRSTRLEN));
		cout << ipToScan << endl;
		cout << "\nIP Dest:"
				<< string(
						inet_ntop(AF_INET, &(ipHeader->ip_dst), ackIp,
								INET_ADDRSTRLEN)) << "\n";

		bool isICMP, isUDP;
		if (ipHeader->ip_p == IPPROTO_UDP)
			isUDP = true;
		if (ipHeader->ip_p == IPPROTO_ICMP)
			isICMP = true;
		//Display Header
		cout << "Scanning .." << endl;
		cout << "IP Address: " << ackIp << "\n";
		cout << "Open ports:" << endl;
		cout << "Port\tService Name\tResults\t\tConclusion" << endl;
		cout
				<< "---------------------------------------------------------------------"
				<< endl;
		string service_name = "";
		if (service != NULL) {
			service_name = service->s_name;
		}
		cout << service_name << "\t" << Port << "\t";
		//Display Header
		if (isUDP) {
			cout << "Open";
		} else if (isICMP) {
			// encapsulation for an ICMP packet: (eth(IP(ICMP & user data)))
			struct icmp* icmpHeader = (struct icmp*) (packet
					+ sizeof(ethernet_h) + sizeof(struct ip));
			// ICMP encloses IP header
			struct ip* enclosedIp = (struct ip *) (packet + sizeof(ethernet_h)
					+ sizeof(struct ip) + 8);
			// encloses first 8 bytes of transport header
			unsigned int type = (unsigned int) icmpHeader->icmp_type;
			unsigned int code = (unsigned int) icmpHeader->icmp_code;
			cout << type << "-=-=-=-=-=-=-=\t" << code; //1, 2, 9, 10, or 13

			if (type == 3
					&& (code == 1 || code == 2 || code == 9 || code == 10
							|| code == 13)) {
				cout << "Filtered\n";
			} else if (type == 3 && code == 3) {
				cout << "Closed\n";
			}
		}

	} else {

		cout << "Pkt Length:" << 0 << endl;
		cout << "Hdr Length:" << 0 << endl;
		cout << "open|filtered";
	}
	cout << "im done BH----------------------------";

}

unsigned short in_cksum_udp(int src, int dst, unsigned short *addr, int len) {
	struct psd_udp buf;
	u_short ans;

	memset(&buf, 0, sizeof(buf));
	buf.src.s_addr = src;
	buf.dst.s_addr = dst;
	buf.pad = 0;
	buf.proto = IPPROTO_UDP;
	buf.udp_len = htons(len);
	memcpy(&(buf.udp), addr, len);
	ans = in_cksum((unsigned short *) &buf, 12 + len);
	return (ans);
}

void createUDPPacket(char* packet, string ipToScan, sockaddr_in &stSockAddr) {
	struct ip *ipHeader = (struct ip*) packet;
	struct udphdr *udpHeader = (struct udphdr*) ((char *) packet
			+ sizeof(struct ip));
	//setup the parameters for a raw packet

	ipHeader->ip_v = 0x4;
	ipHeader->ip_hl = 0x5; //5*32 bit words = 20 bytes
	ipHeader->ip_tos = 0x0;
	ipHeader->ip_len = sizeof(struct udphdr) + sizeof(struct ip);
	ipHeader->ip_id = htonl(54321); //Random number, does not matter
	ipHeader->ip_off = 0x0;
	ipHeader->ip_ttl = 255;
	ipHeader->ip_p = IPPROTO_UDP; //Time being, using protocol TCP
	ipHeader->ip_sum = 0;
	ipHeader->ip_src.s_addr = (getMyAddress()).s_addr; //inet_addr(hostIP.c_str()); //"129.79.247.87";//(getMyAddress()).s_addr;
	ipHeader->ip_dst.s_addr = stSockAddr.sin_addr.s_addr;

	udpHeader->uh_sport = htons(44748);
	udpHeader->uh_dport = stSockAddr.sin_port;
	udpHeader->uh_sum = 0;
	udpHeader->uh_ulen = htons(8);

	ipHeader->ip_sum = csum((unsigned short *) packet, ipHeader->ip_len >> 1);
	udpHeader->uh_sum = 0;
	/*in_cksum_udp(ipHeader->ip_src.s_addr,
	 ipHeader->ip_dst.s_addr, (unsigned short *) udpHeader,
	 sizeof(struct udphdr));
	 */
	if (ntohs(stSockAddr.sin_port) == 53) {
		struct DNS_packet *dns = (struct DNS_packet*) ((char *) packet
				+ sizeof(struct ip) + sizeof(struct udphdr));
		dns->id = (unsigned short) htons(1234);
		dns->qr = 0; //This is a query
		dns->opcode = 0; //This is a standard query
		dns->aa = 0; //Not Authoritative
		dns->tc = 0; //This message is not truncated
		dns->rd = 0; //Recursion Desired
		dns->ra = 0; //Recursion not available! hey we dont have it (lol)
		dns->z = 0;
		dns->ad = 0;
		dns->cd = 0;
		dns->rcode = 0;
		dns->qn_count = htons(1); //we have only 1 question
		dns->ans_count = 0;
		dns->ar_count = 0;
		dns->ns_count = 0;
		dns->query[0] = '\0';
		//dns->query[1] = '\0';
		dns->qn_class = htons(1);
		dns->qn_type = htons(1);
		//cout << "goalazo ----->" << strlen((char*)dns->query) << "\n";

		/*dns->query = (unsigned char *)query.c_str();
		 dns->qn_class = htons(1);
		 dns->qn_type = htons(1);*/
		udpHeader->uh_ulen = htons(8 + sizeof(DNS_packet));
		ipHeader->ip_len = ntohs(udpHeader->uh_ulen) + sizeof(struct ip);
		cout << "len" << ipHeader->ip_len << "\n";
		cout << "len udp ----+++" << ntohs(udpHeader->uh_ulen) << "\n";
	}
}

void packetSendRecvUDP(string ipToScan, short Port) {
	cout << "performing udp scan\n";
	int socketFD = socket(PF_INET, SOCK_RAW, IPPROTO_UDP);
	if (socketFD < 0) {
		cout << strerror(errno) << endl;
		return;
	}

	char destAddr[INET_ADDRSTRLEN];
	struct sockaddr_in stSockAddr;

	memset(&stSockAddr, 0, sizeof(stSockAddr));

	stSockAddr.sin_family = AF_INET;
	stSockAddr.sin_port = htons(Port);
	stSockAddr.sin_addr.s_addr = inet_addr(ipToScan.c_str());

	cout << ipToScan << endl;

	char buffer[4096]; /* single packets are usually not bigger than 8192 bytes */
	memset(buffer, 0, 4096);

	createUDPPacket(buffer, ipToScan, stSockAddr);
	int one = 1;
	int i = setsockopt(socketFD, IPPROTO_IP, IP_HDRINCL, &one, sizeof(one));
	if (i < 0) {
		cout << "Cannot set socket options\n";
	}
	cout << "Scanning IP " << ipToScan << "..." << endl;
	pcap_t *handle = setupCapture(stSockAddr.sin_port, ipToScan);
	int retries = 3;
	while (retries > 1) {
		retries -= 3;
		short size = sizeof(struct ip) + sizeof(udphdr) + sizeof(DNS_packet);
		//char * p = (char *) buffer + sizeof(struct ip) + sizeof(udphdr)
		+sizeof(DNS_packet);
		//cout << "query---00000\t" << *p << "\n";
		if (sendto(socketFD, buffer, size, 0, (struct sockaddr *) &stSockAddr,
				sizeof(stSockAddr)) < 0) {
			cout << "\n\n\nError sending packet data\n";
			cout << errno<<endl << strerror(errno);
			exit(EXIT_FAILURE);
		} else {
			pcap_pkthdr pkt_header;
			const u_char* packet = pcap_next(handle, &pkt_header);
			my_callbackUDP(NULL, &pkt_header, packet, Port);

		}
	}
}

//void packetSendRecvUDPaddasdadsd(char sendOrRecv, string ipToScan,
//		ScanType scan) {
//	int socketFD = socket(PF_INET, SOCK_RAW, IPPROTO_UDP);
//	if (socketFD < 0) {
//		cout << strerror(errno) << endl;
//		exit(EXIT_FAILURE);
//	}
//
//	char destAddr[INET_ADDRSTRLEN];
//	struct sockaddr_in stSockAddr;
//
//	memset(&stSockAddr, 0, sizeof(stSockAddr));
//
//	stSockAddr.sin_family = AF_INET;
//	stSockAddr.sin_port = htons(Port);
//	stSockAddr.sin_addr.s_addr = inet_addr(ipToScan.c_str());
//
//	cout << ipToScan << endl;
//
//	char buffer[4096]; /* single packets are usually not bigger than 8192 bytes */
//	memset(buffer, 0, 4096);
//
//	if (sendOrRecv == 's') {
//
//		createTcpPacket(buffer, IPPROTO_TCP, ipToScan, scan, stSockAddr);
//
//		//calling iphdrincl
//		int one = 1;
//		int i = setsockopt(socketFD, IPPROTO_IP, IP_HDRINCL, &one, sizeof(one));
//		if (i < 0) {
//			cout << "Cannot set socket options\n";
//		}
//		while (1) {
//			if (1 < 0) {
//				cout << "\n\n\nError sending packet data\n";
//				cout << errno<<endl << strerror(errno);
//				exit(EXIT_FAILURE);
//			} else {
//				cout << "sending out data\n";
//				//Capture ack from host being scanned.
//				char scannedIp[30];
//				string ipToScan1 = string(
//						inet_ntop(AF_INET, &(stSockAddr.sin_addr), scannedIp,
//								INET_ADDRSTRLEN));
//				cout
//						<< "================================================================================";
//				capturePacket(1, stSockAddr.sin_port, ipToScan1, sendOrRecv,
//						scan);
//				cout
//						<< "--------------------------------------------------------------------------------";
//				capturePacket(1, stSockAddr.sin_port, ipToScan1, sendOrRecv,
//						scan);
//				cout
//						<< "++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++";
//				capturePacket(1, stSockAddr.sin_port, ipToScan1, sendOrRecv,
//						scan);
//
//			}
//		}
//	} else {
//		cout << "Waiting for data" << endl;
//		if (recvfrom(socketFD, buffer, sizeof(buffer), 0,
//				(struct sockaddr*) &stSockAddr, sizeof(stSockAddr) < 0)) {
//			cout << "Error recieving data\n";
//			exit(EXIT_FAILURE);
//		} else {
//			cout << "This is the buffer:\n" << buffer;
//		}
//	}
//}
//
//int capturePacket(int numPackets, int port, string ipToScan, char sendOrRecv,
//		ScanType scan) {
//	int i;
//	char *dev;
//	char errbuf[PCAP_ERRBUF_SIZE];
//	pcap_t* handle;
//	u_char *packet;
//	struct pcap_pkthdr hdr; // pcap.h
//	struct ether_header *eptr; // net/ethernet.h
//	struct bpf_program filter;
//	bpf_u_int32 maskp; // subnet mask
//	bpf_u_int32 netp;
//
//	dev = pcap_lookupdev(errbuf); //get the device to capture packets
//	if (dev == NULL) {
//		printf("%s\n", errbuf);
//		exit(1);
//	}
//
//	pcap_lookupnet(dev, &netp, &maskp, errbuf); //get the net address and mask
//
//	handle = pcap_open_live(dev, BUFSIZ, 0, 10000, errbuf); //open the device for capture
//	if (handle == NULL) {
//		printf("pcap_open_live(): %s\n", errbuf);
//		exit(1);
//	}
//
//// Set the packet filter
//	string filter_str = "src host ";
//	filter_str.append(ipToScan);
//	filter_str.append(" and port ");
//	char portToScan[5];
//	sprintf(portToScan, "%d", Port);
//	filter_str.append(portToScan);
//	cout << "The filter expn is :" << filter_str << endl;
//	char fltr_str[1000];
//	sprintf(fltr_str, filter_str.c_str());
//	if (pcap_compile(handle, &filter, fltr_str, 0, netp) == -1) {
//		printf("\nError compiling.. quitting");
//		exit(2);
//	} else {
//		cout << "compiled\n" << endl;
//	}
//
//	if (pcap_setfilter(handle, &filter) == -1) {
//		printf("\nFilter err. Quit");
//		exit(2);
//	} else {
//		cout << "filtered\n" << endl;
//	}
//	cout << "numpacks:" << numPackets << endl;
//
//	/* Grab a packet */
//	int socketFD = socket(PF_INET, SOCK_RAW, IPPROTO_UDP);
//	if (socketFD < 0) {
//		cout << strerror(errno) << endl;
//		exit(EXIT_FAILURE);
//	}
//
//	char destAddr[INET_ADDRSTRLEN];
//	struct sockaddr_in stSockAddr;
//
//	memset(&stSockAddr, 0, sizeof(stSockAddr));
//
//	stSockAddr.sin_family = AF_INET;
//	stSockAddr.sin_port = htons(Port);
//	stSockAddr.sin_addr.s_addr = inet_addr(ipToScan.c_str());
//
//	cout << ipToScan << endl;
//
//	char buffer[4096]; /* single packets are usually not bigger than 8192 bytes */
//	memset(buffer, 0, 4096);
//
//	if (sendOrRecv == 's') {
//
//		createUDPPacket(buffer, ipToScan, stSockAddr);
//
//		//calling iphdrincl
//		int one = 1;
//		int i = setsockopt(socketFD, IPPROTO_IP, IP_HDRINCL, &one, sizeof(one));
//		if (i < 0) {
//			cout << "Cannot set socket options\n";
//		}
//		while (1) {
//			if (sendto(socketFD, buffer,
//					sizeof(struct ip) + sizeof(struct udphdr), 0,
//					(struct sockaddr *) &stSockAddr, sizeof(stSockAddr)) < 0) {
//				cout << "\n\n\nError sending packet data\n";
//				cout << errno<<endl << strerror(errno);
//				exit(EXIT_FAILURE);
//			} else {
//				cout << "sending out data\n";
//				//Capture ack from host being scanned.
//				char scannedIp[30];
//				string ipToScan1 = string(
//						inet_ntop(AF_INET, &(stSockAddr.sin_addr), scannedIp,
//								INET_ADDRSTRLEN));
//				break;
//			}
//		}
//	} else {
//		cout << "Waiting for data" << endl;
//		if (recvfrom(socketFD, buffer, sizeof(buffer), 0,
//				(struct sockaddr*) &stSockAddr, sizeof(stSockAddr) < 0)) {
//			cout << "Error recieving data\n";
//			exit(EXIT_FAILURE);
//		} else {
//			cout << "This is the buffer:\n" << buffer;
//		}
//	}
//	pcap_dispatch(handle, 1, my_callback, packet);
////packet = pcap_dispatch()//(handle, &hdr);
//	for (i = 0; i < 30; i++) {
//		printf("%x:", *(packet + i));
//	}
//	/* Print its length */
//	printf("Jacked a packet with length of [%d]\n", hdr.len);
//	/* And close the session */
//	pcap_close(handle);
//	return (0);
//}
/*
 int main(int argc, char* argv[]) {
 if (argc != 2) {
 cout << "Usage:" << endl << "raw [s/r] [ip]";
 exit(EXIT_FAILURE);
 }
 char sendOrRecv = *argv[1];

 string ipToScan = "129.79.247.5";
 //string ipToScan = "129.79.247.87";
 //string ipToScan = "149.160.201.190";
 //    string ipToScan = "50.129.81.224";
 packetSendRecv(sendOrRecv, ipToScan, SYN);
 return 0;
 }

 */
