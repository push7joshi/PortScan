#include<iostream>
#include<cstdlib>
#include<cstring>
#define __FAVOR_BSD
#include<stdio.h>
#include<sys/socket.h>
#include<netinet/ip.h>
#include<netinet/tcp.h>
#include<netinet/ip_icmp.h>
#include<arpa/inet.h>
#include<netinet/if_ether.h>
#include<netdb.h>
#include<errno.h>
#include<pcap.h>
#include<string>
#include<ifaddrs.h>
#include<net/if.h>
#include<algorithm>
#ifndef RAW_H
#define RAW_H
#include "raw.h"
#endif
#ifndef   NI_MAXHOST
#define   NI_MAXHOST 1025
#endif

#define RETRIES 3
using namespace std;

struct psd_tcp {
    struct in_addr src;
    struct in_addr dst;
    unsigned char pad;
    unsigned char proto;
    unsigned short tcp_len;
    struct tcphdr tcp;
};

struct ethernet_h {
    unsigned char destMac[6];
    unsigned char srcMac[6];
    unsigned char etherType[2];
};

typedef struct scanSpec{
    ScanType scan;
    short port;
    int seqNum;
}scanObj;

//**************change these to class variables**********//
int timeout = 3000;
int retries = 3;
int seqNum;
//**************change these to class variables**********//


string stringUpper(char * lString) {
    string uString = string(lString);
    transform(uString.begin(), uString.end(), uString.begin(), ::toupper);
    return uString;
}

/* callback function that is passed to pcap_loop(..) and called each time
 * a packet is recieved                                                    */
//Scan obj
void my_callback(u_char* cScan, const struct pcap_pkthdr* pkthdr,const u_char* packet)
{
    struct ip* ipHeader;
    struct tcphdr* tcpHeader;

    ipHeader = (struct ip*)(packet + sizeof(struct ethernet_h));
    struct protoent* protoEntry = getprotobynumber(ipHeader->ip_p);
    string proto;
    if (protoEntry == NULL) {
        cout<<"errProto"<<endl;
    } else {
        proto = stringUpper(protoEntry->p_name);
        cout<<proto<<endl;
    }

    scanObj currScan = *(scanObj *)cScan;

    struct servent * service = getservbyport(htons(currScan.port), protoEntry->p_name);
    string serviceName;
    if(service != NULL)
        serviceName = stringUpper(service->s_name);
    else
        serviceName = "Not found.";

    cout<<"\nIP src:\t";
    char ackIp[30];
    string ipToScan = string(inet_ntop(AF_INET, &(ipHeader->ip_src), ackIp, INET_ADDRSTRLEN));
    cout<<ipToScan<<endl;
    cout<<"\nIP Dest:"<<string(inet_ntop(AF_INET, &(ipHeader->ip_dst), ackIp, INET_ADDRSTRLEN))<<"\n";

    bool isICMP, isTCP;
    if(ipHeader->ip_p == IPPROTO_TCP) isTCP = true;
    if(ipHeader->ip_p == IPPROTO_ICMP) isICMP = true;
    //Display Header
    cout<<"Scanning .."<<endl;
    cout<<"Current Scan: "<<currScan.scan<<endl;
    cout<<"IP Address: "<<ackIp<<"\n";
    cout<<"Open ports:"<<endl;
    cout<<"Port\tService Name\tResults\t\tConclusion"<<endl;
    cout<<"---------------------------------------------------------------------"<<endl;
    //Display Header
    if(isTCP){
        tcpHeader = (struct tcphdr*)(packet + sizeof(struct ip) + sizeof(ethernet_h));
        unsigned char flags = tcpHeader->th_flags;
        unsigned long ack = ntohl(tcpHeader->th_ack);
        unsigned short sport = ntohs(tcpHeader->th_sport);
        cout<<sport<<"\t"<<serviceName<<"\t";
        if(ack == (seqNum + 1)){
            switch(currScan.scan){
                case SYN:
                    if ((flags & TH_SYN) && (flags & TH_ACK)){
                        cout<<"Open\n";
                    } else if(flags & TH_RST){
                        cout<<"Closed\n";
                    } else if(flags & TH_SYN){
                        cout<<"Open\n";
                    } else {
                        cout<<"Closed"<<endl;
                    }
                    cout<<endl;
                    break;
                case ACK:
                    if(flags & TH_RST){
                        cout<<"Unfiltered\n";
                    }
                    break;
                case NUL:
                case FIN:
                case XMAS:
                    if(flags & TH_RST){
                        cout<<"Closed|Unfiltered\n";
                    }
                    break;
            }
        } else {
            switch(currScan.scan){
                case XMAS:
                case NUL:
                case FIN:
                    cout<<"Open|Filtered\n";
                    break;
                case SYN:
                case ACK:
                    cout<<"Filtered\n";
                    break;
            }
        }
    } else if(isICMP){
        // encapsulation for an ICMP packet: (eth(IP(ICMP & user data)))
        struct icmp* icmpHeader = (struct icmp*)(packet + sizeof(ethernet_h) + sizeof(struct ip));
        // ICMP encloses IP header
        struct ip* enclosedIp = (struct ip *)(packet + sizeof(ethernet_h) + sizeof(struct ip) +  8);
        // encloses first 8 bytes of transport header
        struct tcphdr* enclosedTcp = (struct tcphdr *)(packet + sizeof(struct ip) + sizeof(ethernet_h) + 28);

        int enclosedSeqNum = ntohl(enclosedTcp->th_seq);
        if(enclosedSeqNum == seqNum){
            unsigned int type =(unsigned int)icmpHeader->icmp_type;
            unsigned int code =(unsigned int)icmpHeader->icmp_code;

            unsigned short sport = ntohs(enclosedTcp->th_sport);
            cout<<sport<<"\t"<<serviceName<<"\t\t";
            if( type == 3 && (code == 1 || code == 2 || code == 3 || code == 9 || code == 10 || code == 13)){
                cout<<"Filtered\n";
            } else {
                switch(currScan.scan){
                    case XMAS:
                    case NUL:
                    case FIN:
                        cout<<"Open|Filtered\n";
                        break;
                    case SYN:
                    case ACK:
                        cout<<"Filtered\n";
                        break;

                }
            }

        }
        /************************ToDo*****************/
        //Complete this with all codes.
    }
}

//Scan
pcap_t* setupCapture(short port, string ipToScan) {
    int i;
    char *dev;
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* handle;
    struct pcap_pkthdr hdr; // pcap.h
    struct ether_header *eptr; // net/ethernet.h
    struct bpf_program filter;
    bpf_u_int32 maskp; // subnet mask
    bpf_u_int32 netp;

    dev = pcap_lookupdev(errbuf); //get the device to capture packets
    if (dev == NULL) {
        printf("%s\n", errbuf);
        exit(1);
    }

    cout << dev << endl;

    pcap_lookupnet(dev, &netp, &maskp, errbuf); //get the net address and mask

    handle = pcap_open_live(dev, BUFSIZ, 0, timeout, errbuf); //open the device for capture
    if (handle == NULL) {
        printf("pcap_open_live(): %s\n", errbuf);
        exit(1);
    }

    // Set the packet filter

    string filter_str = "icmp or port ";
    char portToScan[5];
    sprintf(portToScan, "%d", ntohs(port));
    filter_str.append(portToScan);
    filter_str.append(" and src host ");
    filter_str.append(ipToScan);
    cout << "The filter expn is :" << filter_str << endl;
    if (pcap_compile(handle, &filter, filter_str.c_str(), 0, netp) == -1) {
        printf("\nError compiling.. quitting");
        exit(2);
    } else {
        cout << "compiled\n" << endl;
    }

    if (pcap_setfilter(handle, &filter) == -1) {
        printf("\nFilter err. Quit");
        exit(2);
    } else {
        cout << "filtered\n" << endl;
    }
    return handle;
}

//Helper
unsigned short in_cksum(unsigned short *addr, int len)

{
    int nleft = len;
    int sum = 0;
    unsigned short *w = addr;
    unsigned short answer = 0;

    while (nleft > 1) {
        sum += *w++;
        nleft -= 2;
    }

    if (nleft == 1) {
        *(unsigned char *) (&answer) = *(unsigned char *) w;
        sum += answer;
    }

    sum = (sum >> 16) + (sum & 0xFFFF);
    sum += (sum >> 16);
    answer = ~sum;
    return (answer);
}
//helper
unsigned short in_cksum_tcp(int src, int dst, unsigned short *addr, int len) {
    struct psd_tcp buf;
    u_short ans;

    memset(&buf, 0, sizeof(buf));
    buf.src.s_addr = src;
    buf.dst.s_addr = dst;
    buf.pad = 0;
    buf.proto = IPPROTO_TCP;
    buf.tcp_len = htons(len);
    memcpy(&(buf.tcp), addr, len);
    ans = in_cksum((unsigned short *) &buf, 12 + len);
    return (ans);
}
//helper
unsigned short csum(unsigned short *buf, int nwords) {
    unsigned long sum;
    for (sum = 0; nwords > 0; nwords--)
        sum += *buf++;
    sum = (sum >> 16) + (sum & 0xffff);
    sum += (sum >> 16);
    return (unsigned short) (~sum);
}
//helper
struct in_addr getMyAddress() {
    struct ifaddrs *ifap, *ifa;
    struct sockaddr_in *sa;
    char addr[NI_MAXHOST];
    int i = getifaddrs(&ifap);
    getifaddrs(&ifap);

    struct sockaddr_in dummy, myAddr;
    socklen_t addr_len = sizeof(myAddr);
    //nameserver for Google
    dummy.sin_addr.s_addr = inet_addr("74.125.225.209");
    dummy.sin_family = AF_INET;
    dummy.sin_port = htons(80);

    int descr = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (descr < 0) {
        cout << "Failed socket create to get IP" << endl;
        exit(EXIT_FAILURE);
    }
    if (connect(descr, (struct sockaddr *) &dummy, sizeof(dummy)) != 0) {
        cout << "Could not connect." << endl;
        exit(EXIT_FAILURE);
    }

    if (getsockname(descr, (struct sockaddr *) &myAddr, &addr_len) != 0) {
        cout << "\nCould not get the IP address!\n" << endl;
        exit(EXIT_FAILURE);
    }

    inet_ntop(AF_INET, &(myAddr.sin_addr.s_addr), addr, INET_ADDRSTRLEN);
    string test = string(addr);
    cout << test << endl;

    for (ifa = ifap; ifa; ifa = ifa->ifa_next) {
        if (((struct sockaddr_in*) ifa->ifa_addr)->sin_addr.s_addr
                == myAddr.sin_addr.s_addr) {

            return myAddr.sin_addr;
        }
    }
}

//Scan
int createTcpPacket(char* packet, int protocol, string ipToScan, ScanType scan, sockaddr_in &stSockAddr)
{
    cout<<"1."<<packet<<endl;
    struct ip *ipHeader   = (struct ip*)packet;
    struct tcphdr *tcpHeader = (struct tcphdr*)((char *)packet + sizeof(struct ip));
    //setup the parameters for a raw packet

    ipHeader->ip_v          = 0x4;
    ipHeader->ip_hl         = 0x5; //5*32 bit words = 20 bytes
    ipHeader->ip_tos        = 0x0;
    ipHeader->ip_len        = sizeof(struct tcphdr) + sizeof(struct ip);
    ipHeader->ip_id         = htonl(54321);//Random number, does not matter
    ipHeader->ip_off        = 0x0;
    ipHeader->ip_ttl        = 255;
    ipHeader->ip_p          = protocol; //Time being, using protocol TCP
    ipHeader->ip_sum        = 0;
    ipHeader->ip_src.s_addr = (getMyAddress()).s_addr;
    ipHeader->ip_dst.s_addr = stSockAddr.sin_addr.s_addr;
    tcpHeader->th_sport     = htons(44748);
    tcpHeader->th_dport     = stSockAddr.sin_port;
    int seqNum              = random();
    tcpHeader->th_seq       = htonl(seqNum); //seqNum;
    tcpHeader->th_x2        = 0;
    tcpHeader->th_ack       = 0;
    tcpHeader->th_off       = sizeof(struct tcphdr)/4; //20 bytes
    tcpHeader->th_win       = htons(32768);
    tcpHeader->th_urp       = 0;
    tcpHeader->th_sum       = 0;

    //set the tcp flag as per the scan type
    switch (scan){
        case SYN:
            tcpHeader->th_flags = TH_SYN;
            break;
        case FIN:
            tcpHeader->th_flags = TH_FIN;
            break;
        case NUL:
            tcpHeader->th_flags = 0x00;
            break;
        case XMAS:
            tcpHeader->th_flags = (TH_FIN | TH_PUSH | TH_URG);
            break;
        case ACK:
            tcpHeader->th_flags = TH_ACK;
            break;
    }

    ipHeader->ip_sum = csum((unsigned short *)packet, ipHeader->ip_len >> 1);
    tcpHeader->th_sum = in_cksum_tcp(ipHeader->ip_src.s_addr, ipHeader->ip_dst.s_addr, (unsigned short *)tcpHeader, sizeof(struct tcphdr));
    return seqNum;
}

//helper
bool isAlive(string ipToScan){
    struct sockaddr_in sa;
    sa.sin_family = AF_INET;
    sa.sin_port = htons(80);
    sa.sin_addr.s_addr = inet_addr(ipToScan.c_str());
    socklen_t sLen = sizeof(sa);
    char host[1024];
    const sockaddr* sAddr = (sockaddr*)&sa;
    if(getnameinfo(sAddr, sizeof(sa), host, sizeof(host), NULL, 0, NI_NAMEREQD)){
        return false;
    } else {
        return true;
    }
}

//Scan
void packetSendRecv(string ipToScan, short port, ScanType scan)
{
    //helper
    bool liveHost = isAlive(ipToScan);
    if(!liveHost){
        cout<<"Could not reach host. It is possibly down or a wrong IP!"<<endl;
        exit(EXIT_FAILURE);
    }
    int socketFD = socket (PF_INET, SOCK_RAW, IPPROTO_TCP);
    if(socketFD < 0){
        cout<<strerror(errno)<<endl;
        exit(EXIT_FAILURE);
    }

    char destAddr[INET_ADDRSTRLEN];
    struct sockaddr_in stSockAddr;

    memset(&stSockAddr, 0, sizeof(stSockAddr));

    stSockAddr.sin_family = AF_INET;
    stSockAddr.sin_port = htons(port);
    stSockAddr.sin_addr.s_addr = inet_addr(ipToScan.c_str());

    cout<<ipToScan<<endl;

    char buffer[4096]; /* single packets are usually not bigger than 8192 bytes */
    memset(buffer, 0, 4096);

    int seqNum = createTcpPacket(buffer, IPPROTO_TCP, ipToScan, scan, stSockAddr);

    //calling iphdrincl
    int one = 1;
    int i = setsockopt(socketFD, IPPROTO_IP, IP_HDRINCL, &one, sizeof(one));
    if (i < 0){
        cout<<"Cannot set socket options\n";
    }

    cout<<"Scanning IP "<<ipToScan<<"..."<<endl;
    pcap_t *handle = setupCapture(stSockAddr.sin_port, ipToScan);
    while(1){
        if(sendto(socketFD, buffer, sizeof(struct ip) + sizeof(struct tcphdr), 0, (struct sockaddr *) &stSockAddr, sizeof(stSockAddr)) < 0){
            cout<<"\n\n\nError sending packet data\n";
            cout<<errno<<endl<<strerror(errno);
            exit(EXIT_FAILURE);
        } else {/*
                   pcap_pkthdr pkt_header;
                   const u_char* packet = pcap_next(handle, &pkt_header);
                   if(packet != NULL){
                   my_callback(pkt_header, packet, scan, port);
                   break;
                   }
                   else{
                   cout<<"NULL Packet"<<endl;
                   break;*/
            scanObj currScan{scan, port};
            int dispatch_msg = pcap_dispatch(handle, 1, my_callback, (u_char *)&currScan);
            //cout<<"dispatch msg: "<<dispatch_msg<<"\n";
            if(dispatch_msg  == -1){
                cout<<"errr"<<endl;
                return;
            } else if(dispatch_msg > 0){
                cout<<"closing\n";
                pcap_close(handle);
                return;
            }else if(dispatch_msg == 0){
                cout<<"time out\n";
                if(retries > 0){
                    cout<<"retrying.... No of retries left"<<retries<<"\n";
                    retries--;
                    continue;
                }else{
                    cout<<"unable to get connection after all the retries allowed\n";
                    return;
                }
            }
        }
        }
    }
/*
    int main(int argc, char* argv[]){
        if(argc != 2){
            cout<<"Usage:"<<endl<<"raw [s/r] [ip]";
            exit(EXIT_FAILURE);
        }
        char sendOrRecv = *argv[1];

        //            string ipToScan = "149.165.180.113";
        string ipToScan = "129.79.247.87";
        //            string ipToScan = "129.79.242.127";
        //            string ipToScan = "50.129.81.224";
        // string ipToScan = "10.1.1.1";
        //ToDo
        packetSendRecv(ipToScan, 111, SYN);
        return 0;
    }*/
