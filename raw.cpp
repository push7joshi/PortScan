#include<iostream>
#include<cstdlib>
#include<cstring>
#define __FAVOR_BSD
#include<stdio.h>
#include<sys/socket.h>
#include<netinet/ip.h>
#include<netinet/tcp.h>
#include<arpa/inet.h>
#include<netinet/if_ether.h>
#include<netdb.h>
#include<errno.h>
#include<pcap.h>
#include<string>
#include<ifaddrs.h>
#include<net/if.h>
#include<algorithm>

#ifndef   NI_MAXHOST
#define   NI_MAXHOST 1025
#endif

using namespace std;

int Port = 80;
const string hostIP = "129.79.247.86";

struct psd_tcp {
    struct in_addr src;
    struct in_addr dst;
    unsigned char pad;
    unsigned char proto;
    unsigned short tcp_len;
    struct tcphdr tcp;
};

struct ethernet_h{
    unsigned char destMac[6];
    unsigned char srcMac[6];
    unsigned char etherType[2];
};

enum ScanType{
    SYN,
    FIN,
    NUL,
    XMAS,
    ACK,
    UDP
};

inline string stringUpper(char * lString){
    string uString = string (lString);
    transform(uString.begin(), uString.end(), uString.begin(), :: toupper);
    return uString;
}


/* callback function that is passed to pcap_loop(..) and called each time
 * a packet is recieved                                                    */
void my_callback(u_char *useless,const struct pcap_pkthdr* pkthdr,const u_char*
        packet)
{
    cout<<"Pkt Length:"<<pkthdr->len<<endl;
    cout<<"Hdr Length:"<<pkthdr->caplen<<endl;
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

    cout<<Port<<endl;
    struct servent * service = getservbyport(htons(Port), protoEntry->p_name);
    cout<<stringUpper(service->s_name)<<endl;

    cout<<"\nIP src:\t";
    char ackIp[30];
    string ipToScan = string(inet_ntop(AF_INET, &(ipHeader->ip_src), ackIp, INET_ADDRSTRLEN));
    cout<<ipToScan<<endl;
    cout<<"\nIP Dest:"<<string(inet_ntop(AF_INET, &(ipHeader->ip_dst), ackIp, INET_ADDRSTRLEN))<<"\n";
}


pcap_t* setupCapture(int port, string ipToScan)
{
    int i;
    char *dev;
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* handle;
    struct pcap_pkthdr hdr;     // pcap.h
    struct ether_header *eptr;  // net/ethernet.h
    struct  bpf_program filter;
    bpf_u_int32 maskp;          // subnet mask
    bpf_u_int32 netp;

    dev = pcap_lookupdev(errbuf); //get the device to capture packets
    if(dev == NULL)
    { printf("%s\n",errbuf); exit(1); }

    cout<<dev<<endl;

    pcap_lookupnet(dev,&netp,&maskp,errbuf); //get the net address and mask

    handle = pcap_open_live(dev, BUFSIZ, 0, 0, errbuf); //open the device for capture
    if(handle == NULL)
    { printf("pcap_open_live(): %s\n",errbuf); exit(1); }

    // Set the packet filter
    string filter_str = "src host ";
    filter_str.append(ipToScan);
    filter_str.append(" and port ");
    char portToScan[5];
    sprintf(portToScan, "%d", Port);
    filter_str.append(portToScan);
    cout<<"The filter expn is :"<<filter_str<<endl;
    char fltr_str[1000];
    sprintf(fltr_str, filter_str.c_str());
    if(pcap_compile(handle, &filter, fltr_str, 0, netp) == -1){
        printf("\nError compiling.. quitting");
        exit(2);
    } else {
        cout<<"compiled\n"<<endl;
    }

    if(pcap_setfilter(handle, &filter) == -1){
        printf("\nFilter err. Quit");
        exit(2);
    } else {
        cout<<"filtered\n"<<endl;
    }
    return handle;
}
//const u_char* packet = pcap_next(handle, &hdr);
/*const u_char** data;
  pcap_pkthdr *pk_hdr = &hdr;
  int retValue = pcap_next_ex(handle, &pk_hdr , data);

  if(retValue < 0)
  exit(EXIT_FAILURE);*/

/*if(packet == NULL){
  cout<<string(pcap_geterr(handle))<<endl;
  pcap_perror(handle, "This is the err");
  cout<<"none"<<endl;
  exit(EXIT_FAILURE);
  }*/


//printf("Jacked a packet with length of [%d]\n", hdr.len);
//
int capturePacket(pcap_t *handle){
    if(pcap_loop(handle, 1, my_callback, NULL) < 0){
        cout<<"errr"<<endl;
        exit(1);
    }
    /* 
       struct ip *ipHeader;
       struct tcphdr *tcpHeader;

       ipHeader = (struct ip*)(packet+ sizeof(struct ethernet_h));

       cout<<"\nIP src:\t";
       char ackIp[30];
       string ipToScan1 = string(inet_ntop(AF_INET, &(ipHeader->ip_src), ackIp, INET_ADDRSTRLEN));
       cout<<ipToScan1<<endl;
       cout<<"\nIP Dest:"<<string(inet_ntop(AF_INET, &(ipHeader->ip_dst), ackIp, INET_ADDRSTRLEN))<<"\n";
       */
    pcap_close(handle);
    return(0);
}

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

unsigned short in_cksum_tcp(int src, int dst, unsigned short *addr, int len)
{
    struct psd_tcp buf;
    u_short ans;

    memset(&buf, 0, sizeof(buf));
    buf.src.s_addr = src;
    buf.dst.s_addr = dst;
    buf.pad = 0;
    buf.proto = IPPROTO_TCP;
    buf.tcp_len = htons(len);
    memcpy(&(buf.tcp), addr, len);
    ans = in_cksum((unsigned short *)&buf, 12 + len);
    return (ans);
}

unsigned short csum(unsigned short *buf, int nwords)
{
    unsigned long sum;
    for(sum=0; nwords>0; nwords--)
        sum += *buf++;
    sum = (sum >> 16) + (sum &0xffff);
    sum += (sum >> 16);
    return (unsigned short)(~sum);
}

struct in_addr getMyAddress(){
    struct ifaddrs *ifap, *ifa;
    struct sockaddr_in *sa;
    char addr[NI_MAXHOST];
    int i = getifaddrs(&ifap);
    getifaddrs (&ifap);

    struct sockaddr_in dummy, myAddr;
    socklen_t addr_len = sizeof(myAddr);
    dummy.sin_addr.s_addr = inet_addr("74.125.225.209");
    dummy.sin_family = AF_INET;
    dummy.sin_port = htons(80);

    int descr = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if(descr < 0){ 
        cout<<"Failed socket create to get IP"<<endl;
        exit(EXIT_FAILURE);
    }   
    if(connect(descr, (struct sockaddr *)&dummy, sizeof(dummy)) != 0){ 
        cout<<"Could not connect."<<endl;
        exit(EXIT_FAILURE);
    }   

    if(getsockname(descr, (struct sockaddr *)&myAddr, &addr_len) != 0){ 
        cout<<"\nCould not get the IP address!\n"<<endl;
        exit(EXIT_FAILURE);
    }   

    inet_ntop(AF_INET, &(myAddr.sin_addr.s_addr), addr, INET_ADDRSTRLEN);
    string test = string(addr);
    cout<<test<<endl;

    for (ifa = ifap; ifa; ifa = ifa->ifa_next) {
        if(((struct sockaddr_in*)ifa->ifa_addr)->sin_addr.s_addr == myAddr.sin_addr.s_addr){

            return myAddr.sin_addr;
        }
    }
}

void createTcpPacket(char* packet, int protocol, string ipToScan, ScanType scan, sockaddr_in &stSockAddr)
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
    ipHeader->ip_src.s_addr = (getMyAddress()).s_addr;   //inet_addr(hostIP.c_str()); //"129.79.247.87";//(getMyAddress()).s_addr;
    ipHeader->ip_dst.s_addr = stSockAddr.sin_addr.s_addr;
    tcpHeader->th_sport     = htons(44748);
    tcpHeader->th_dport     = stSockAddr.sin_port;
    tcpHeader->th_seq       = random();
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
}

void packetSendRecv(char sendOrRecv, string ipToScan, ScanType scan)
{
    int socketFD = socket (PF_INET, SOCK_RAW, IPPROTO_TCP);
    if(socketFD < 0){
        cout<<strerror(errno)<<endl;
        exit(EXIT_FAILURE);
    }

    char destAddr[INET_ADDRSTRLEN];
    struct sockaddr_in stSockAddr;

    memset(&stSockAddr, 0, sizeof(stSockAddr));

    stSockAddr.sin_family = AF_INET;
    stSockAddr.sin_port = htons(Port);
    stSockAddr.sin_addr.s_addr = inet_addr(ipToScan.c_str());

    cout<<ipToScan<<endl;

    char buffer[4096]; /* single packets are usually not bigger than 8192 bytes */
    memset(buffer, 0, 4096);

    if(sendOrRecv == 's'){

        createTcpPacket(buffer, IPPROTO_TCP, ipToScan, scan, stSockAddr);

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
            } else {
                if(pcap_loop(handle, 1, my_callback, NULL) < 0){
                    cout<<"errr"<<endl;
                    exit(1);
                } else {
                    pcap_close(handle);
                }
            }       
        }
    }
}

int main(int argc, char* argv[]){
    if(argc != 2){
        cout<<"Usage:"<<endl<<"raw [s/r] [ip]";
        exit(EXIT_FAILURE);
    }
    char sendOrRecv = *argv[1];

    //    string ipToScan = "129.79.247.5";
    string ipToScan = "129.79.247.87";
    //string ipToScan = "149.160.201.190";
    //    string ipToScan = "50.129.81.224";
    packetSendRecv(sendOrRecv, ipToScan, SYN);
    return 0;
}


