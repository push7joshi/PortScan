#include<iostream>
#include<cstdlib>
#include<cstring>

#include<stdio.h>
#include<sys/socket.h>
#include<netinet/ip.h>
#include<netinet/tcp.h>
#include<arpa/inet.h>
#include<netdb.h>

using namespace std;

const int Port = 25;


struct sockaddr_in sockSetup(int& socketFD){
    socketFD = socket (PF_INET, SOCK_RAW, IPPROTO_TCP);
    char destAddr[INET_ADDRSTRLEN];
    struct sockaddr_in stSockAddr;

    memset(&stSockAddr, 0, sizeof(stSockAddr));

    stSockAddr.sin_family = AF_INET;
    stSockAddr.sin_port = htons(Port);
    stSockAddr.sin_addr.s_addr = inet_addr(INADDR_ANY);

    //Bind the socket
    if( bind(socketFD, (struct sockaddr*)&socketFD, sizeof(socketFD)) == -1){
        cout<<"Failed to bind the server"<<endl;
        exit(EXIT_FAILURE);
    }
    return stSockAddr;
}


unsigned short csum(unsigned short *buf, int nwords)
{
    unsigned long sum;
    for (sum = 0; nwords > 0; nwords--)
        sum += *buf++;
    sum = (sum >> 16) + (sum & 0xffff);
    sum += (sum >> 16);
    return ~sum;
}


int main(void){

    int socketFD;
    struct sockaddr_in stSockAddr = sockSetup(socketFD);
    char buffer[8192]; /* single packets are usually not bigger than 8192 bytes */


    struct ip *ipHeader   = (struct ip*)buffer;
    struct tcphdr *tcpHeader = (struct tcphdr*)buffer + sizeof(struct ip);

    //setup the parameters for a raw packet

    ipHeader->ip_v          = 4;
    ipHeader->ip_hl         = 5; //5*32 bit words = 20 bytes
    ipHeader->ip_tos        = 0;
    ipHeader->ip_len        = sizeof(struct tcphdr) + sizeof(struct ip);
    ipHeader->ip_id         = htonl(123);;//Random number, does not matter
    ipHeader->ip_off        = 0;
    ipHeader->ip_ttl        = 64;
    ipHeader->ip_p          = 6; //Time being, using protocol TCP
    ipHeader->ip_sum        = csum((unsigned short *)ipHeader, sizeof(struct ip));
    ipHeader->ip_src.s_addr = inet_addr("1.2.22.2");
    ipHeader->ip_dst.s_addr = stSockAddr.sin_addr.s_addr;
    tcpHeader->sport        = htons(1234);
    tcpHeader->dport        = htons(Port);
    tcpHeader->seq          = rand()%100+1;
    tcpHeader->ack          = 0;
    tcpHeader->th_off       = 0;
    tcpHeader->th_flags     = TH_SYN;
    tcpHeader->th_win       = htonl(32768);
    tcpHeader->th_urp       = 0;

    //calling iphdrincl
    int one = 1;
    if (setsockopt(socketFD, IPPROTO_IP, IP_HDRINCL, &one, sizeof(one)) < 0){
        cout<<"Cannot set socket options\n";   
    }

    while(1){
        
    }

}
