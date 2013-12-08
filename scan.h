#ifndef SCAN_H
#define SCAN_H

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
#include<vector>
#include "helpers.h"

using namespace std;

enum ScanType{
    SYN=0,
    FIN=2,
    NUL=1,
    XMAS=3,
    ACK=4,
    UDP=5
};

struct ethernet_h {
    unsigned char destMac[6];
    unsigned char srcMac[6];
    unsigned char etherType[2];
};

typedef struct scanSpec{
    ScanType scan;
    short port;
}scanObj;

int timeout = 3000;
int retries = 3;

class Scan{
    public:
        void ScanJob(string ip, unsigned short Port, vector<ScanType> stScan){
            ipToScan = ip;
            port = Port;
            scanVector = stScan;
        }

        string ipToScan;
        unsigned short port;
        vector<ScanType> scanVector;
        int seqNum;
        pcap_t* capDesc;
        ScanType cScan;

        void runTcpScan();
        void runUdpScan();

    private:
        void createTcpPacket(char* packet, sockaddr_in &stSockAddr);
        pcap_t* setupCapture();
        static void my_callback(u_char* scanObj, const struct pcap_pkthdr* pkthdr,const u_char* packet);
};

#endif

