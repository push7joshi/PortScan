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
#include<netinet/udp.h>
#include<netdb.h>
#include<errno.h>
#include<pcap.h>
#include<string>
#include<ifaddrs.h>
#include<net/if.h>
#include<algorithm>
#include<vector>
#include<map>
#include<list>
#include<pthread.h>
#include "helpers.h"
#include "service.h"

using namespace std;

const static int scanTypeLength = 6;

enum ScanType{
    SYN=0,
    FIN=2,
    NUL=1,
    XMAS=3,
    ACK=4,
    UDP=5
};

const static int portStateLength = 12;

enum PortState{
    Open = 0,
    OpenAndUnfiltered,
    OpenAndFiltered,
    OpenORFiltered,
    Closed,
    Filtered,
    Unfiltered,
    ClosedAndUnfiltered,
    CloedAndFiltered,
    NoResposne,
    Unknown,
    NotUsed
};

struct ethernet_h {
    unsigned char destMac[6];
    unsigned char srcMac[6];
    unsigned char etherType[2];
};

inline string strScanType(ScanType scan){
    switch(scan){
        case SYN:
            return "SYN";
        case FIN:
            return "FIN";
        case NUL:
            return "NUL";
        case XMAS:
            return "XMAS";
        case ACK:
            return "ACK";
        case UDP:
            return "UDP";
    }
}

inline string strPortState(PortState state){
    switch(state){
        case Open:
            return "Open";
        case OpenAndUnfiltered:
            return "OpenAndUnfiltered";
        case OpenAndFiltered:
            return "OpenAndFiltered";
        case OpenORFiltered:
            return "OpenAndFiltered";
        case Closed:
            return "Closed";
        case Filtered:
            return "Filtered";
        case Unfiltered:
            return "Unfiltered";
        case ClosedAndUnfiltered:
            return "ClosedAndUnfiltered";
        case CloedAndFiltered:
            return "CloedAndFiltered";
        case NoResposne:
            return "NoResposne";
        case Unknown:
            return "Unknown";
        case NotUsed:
            return "NotUsed";
    }
}

struct DNS_packet {
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

static vector<int> knownServices{ 22,24,25,43,80,110,143,587};

class Scan{
    public:
        Scan(){
            for(int i=0; i<6;i++){
                scanResult = Unknown;
            }
        }

        string ipToScan;
        unsigned short port;
        //map<ScanType, PortState> scanResult;
        ScanType cScan;
        PortState scanResult;
        int seqNum;
        pcap_t* capDesc;

        void runTcpScan();
        void runUdpScan();

    private:
        void createTcpPacket(char* packet, sockaddr_in &stSockAddr);
        pcap_t* setupCapture();
        static void my_callbackUDP(u_char* scanObj, const struct pcap_pkthdr* pkthdr,const u_char* packet);
        static void my_callback(u_char* scanObj, const struct pcap_pkthdr* pkthdr,const u_char* packet);
        void createUDPPacket(char* packet, sockaddr_in &stSockAddr);
};

static vector<Scan> scanArray;
//<ip, <port, <scan, result>>>
static map<string, list< pair<short, vector<PortState> > > > resultMap;

#endif

