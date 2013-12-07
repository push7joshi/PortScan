#ifndef SCAN_H
#define SCAN_H

#include<iostream>
#include<vector>

using namespace std;
enum ScanType{
    SYN=0,
    FIN=2,
    NUL=1,
    XMAS=3,
    ACK=4,
    UDP=5
};

class ScanJob{
    public:
        void ScanJob(string ip, unsigned short Port, vector<ScanType> stScan){
            ipToScan = ip;
            port = Port;
            scanVector = stScan;
        };

        string ipToScan;
        unsigned short port;
        vector<ScanType> scanVector;
        int seqNum;
        pcap_t* capDesc;
        //packetSendRecv to be renamed to:
        void runTcpScan();
        //packetSendRecvUdp to be renamed to:
        void runUdpScan();
    private:
        int createTcpPacket(char* packet, int protocol, string ipToScan, ScanType scan, sockaddr_in &stSockAddr);
        pcap_t* setupCapture(short port, string ipToScan);
        void my_callback(u_char* cScan, const struct pcap_pkthdr* pkthdr,const u_char* packet)
};

#endif
