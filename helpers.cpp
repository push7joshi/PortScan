#include<iostream>
#include "helpers.h"

using namespace std;

string stringUpper(char * lString) {
    string uString = string(lString);
    transform(uString.begin(), uString.end(), uString.begin(), ::toupper);
    return uString;
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

