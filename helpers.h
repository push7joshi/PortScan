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
#ifndef HELPERS_H
#define HELPERS_H

using namespace std;

struct psd_tcp {
    struct in_addr src;
    struct in_addr dst;
    unsigned char pad;
    unsigned char proto;
    unsigned short tcp_len;
    struct tcphdr tcp;
};

string stringUpper(char * lString);
struct in_addr getMyAddress();
bool isAlive(string ipToScan);
struct in_addr getMyAddress();
unsigned short csum(unsigned short *buf, int nwords);
unsigned short in_cksum_tcp(int src, int dst, unsigned short *addr, int len);
unsigned short in_cksum(unsigned short *addr, int len);

#endif

