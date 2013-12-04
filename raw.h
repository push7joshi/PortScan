#include<pcap.h>
using namespace std;

enum ScanType{
    SYN=0,
    FIN=2,
    NUL=1,
    XMAS=3,
    ACK=4,
    UDP=5
};

void packetSendRecv(char sendOrRecv, string ipToScan, short port, ScanType scan);

struct in_addr getMyAddress() ;
unsigned short csum(unsigned short *buf, int nwords);
unsigned short in_cksum(unsigned short *addr, int len);
pcap_t* setupCapture(int port, string ipToScan, short Port);
void packetSendRecvUDP(char sendOrRecv, string ipToScan, short Port);
string stringUpper(char * lString);
