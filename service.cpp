#include "service.h"
#include<pthread.h>
using namespace std;

//Connects to live host<ipToScan> that
//showed port<port> was open in the scan
int connectToHost(string ipToScan, int port){
    struct sockaddr_in sa;
    memset(&sa, 0, sizeof(sa));
    sa.sin_family = AF_INET;
    sa.sin_port = htons(port);
    sa.sin_addr.s_addr = inet_addr(ipToScan.c_str());

    int clientSock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if(clientSock < 0){
        cout<<"Error creating socket to get service."<<endl;
        pthread_exit(NULL);
//        exit(EXIT_FAILURE);
    }
    const struct sockaddr* sAddr = (struct sockaddr *)&sa;
    if(connect(clientSock, sAddr, sizeof(sa)) < 0){
        return -1;
    }
    return clientSock;
}


string httpCheck(int clientSock){
    char getRequest[100];
    strcpy(getRequest,"GET / HTTP/1.1\r\nHOST: 129.79.247.86\r\n\r\n");
    //sendto(int socket, char data, int dataLength, flags, destinationAddress, int destinationStructureLength)
    int bytes_sent = send(clientSock, getRequest, strlen(getRequest), 0);
    char rMsg[1024];
    int msgLen;
    while ((msgLen = recv(clientSock, rMsg, 1000, 0)) > 0) {
        string recvMsg(rMsg);
        if (recvMsg.find("HTTP/1.1") != string::npos) {
            return "HTTP 1.1 in use";
        } else if (recvMsg.find("HTTP/1.0") != string::npos) {
            return "HTTP 1.0 in use";
        } else {
            return "HTTP not running";
        }
    }
}

string smtpCheck(int clientSock, string ipToScan){
    char rMsg[1024];
    memset(rMsg, 0, sizeof(rMsg));
    int msgLen = recv(clientSock, rMsg, 1000, 0);
    rMsg[msgLen] = '\0';
    char getRequest[25];
    strcpy(getRequest,"EHLO\n\n");
    int requestLen = 5 + strlen(ipToScan.c_str());
    int bytes_sent = send(clientSock, getRequest, strlen(getRequest), 0);
    msgLen = recv(clientSock, rMsg, 1000, 0);
    cout<<rMsg<<endl;
    string recvMsg(rMsg);

    if (recvMsg.find("250") != string::npos) {
        return "ESMTP in use";
    } else if (recvMsg.find("500") != string::npos) {
        return "SMTP in use";
    }
}


string sshCheck(int clientSock){
    char rMsg[1024];
    memset(rMsg, 0, sizeof(rMsg));
    int msgLen = recv(clientSock, rMsg, 1024, 0);
    return string(rMsg);
}

string popCheck(int clientSock){
    char rMsg[1024];
    memset(rMsg, 0, sizeof(rMsg));
    int msgLen = recv(clientSock, rMsg, 1024, 0);
    cout<<rMsg<<endl;
    if(msgLen > 0){
        return "POP in use";
    } else {
        return string();
    }
}

string imapCheck(int clientSock){
    char rMsg[1024];
    memset(rMsg, 0, sizeof(rMsg));
    int msgLen = recv(clientSock, rMsg, 1024, 0);
    if (msgLen < 0){
        cout<<"Service Detection: Error while recieving."<<endl;
    }
    string resMsg(rMsg);
    size_t pos = resMsg.find("IMAP");
    if(pos != string::npos){
        return resMsg.substr(pos, 10);
    } else {
        return string();
    }
}

string whoCheck(int clientSock, string ipToScan){
    char getRequest[20];
    char rMsg[1024];
    strcpy(getRequest,"google.com\n\n");
    //    strcat(getRequest, ipToScan.c_str());
    int requestLen = 5 + strlen(ipToScan.c_str());
    int bytes_sent = send(clientSock, &getRequest, 4, 0);
    int msgLen = recv(clientSock, rMsg, 1000, 0);
    if(msgLen > 0){
        return "WHOIS running";
    } else {
        return string();
    }
}

string privCheck(int clientSock){
    char rMsg[1024];
    memset(rMsg, 0, sizeof(rMsg));
    int msgLen = recv(clientSock, rMsg, 1024, 0);
    cout<<rMsg<<endl;
    string service(rMsg);
    if(service.find("mailserver") != string::npos){
        return "Private mail sys in use";
    } else {
        return string();
    }
}

string servChk(string ipToScan, unsigned short port){
    string result;
    int clientSock = connectToHost(ipToScan, port);
    if(clientSock < 0){
        return string("Unknown");
    }
    switch(port){
        case 80:
            return httpCheck(clientSock);
        case 22:
            return sshCheck(clientSock);
        case 24:
            return privCheck(clientSock);
        case 25:
        case 587:
            return smtpCheck(clientSock, ipToScan);
        case 43:
            return whoCheck(clientSock, ipToScan);
        case 110:
            return popCheck(clientSock);
        case 143:
            return imapCheck(clientSock);
        default:
            return "Unknown";
    }
}
/*
int main(int argc, char* argv[]){
    unsigned short port = atoi(argv[1]);
    cout<<servChk("129.79.247.87", port)<<endl;
}*/

