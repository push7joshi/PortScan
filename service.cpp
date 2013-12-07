#include<iostream>
#include<cstdlib>
#include<cstring>
#include<stdio.h>
#include<vector>
#include <getopt.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <fstream>
#include<string>
#ifndef RAW_H

#define RAW_H
#endif

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
        exit(EXIT_FAILURE);
    }
    const struct sockaddr* sAddr = (struct sockaddr *)&sa;
    if(connect(clientSock, sAddr, sizeof(sa)) < 0){
        cout<<"Could not connect to the host for service."<<endl;
        exit(EXIT_FAILURE);
    }
    cout<<"Connected"<<endl;
    return clientSock;
}


string httpCheck(string ipToScan){
    int clientSock = connectToHost(ipToScan, 80);
    char getRequest[20];
    strcpy(getRequest,"GET / HTTP/1.1\r\nHOST: 129.79.247.86\r\n\r\n");
    //sendto(int socket, char data, int dataLength, flags, destinationAddress, int destinationStructureLength)
    int bytes_sent = send(clientSock, getRequest, strlen(getRequest), 0);
    char rMsg[10240];
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

string smtpCheck(string ipToScan){
    int clientSock = connectToHost(ipToScan, 25);
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


string sshCheck(string ipToScan){
    int clientSock = connectToHost(ipToScan, 22);
    char rMsg[1024];
    memset(rMsg, 0, sizeof(rMsg));
    int msgLen = recv(clientSock, rMsg, 1024, 0);
    return string(rMsg);
}

string popCheck(string ipToScan){
    int clientSock = connectToHost(ipToScan, 110);
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

string imapCheck(string ipToScan){
    int clientSock = connectToHost(ipToScan, 143);
    char rMsg[1024];
    memset(rMsg, 0, sizeof(rMsg));
    int msgLen = recv(clientSock, rMsg, 1024, 0);
    cout<<rMsg<<endl;
    if(msgLen > 0){
        return "IMAP in use";
    } else {
        return string();
    }
}

string whoCheck(string ipToScan){
    int clientSock = connectToHost(ipToScan, 43);

    char getRequest[20];
    char rMsg[1024];
    strcpy(getRequest,"google.com\n\n");
    //    strcat(getRequest, ipToScan.c_str());
    int requestLen = 5 + strlen(ipToScan.c_str());
    cout<<getRequest<<endl;
    int bytes_sent = send(clientSock, &getRequest, 4, 0);
    int msgLen = recv(clientSock, rMsg, 1000, 0);
    cout<<rMsg<<endl;
    if(msgLen > 0){
        return "WHOIS running";
    } else {
        return string();
    }
}

string privCheck(string ipToScan){
    int clientSock = connectToHost(ipToScan, 24);
    char rMsg[1024];
    memset(rMsg, 0, sizeof(rMsg));
    int msgLen = recv(clientSock, rMsg, 1024, 0);
    string service(rMsg);
    if(service.find("mailserver") != string::npos){
        return "Private mail sys in use";
    } else {
        return string();
    }
}

int main(void){
   string result = popCheck("129.79.247.87");
    cout<<"Check:"<<result<<endl;
}
