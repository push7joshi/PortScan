#include "scan.h"
#include <pthread.h>
int timeout = 3000;
int retries = 3;

/* callback function that is passed to pcap_loop(..) and called each time
 * a packet is recieved                                                    */
//Scan
void Scan::my_callback(u_char* scanObj, const struct pcap_pkthdr* pkthdr,const u_char* packet)
{
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

    Scan *mySelf = (Scan *)scanObj;
    string serviceName;

	cout<<"working1223"<<endl;
    if(find(knownService.begin(), knownService.end(), ntohs(mySelf->port)) != knownService.end()){
        serviceName = servChk(mySelf->ipToScan, ntohs(mySelf->port));
    } else {
        struct servent * service = getservbyport(mySelf->port, protoEntry->p_name);
        if(service != NULL)
            serviceName = stringUpper(service->s_name);
        else
            serviceName = "Not found.";
    }
	cout<<"working"<<endl;
    cout<<"\nIP src:\t";
    char ackIp[30];
    string ipToScan = string(inet_ntop(AF_INET, &(ipHeader->ip_src), ackIp, INET_ADDRSTRLEN));
    cout<<ipToScan<<endl;
    cout<<"\nIP Dest:"<<string(inet_ntop(AF_INET, &(ipHeader->ip_dst), ackIp, INET_ADDRSTRLEN))<<"\n";

    bool isICMP, isTCP;
    if(ipHeader->ip_p == IPPROTO_TCP) isTCP = true;
    if(ipHeader->ip_p == IPPROTO_ICMP) isICMP = true;
    //Display Header
    cout<<"Scanning .."<<endl;
    cout<<"Current Scan: "<<mySelf->cScan<<endl;
    cout<<"IP Address: "<<ackIp<<"\n";
    cout<<"Open ports:"<<endl;
    cout<<"Port\tService Name\tResults\t\tConclusion"<<endl;
    cout<<"---------------------------------------------------------------------"<<endl;
    //Display Header
    if(isTCP){
        tcpHeader = (struct tcphdr*)(packet + sizeof(struct ip) + sizeof(ethernet_h));
        unsigned char flags = tcpHeader->th_flags;
        unsigned long ack = ntohl(tcpHeader->th_ack);
        unsigned short sport = ntohs(tcpHeader->th_sport);
        cout<<sport<<"\t"<<serviceName<<"\t";
        if(ack == (mySelf->seqNum + 1)){
            switch(mySelf->cScan){
                case SYN:
                    if ((flags & TH_SYN) && (flags & TH_ACK)){
                        cout<<"Open\n";
                    } else if(flags & TH_RST){
                        cout<<"Closed\n";
                    } else if(flags & TH_SYN){
                        cout<<"Open\n";
                    } else {
                        cout<<"Closed"<<endl;
                    }
                    cout<<endl;
                    break;
                case ACK:
                    if(flags & TH_RST){
                        cout<<"Unfiltered\n";
                    }
                    break;
                case NUL:
                case FIN:
                case XMAS:
                    if(flags & TH_RST){
                        cout<<"Closed|Unfiltered\n";
                    }
                    break;
            }
        } else {
            switch(mySelf->cScan){
                case XMAS:
                case NUL:
                case FIN:
                    cout<<"Open|Filtered\n";
                    break;
                case SYN:
                case ACK:
                    cout<<"Filtered\n";
                    break;
            }
        }
    } else if(isICMP){
        // encapsulation for an ICMP packet: (eth(IP(ICMP & user data)))
        struct icmp* icmpHeader = (struct icmp*)(packet + sizeof(ethernet_h) + sizeof(struct ip));
        // ICMP encloses IP header
        struct ip* enclosedIp = (struct ip *)(packet + sizeof(ethernet_h) + sizeof(struct ip) +  8);
        // encloses first 8 bytes of transport header
        struct tcphdr* enclosedTcp = (struct tcphdr *)(packet + sizeof(struct ip) + sizeof(ethernet_h) + 28);

        int enclosedSeqNum = ntohl(enclosedTcp->th_seq);
        if(enclosedSeqNum == mySelf->seqNum){
            unsigned int type =(unsigned int)icmpHeader->icmp_type;
            unsigned int code =(unsigned int)icmpHeader->icmp_code;

            unsigned short sport = ntohs(enclosedTcp->th_sport);
            cout<<sport<<"\t"<<serviceName<<"\t\t";
            if( type == 3 && (code == 1 || code == 2 || code == 3 || code == 9 || code == 10 || code == 13)){
                cout<<"Filtered\n";
            } else {
                switch(mySelf->cScan){
                    case XMAS:
                    case NUL:
                    case FIN:
                        cout<<"Open|Filtered\n";
                        break;
                    case SYN:
                    case ACK:
                        cout<<"Filtered\n";
                        break;

                }
            }

        }
        /************************ToDo*****************/
        //Complete this with all codes.
    }
}

//Scan
pcap_t* Scan::setupCapture(){
    int i;
    char *dev;
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* handle;
    struct pcap_pkthdr hdr; // pcap.h
    struct ether_header *eptr; // net/ethernet.h
    struct bpf_program filter;
    bpf_u_int32 maskp; // subnet mask
    bpf_u_int32 netp;

    dev = pcap_lookupdev(errbuf); //get the device to capture packets
    if (dev == NULL) {
        printf("%s\n", errbuf);
        pthread_exit(NULL);
        //exit(1);
    }

    cout << dev << endl;

    pcap_lookupnet(dev, &netp, &maskp, errbuf); //get the net address and mask

    handle = pcap_open_live(dev, BUFSIZ, 0, timeout, errbuf); //open the device for capture
    if (handle == NULL) {
        printf("pcap_open_live(): %s\n", errbuf);
        pthread_exit(NULL);
        //exit(1);
    }

    // Set the packet filter

    string filter_str = "icmp or port ";
    char portToScan[5];
    sprintf(portToScan, "%d", ntohs(port));
    filter_str.append(portToScan);
    filter_str.append(" and src host ");
    filter_str.append(ipToScan);
    cout << "The filter expn is :" << filter_str << endl;
    if (pcap_compile(handle, &filter, filter_str.c_str(), 0, netp) == -1) {
        printf("\nError compiling.. quitting");
        pthread_exit(NULL);
//        exit(2);
    } else {
        cout << "compiled\n" << endl;
    }

    if (pcap_setfilter(handle, &filter) == -1) {
        printf("\nFilter err. Quit");
        pthread_exit(NULL);
        //        exit(2);
    } else {
        cout << "filtered\n" << endl;
    }
    return handle;
}

//Scan
void Scan::createTcpPacket(char* packet, sockaddr_in &stSockAddr)
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
    ipHeader->ip_p          = IPPROTO_TCP;
    ipHeader->ip_sum        = 0;
    ipHeader->ip_src.s_addr = (getMyAddress()).s_addr;
    ipHeader->ip_dst.s_addr = stSockAddr.sin_addr.s_addr;
    tcpHeader->th_sport     = htons(44748);
    tcpHeader->th_dport     = stSockAddr.sin_port;
    seqNum                  = random();
    tcpHeader->th_seq       = htonl(seqNum);
    tcpHeader->th_x2        = 0;
    tcpHeader->th_ack       = 0;
    tcpHeader->th_off       = sizeof(struct tcphdr)/4; //20 bytes
    tcpHeader->th_win       = htons(32768);
    tcpHeader->th_urp       = 0;
    tcpHeader->th_sum       = 0;

    //set the tcp flag as per the scan type
    switch (cScan){
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

//Scan
void Scan::runTcpScan()
{
    //helper
	cout<<"running tcp:"<<ipToScan<<"\t"<<ntohs(port)<<"\n";
    bool liveHost = isAlive(ipToScan);
    if(!liveHost){
        cout<<"Could not reach host. It is possibly down or a wrong IP!"<<endl;
        pthread_exit(NULL);
//        exit(EXIT_FAILURE);
    }
    int socketFD = socket (PF_INET, SOCK_RAW, IPPROTO_TCP);
    if(socketFD < 0){
        cout<<strerror(errno)<<endl;
        pthread_exit(NULL);
//        exit(EXIT_FAILURE);
    }

    char destAddr[INET_ADDRSTRLEN];
    struct sockaddr_in stSockAddr;

    memset(&stSockAddr, 0, sizeof(stSockAddr));

    stSockAddr.sin_family = AF_INET;
    stSockAddr.sin_port = port;
    stSockAddr.sin_addr.s_addr = inet_addr(ipToScan.c_str());

    char buffer[4096]; /* single packets are usu-+6ally not bigger than 4096 bytes */
    memset(buffer, 0, 4096);

    //Scan
    createTcpPacket(buffer, stSockAddr);

    //calling iphdrincl
    int one = 1;
    int i = setsockopt(socketFD, IPPROTO_IP, IP_HDRINCL, &one, sizeof(one));
    if (i < 0){
        cout<<"Cannot set socket options\n";
    }
    //Scan
    pcap_t *handle = setupCapture();
    while(1){
    	cout<<"will scan tcp:"<<ipToScan<<"\t"<<ntohs(port)<<"\n";
        if(sendto(socketFD, buffer, sizeof(struct ip) + sizeof(struct tcphdr), 0, (struct sockaddr *) &stSockAddr, sizeof(stSockAddr)) < 0){
            cout<<"\n\n\nError sending packet data\n";
            cout<<errno<<endl<<strerror(errno);
            return;
            //exit(EXIT_FAILURE);
        } else {
        	cout<<"done scanning will call tcp:"<<ipToScan<<"\t"<<ntohs(port)<<"\n";

            int dispatch_msg = pcap_dispatch(handle, 1, my_callback, (u_char *)this);
            //cout<<"dispatch msg: "<<dispatch_msg<<"\n";
            if(dispatch_msg  == -1){
                cout<<"errr"<<endl;
                return;
            } else if(dispatch_msg > 0){
                cout<<"closing\n";
                pcap_close(handle);
                return;
            }else if(dispatch_msg == 0){
                cout<<"time out\n";
                if(retries > 0){
                    cout<<"retrying.... No of retries left"<<retries<<ntohs(port)<<"\n";
                    retries--;
                    continue;
                }else{
                    cout<<"unable to get connection after all the retries allowed\n";
                    return;
                }
            }
        }
    }
}

