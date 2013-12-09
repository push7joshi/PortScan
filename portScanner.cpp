#include<iostream>
#include<cstdlib>
#include<cstring>
#include<stdio.h>
#include<vector>
#include <getopt.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <fstream>
#include <math.h>
#include<pthread.h>
#include "service.h"
#include "scan.h"
#include "helpers.h"

using namespace std;

pthread_mutex_t cs_mutex = PTHREAD_RECURSIVE_MUTEX_INITIALIZER_NP;

pthread_mutex_t arrMutex = PTHREAD_RECURSIVE_MUTEX_INITIALIZER_NP;
int counter = 0;

struct ps_args_t {
    vector<int> ports;
    vector<string> ip;
    int num_threads;
    bool scans[6];
    string prefix;
    vector<int>::iterator port_iterator;
    vector<string>::iterator ip_iterator;
};

void usage() {
    cout << "--help <display invocation options>\n";
    cout << "--ports <ports to scan>. Default all ports from 1-1024\n";
    cout << "--ip <IP address to scan>\n";
    cout << "--preﬁx <IP preﬁx to scan>.\n";
    cout << "--ﬁle <ﬁle name containing IP addresses to scan>\n";
    cout << "--speedup <parallel threads to use>\n";
    cout << "--scan < one or more scans>\n";

}
void get_ports(vector<int> &ports, char* string) {
    ports = vector<int>();
    int prev = 0;
    char * next;
    while (1) {
        int position = strtol(string, &next, 10);
        cout << "--------------------->" << position << "\n";
        //next++;
        if (position == 0) {
            break;
        } else {
            //cout << "next" << *next << "\n";
            if (*next == '-') {
                prev = position;
            } else {
                if (prev == 0) {
                    ports.push_back(position);
                } else {
                    int i;
                    for (i = prev; i <= position; i++) {
                        int j = i;
                        ports.push_back(j);
                    }
                    prev = 0;
                }
            }
            string = next + 1;
        }

    }
}
void read_ip_from_file(vector<string> &ip_list, char* file_name) {
    fstream in;
    string str;
    in.open(file_name);
    if (!in) {
        cout << "Error: Can't open the file named data.txt.\n";
        exit(1);
    }
    getline(in, str);
    while (in) {
        in_addr iaddr;
        inet_pton(AF_INET, str.c_str(), &iaddr);
        ip_list.push_back(str);
        getline(in, str);
    }
}

void parse_prefixes(ps_args_t &ps_args) {
    string prefix = ps_args.prefix;
    ps_args.ip = vector<string>();
    //  /long mask;
    //long ip_num = 0;
    char delim = '/';
    char * ip_char = strtok((char *) prefix.c_str(), &delim);
    char * delim_char = strtok(NULL, &delim);
    int ip_int = 0;
    char temp[INET_ADDRSTRLEN];

    unsigned int host_len = strtol(delim_char, NULL, 10);
    //printf("0-0-0-0-0----%x\n", host_len);
    unsigned int range = (unsigned int) pow(2, host_len);
    unsigned int subnet_mask = (unsigned int) pow(2, 32) - range + 1; //    unsigned int range = (unsigned int) pow(2, range);(int) pow(2, host_len);
    //cout << "hostlen,----subnet mask" << host_len << "-=======" << subnet_mask << "\n";

    inet_pton(AF_INET, ip_char, &ip_int);
    //cout<<"b------->"<<ip_int<<"\n";
    ip_int = ntohl(ip_int);

    unsigned int ip_after_mask = ip_int & subnet_mask;

    for (int i = 0; i < range; i++) {
        //cout<<"b------->"<<ip_int<<"\n";
        ip_after_mask += 1;
        //cout<<"b------->"<<ip_int<<"\n";
        int ip_to_be_converted = htonl(ip_after_mask);
        //cout<<"b------->"<<ip_int<<"\n";
        inet_ntop(AF_INET, &ip_to_be_converted, temp, INET_ADDRSTRLEN);
        string s = temp;
        ps_args.ip.push_back(s);
        //cout << "a-=-=-=-=-=-===-=>" << s << "\n";

    }

    cout << ip_char << "|||||" << delim_char << "\n";
    //cout<<"|_+_+_+_+_+|"<<"\n";
    return;
    /*  char * next;
        char *curr = (char *) prefix.c_str();
        ip_num = strtol(curr, &next, 10)*(pow(2,24));
        curr = next+1;

        ip_num += strtol(curr, &next, 10)*(pow(2,16));
        curr = next+1;
        ip_num += strtol(curr, &next, 10)*(pow(2,8));
        curr = next+1;
        ip_num += strtol(curr, &next, 10);
        curr = next+1;
        ip_char[4] = strtol(curr, &next, 10);
    //curr = next;
    //printf("prefix: %d|%d|%d|%d|%d\n", ip_char[0],ip_char[1],ip_char[2],ip_char[3],ip_char[4],ip_char[5]);
    */
}
void get_default_ports(vector<int> &ports) {
    cout << "default ports ++++++++++++++";
    ports = vector<int>();
    for (int i = 0; i <= 1024; i++) {
        ports.push_back(i);
    }
}
void parse_args(ps_args_t &ps_args, int argc, char * argv[]) {
    ps_args.ip = vector<string>();
    ps_args.num_threads = 0;
    ps_args.prefix = string();
    int port_set = 0;
    int scans_flag = 0;
    memset(ps_args.scans, 0, sizeof(ps_args.scans));
    //ps_args.scans = vector<string>();
    /*
       --help <display invocation options>. Example: ”./portScanner --help”.
       --ports <ports to scan>. Example: ”./portScanner --ports 1,2,3-5”.
       --ip <IP address to scan>. Example: ”./portScanner--ip 127.0.0.1”.
       --preﬁx <IP preﬁx to scan>. Example: ”./portScanner--preﬁx 127.143.151.123/24”.
       --ﬁle <ﬁle name containing IP addresses to scan>. Example: ”./portScanner --ﬁle ﬁlename.txt”.
       --speedup <parallel threads to use>. Example: ”./portScanner --speedup 10”.
       --scan <one or more scans>. Example: ”./portScanner --scan SYN NULL FIN XMAS”
       */
    static struct option long_options[] = { { "help", no_argument, NULL, 'h' },
        { "ports", required_argument, NULL, 'p' }, { "ip",
                                                       required_argument, NULL, 'i' }, { "prefix",
                                                           required_argument, NULL, 'r' }, { "file", required_argument,
                                                               NULL, 'f' }, { "speedup", required_argument, NULL, 't' }, {
                                                                   "scan", required_argument, NULL, 's' }, };
    int ch;
    int option_index = 0;
    string opt;
    int curr = 0;
    while ((ch = getopt_long_only(argc, argv, "i:f:r:p:t:s:h", long_options,
                    &option_index)) != -1) {
        switch (ch) {
            case 'h': //help
                usage();
                //cout << "h\n";
                break;
            case 'i': //help
                //usage(stdout);
                in_addr iaddr;
                inet_pton(AF_INET, optarg, &iaddr);
                ps_args.ip.push_back(optarg);
                //          cout << "i " << ps_args.ip[0].s_addr << "\n";
                break;
            case 'f': //help
                //usage(stdout);
                //cout<<"akjdnmakldas\n";
                opt = optarg;
                read_ip_from_file(ps_args.ip, optarg);
                //      cout<<ps_args.ip[0].s_addr<<"\n";
                //  cout<<ps_args.ip[1].s_addr<<"\n";
                break;

            case 'r': //help
                //usage(stdout);
                ps_args.prefix = optarg;
                parse_prefixes(ps_args);

                //cout << "prfix " << ps_args.prefix << "\n";
                break;
            case 'p': //help
                //usage(stdout);

                cout << "included ports" << optarg << "\n";
                get_ports(ps_args.ports, optarg);
                port_set = 1;
                //          cout << "adasdasdassdas : " << ps_args.ports[1] << "\n";
                /*for (vector<int>::iterator it = ps_args.ports.begin();
                  it != ps_args.ports.end(); ++it) {
                  cout << " " << *it << " \n";
                  }*/
                break;
            case 't': //help
                //usage(stdout);
                //ps_args.num_threads = 0;
                cout<<"setting threads\n";
                ps_args.num_threads = strtol(optarg, NULL, 10);
                //cout << "\nnum threads " << ps_args.num_threads << "\t" << optarg << "\n";
                break;
            case 's': //help
                //usage(stdout);
                //cout << "dadafsd\n";
                scans_flag = 1;
                /*          char UDP_C[] = "UDP\0";
                            char FIN_C[] = "FIN_C\0";
                            char TCP_SYN_C[] = "SYN\0";
                            char XMAS_C[] = "XMAS\0";
                            char TCP_ACK_C[] = "ACK\0";
                            char TCP_NULL_C[] = "NULL\0";
                            */
                curr = optind - 1;
                for (; curr < argc && argv[curr] != "-"; curr++) {
                    scans_flag = 1;
                    opt = argv[curr];
                    if (opt == "UDP") {
                        ps_args.scans[UDP] = 1;
                    } else if (opt == "FIN") {
                        ps_args.scans[FIN] = 1;
                    } else if (opt == "SYN") {
                        ps_args.scans[SYN] = 1;
                    } else if (opt == "XMAS") {
                        ps_args.scans[XMAS] = 1;
                    } else if (opt == "ACK") {
                        ps_args.scans[ACK] = 1;
                    } else if (opt == "NUL") {
                        ps_args.scans[NUL] = 1;
                    }
                }
                break;
            default:
                break;
        }
    }
    if (port_set == 0) {
        get_default_ports(ps_args.ports);
    }
    if (scans_flag == 0) {
        for (int i = 0; i < 6; i++) {
            ps_args.scans[i] = 1;
        }
    }
}
;

void get_next_ip_port(ps_args_t &ps_args, string &ip, int &port) {
    //synchronized
    pthread_mutex_lock(&cs_mutex);
    ip = "finish";
    port = -1;
    while (1) {
        if (ps_args.port_iterator == ps_args.ports.end()) {
            if (ps_args.ip_iterator == ps_args.ip.end()) {
                //end of queue..... no more jobs
                cout << "end of ip list\n";
                ps_args.port_iterator = ps_args.ports.end();
                pthread_mutex_unlock(&cs_mutex);
                return;
            }
            ps_args.ip_iterator++;
            cout << "end of port list\n";
            ps_args.port_iterator = ps_args.ports.begin();
            if (ps_args.ip_iterator == ps_args.ip.end()) {
                //end of queue..... no more jobs
                cout << "end of ip list\n";
                ps_args.port_iterator = ps_args.ports.end();
                pthread_mutex_unlock(&cs_mutex);
                return;
            }
        } else {
            //cout << "asdasdasd\n";
            ip = *(ps_args.ip_iterator);
            port = *(ps_args.port_iterator);
            ps_args.port_iterator++;
            ps_args.ip_iterator;
            pthread_mutex_unlock(&cs_mutex);
            return;
        }
        pthread_mutex_unlock(&cs_mutex);
    }
    //end of synchronized
}

void * perform_scan(void * args) {
    ps_args_t* ps_args = ((ps_args_t *) args);
    string ip = "ip";
    int port = 0;
    while (ip != "finish" && port != -1) {
        get_next_ip_port(*ps_args, ip, port);
        if (ip == "finish" && port == -1) {
            return NULL;
        }
        for (int s = 0; s < 6; s++) {
            if (ps_args->scans[s] == 1) {
                Scan sc = Scan();
                sc.ipToScan = ip;
                sc.port = htons(port);
                //sc.scanVector = vector<ScanType>();
                switch (s) {
                    case SYN:
                        sc.cScan = SYN;

                        sc.runTcpScan();
                        break;
                    case NUL:
                        sc.cScan = NUL;

                        sc.runTcpScan();
                        break;
                    case FIN:
                        sc.cScan = FIN;

                        sc.runTcpScan();
                        break;
                    case XMAS:
                        sc.cScan = XMAS;

                        sc.runTcpScan();
                        break;
                    case ACK:
                        sc.cScan = ACK;

                        sc.runTcpScan();
                        break;
                    case UDP:
                        sc.cScan = UDP;
                        sc.runUdpScan();
                        break;
                }
                pthread_mutex_lock(&arrMutex);
                scanArray.push_back(sc);
                pthread_mutex_unlock(&arrMutex);
            }
        }
    }
    return NULL;
}

void get_final_result(vector<PortState> &stScan) {
    int filtered = 0;
    int unfiltered = 0;
    int open_filtered = 0;
    int closed_filtered = 0;
    int num_scans = 0;
    int last_scan = -1;
    if (stScan[SYN] == Open || stScan[SYN] == Open) {
        stScan[7] = Open;
        return;
    }
    if (stScan[SYN] == Closed || stScan[FIN] == Closed || stScan[XMAS] == Closed
            || stScan[NUL] == Closed) {
        stScan[7] = Closed;
        return;
    }
    for (int i = 0; i < 6; i++) {
        if (stScan[i] == OpenORFiltered) {
            open_filtered++;
        } else if (stScan[i] == CloedAndFiltered) {
            closed_filtered++;
        } else if (stScan[i] == Unfiltered) {
            unfiltered++;
        } else if (stScan[i] == Filtered) {
            filtered++;
        }
        num_scans++;
        last_scan = i;
    }
    if (unfiltered > 0 && open_filtered > 0) {
        stScan[7] = Open;
        return;
    }
    if (unfiltered > 0 && closed_filtered > 0) {
        stScan[7] = Closed;
        return;
    }
    if (filtered) {
        stScan[7] = Filtered;
        return;
    }
    if (open_filtered >= closed_filtered) {
        stScan[7] = OpenAndFiltered;
        return;
    } else {
        stScan[7] = CloedAndFiltered;
        return;
    }
}

void pResultMap(){
    map<string, list< pair<short, vector<PortState> > > >::iterator resMapIterator = resultMap.begin();
    while(resMapIterator != resultMap.end()){
        cout<<"Scanned Host: "<<resMapIterator->first<<endl<<endl;

        cout<<"Port\tService Name\tService Version\t\tResults\t\tConclusion"<<endl;
        cout<<"---------------------------------------------------------------------------------"<<endl;
        list< pair<short, vector<PortState> > > portList = resMapIterator->second;
        list< pair<short, vector<PortState> > >::iterator listIter;
        string serviceName;

        for(listIter = portList.begin(); listIter != portList.end(); ++listIter){
            struct servent * service = getservbyport(listIter->first,
                    "");
            if (service != NULL)
                serviceName = stringUpper(service->s_name);
            else
                serviceName = "Unknown";

            cout<<ntohs(listIter->first)<<"\t"<<serviceName<<"\t\t";
            vector<PortState>::iterator scanIterator;
            vector<PortState> scanVec = listIter->second;

            int scanCounter = 0;
            string serviceVersion;


            if (count(knownServices.begin(), knownServices.end(), ntohs(listIter->first)) != 0
                    && count(scanVec.begin(), scanVec.end(), Open) != 0){
                serviceVersion = servChk(resMapIterator->first, ntohs(listIter->first));
                cout<<serviceVersion<<"\t\t";
            } else {
                serviceVersion = string();
                cout<<"\t\t\t";
            }

            for (scanIterator = scanVec.begin(); scanIterator != scanVec.end(); ++scanIterator){
                if(scanVec[scanCounter] != Unknown)
                    cout<<strScanType((ScanType)scanCounter)<<":"<<strPortState(scanVec[scanCounter])<<"\t";

                /*        if(scanCounter == 0){
                          cout<<strPortState(scanVec[scanTypeLength+1]);
                          }*/
                ++scanCounter;
            }
            cout<<endl;
        }
        ++resMapIterator;
    }
}

void interpretResults(){

    vector<Scan>::iterator it;

    for(it = scanArray.begin(); it != scanArray.end(); ++it){
        string scannedIp     = it->ipToScan;
        short scannedPort    = it->port;
        ScanType scan        = it->cScan;
        PortState scanResult = it->scanResult;

        map<string, list< pair<short, vector<PortState> > > >::iterator resMapIterator = resultMap.find(scannedIp);
        //check ip present in the map, go further and check other members
        if(resMapIterator != resultMap.end()){

            list< pair<short, vector<PortState> > > portList = resMapIterator->second;
            //cout<<"List sizeeeeee"<<portList.size()<<endl;
            //find the port.
            list< pair<short, vector<PortState> > >::iterator listIter;
            for (listIter = portList.begin(); listIter != portList.end(); ++listIter) {
                //  if present add scan to vector
                if(listIter->first == scannedPort){
             /*       vector<PortState> portSt = listIter->second;
                    portSt[scan] = scanResult;
                    listIter->second = portSt;*/
                    break;
                }
            }
            //  else add new pair;
            if(listIter == portList.end()){
                //create vector
                vector<PortState> portSt (scanTypeLength+1, Unknown);
                portSt[scan] = scanResult;
                //add final inference
                get_final_result(portSt);
                //create pair
                pair<short, vector<PortState> > portResult (scannedPort, portSt);
                //append to the list
                portList.push_back(portResult);
                resultMap[scannedIp]= portList;
            } else
            {
                    vector<PortState> portSt = listIter->second;
                    portSt[scan] = scanResult;
                    listIter->second = portSt;
                   
                    pair<short, vector<PortState> > portResult (scannedPort, portSt);
                    *(listIter)=portResult;
                    resultMap[scannedIp]= portList;
             }
        } else { //IP not present in the map.
            //Create entries
            //create Port state vector
            //           cout<<"First time "<<endl;

            vector<PortState> portSt (scanTypeLength+1, Unknown);
            portSt[scan] = scanResult;
            get_final_result(portSt);
            //create pair
            pair<short, vector<PortState> > portResult (scannedPort, portSt);
            //create and push to the list
            list< pair<short, vector<PortState> > > portList;
            portList.push_back(portResult);
            //add the entries to the map;
            resultMap[scannedIp] = portList;
        }
    }
    pResultMap();
}

int main(int argc, char * argv[]) {
    ps_args_t ps_args;
    parse_args(ps_args, argc, argv);
    ps_args.ip_iterator = ps_args.ip.begin();
    //ps_args.ip_iterator = ps_args.ip_iterator+1;
    ps_args.port_iterator = ps_args.ports.begin();
    //ps_args.num_threads = 0;
    //ps_args.port_iterator++;
    //vector<int>::iterator k = ps_args.ports.begin();

    ///cout<<"dasdasdafs"<<*(k)<<"\n";
    //cout << "kgmblkdfmgod\n";
    //  /cout<<"skkdmasd"<<*(ps_args.ip.begin()+1)<<"\n";
    //cout << "first" << *(ps_args.ip_iterator) << "\t\n";
    //cout << *(ps_args.port_iterator) << "\n";
    cout<<"the num threads in main"<<ps_args.num_threads<<"\n";
    if (ps_args.num_threads > 0) {
        cout<<"using thread"<<"\n";
        pthread_t pth[ps_args.num_threads];
        for (int i = 0; i < ps_args.num_threads; i++) {
            pthread_create(&pth[i], NULL, perform_scan, &ps_args);
        }
        //      pthread_create(&pth1, NULL, perform_scan, &ps_args);
        //      pthread_create(&pth2, NULL, perform_scan, &ps_args);
        //      pthread_create(&pth4, NULL, perform_scan, &ps_args);
        //pthread_create(&pth1,NULL,perform_scan,&ps_args);
        for (int i = 0; i < ps_args.num_threads; i++) {
            pthread_join(pth[i], NULL);
        }

        //      pthread_join(pth1, NULL);
        //      pthread_join(pth2, NULL);
        //      //pthread_join(pth3, NULL);
        //      pthread_join(pth4, NULL);
    } else {
        perform_scan(&ps_args);
    }
    interpretResults();
    //perform_scan(&ps_args);
    /*for (vector<string>::iterator i = ps_args.ip.begin(); i != ps_args.ip.end();
      ++i) {

      for (vector<int>::iterator j = ps_args.ports.begin();
      j != ps_args.ports.end(); ++j) {
      cout << "ip" << *i << "\tport" << *j << "\n";
    //         perform_scan(k.s_addr, *j);
    }
    }*/
}
