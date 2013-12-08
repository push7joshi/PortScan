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
#include "scan.h"
#include<pthread.h>
using namespace std;

pthread_mutex_t cs_mutex = PTHREAD_RECURSIVE_MUTEX_INITIALIZER_NP;

struct ps_args_t {
	vector<int> ports;
	vector<string> ip;
	int num_threads;
	bool scans[6];
	string prefix;
	vector<int>::iterator port_iterator;
	vector<string>::iterator ip_iterator;
	int count;
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
//	/long mask;
	//long ip_num = 0;
	char delim = '/';
	char * ip_char = strtok((char *) prefix.c_str(), &delim);
	char * delim_char = strtok(NULL, &delim);
	int ip_int = 0;
	char temp[INET_ADDRSTRLEN];

	unsigned int host_len = strtol(delim_char, NULL, 10);
	//printf("0-0-0-0-0----%x\n", host_len);
	unsigned int range = (unsigned int) pow(2, host_len);
	unsigned int subnet_mask = (unsigned int) pow(2, 32) - range + 1; //	unsigned int range = (unsigned int) pow(2, range);(int) pow(2, host_len);
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
	/*	char * next;
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
	ps_args.num_threads = 1;
	ps_args.prefix = string();
	int port_set = 0;
	int scans_flag = 0;
	ps_args.count = 0;
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
//			cout << "i " << ps_args.ip[0].s_addr << "\n";
			break;
		case 'f': //help
				  //usage(stdout);
			//cout<<"akjdnmakldas\n";
			opt = optarg;
			read_ip_from_file(ps_args.ip, optarg);
			//		cout<<ps_args.ip[0].s_addr<<"\n";
			//	cout<<ps_args.ip[1].s_addr<<"\n";
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
//			cout << "adasdasdassdas : " << ps_args.ports[1] << "\n";
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
			/*			char UDP_C[] = "UDP\0";
			 char FIN_C[] = "FIN_C\0";
			 char TCP_SYN_C[] = "SYN\0";
			 char XMAS_C[] = "XMAS\0";
			 char TCP_ACK_C[] = "ACK\0";
			 char TCP_NULL_C[] = "NULL\0";
			 */
			curr = optind - 1;
			for (; curr < argc && argv[curr] != "-"; curr++) {
				scans_flag = 1;
				opt = optarg;
				if (opt == "UDP") {
					ps_args.scans[UDP] = 1;
				} else if (optarg == "FIN") {
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
		cout << "about to start: " << ip << "\t port:" << port << "\n";
		if (ip == "finish" && port == -1) {
			return NULL;
		}
		for (int s = 0; s < 6; s++) {
			if (ps_args->scans[s] == 1) {
				cout << "really starting: " << ip << "\t port:" << port << "\n";
				ScanType j;
				Scan sc = Scan();
				sc.ipToScan = ip;
				sc.port = htons(port);
				cout<<"------count-----------"<<ps_args->count++<<"\n";
				sc.scanVector = vector<ScanType>();
				switch (s) {
				case SYN:
					//cout << "RUNNING SYN: " << ip << "\t port:" << port << "\n";
					sc.scanVector.push_back(SYN);
					sc.cScan = SYN;
					sc.runTcpScan();
					cout << "finished SYN: " << ip << "\t port:" << port
							<< "\n";
					//packetSendRecv(ip, port, SYN);
					break;
				case NUL:
					sc.scanVector.push_back(NUL);
					sc.cScan = NUL;
					sc.runTcpScan();
					//packetSendRecv(ip, port, NUL);
					break;
				case FIN:
					sc.scanVector.push_back(FIN);
					sc.cScan = FIN;
					sc.runTcpScan();
					//packetSendRecv(ip, port, FIN);
					break;
				case XMAS:
					sc.scanVector.push_back(XMAS);
					sc.cScan = XMAS;
					sc.runTcpScan();
					//packetSendRecv(ip, port, XMAS);
					break;
				case ACK:
					sc.scanVector.push_back(ACK);
					sc.cScan = ACK;
					sc.runTcpScan();
					//packetSendRecv(ip, port, ACK);
					break;
				case UDP:
					//packetSendRecvUDP(ip, port);
					break;
				}
			}
		}
	}
	return NULL;
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
//	/cout<<"skkdmasd"<<*(ps_args.ip.begin()+1)<<"\n";
	//cout << "first" << *(ps_args.ip_iterator) << "\t\n";
	//cout << *(ps_args.port_iterator) << "\n";
	cout<<"the num threads in main"<<ps_args.num_threads<<"\n";
	if (ps_args.num_threads > 0) {
		cout<<"using thread"<<"\n";
		pthread_t pth[ps_args.num_threads];
		for (int i = 0; i < ps_args.num_threads; i++) {
			pthread_create(&pth[i], NULL, perform_scan, &ps_args);
		}
//		pthread_create(&pth1, NULL, perform_scan, &ps_args);
//		pthread_create(&pth2, NULL, perform_scan, &ps_args);
//		pthread_create(&pth4, NULL, perform_scan, &ps_args);
		//pthread_create(&pth1,NULL,perform_scan,&ps_args);
		for (int i = 0; i < ps_args.num_threads; i++) {
			pthread_join(pth[i], NULL);
		}

//		pthread_join(pth1, NULL);
//		pthread_join(pth2, NULL);
//		//pthread_join(pth3, NULL);
//		pthread_join(pth4, NULL);
	} else {
		perform_scan(&ps_args);
	}
	//perform_scan(&ps_args);
	/*for (vector<string>::iterator i = ps_args.ip.begin(); i != ps_args.ip.end();
	 ++i) {

	 for (vector<int>::iterator j = ps_args.ports.begin();
	 j != ps_args.ports.end(); ++j) {
	 cout << "ip" << *i << "\tport" << *j << "\n";
	 //			perform_scan(k.s_addr, *j);
	 }
	 }*/
}
