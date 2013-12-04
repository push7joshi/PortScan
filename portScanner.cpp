#include<iostream>
#include<cstdlib>
#include<cstring>
#include<stdio.h>
#include<vector>
#include <getopt.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <fstream>
#include "raw.h"

using namespace std;

#define TCP_SYN 0
#define TCP_NULL 1
#define TCP_FIN 2
#define TCP_XMAS 3
#define TCP_ACK 4
#define UDP_SCAN 5

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
					for (i = prev; i < position; i++) {
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

void parse_args(ps_args_t &ps_args, int argc, char * argv[]) {
	ps_args.ports = vector<int>(1, -1);
	ps_args.ip = vector<string>();
	ps_args.num_threads = 1;
	ps_args.prefix = string();
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
	int scans_flag = 0;
	int option_index = 0;
	string opt;
	int curr = 0;
	while ((ch = getopt_long_only(argc, argv, "i:f:r:p:t:s:h", long_options,
			&option_index)) != -1) {
		switch (ch) {
		case 'h': //help
			usage();
			//cout << "h\n";
			//exit(0);
			break;
		case 'i': //help
				  //usage(stdout);
			in_addr iaddr;
			inet_pton(AF_INET, optarg, &iaddr);
			ps_args.ip.push_back(optarg);
//			cout << "i " << ps_args.ip[0].s_addr << "\n";
			//exit(0);
			break;
		case 'f': //help
				  //usage(stdout);
			//exit(0);
			//cout<<"akjdnmakldas\n";
			opt = optarg;
			read_ip_from_file(ps_args.ip, optarg);
			//		cout<<ps_args.ip[0].s_addr<<"\n";
			//	cout<<ps_args.ip[1].s_addr<<"\n";
			break;

		case 'r': //help
			//usage(stdout);
			ps_args.prefix = optarg;
			//cout << "prfix " << ps_args.prefix << "\n";
			//exit(0);
			break;
		case 'p': //help
			//usage(stdout);

			//cout << "included ports\n";
			get_ports(ps_args.ports, optarg);
			/*for (vector<int>::iterator it = ps_args.ports.begin();
					it != ps_args.ports.end(); ++it) {
			cout << " " << *it << " \n";
			}*/
			break;
		case 't': //help
				  //usage(stdout);
			ps_args.num_threads = 0;
			ps_args.num_threads = strtol(optarg, NULL, 10);
//			cout << "\nnum threads " << ps_args.num_threads << "\t" << optarg << "\n";
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
				scans_flag = 0;
				opt = optarg;
				if (opt == "UDP") {
					ps_args.scans[UDP] = 1;
				} else if (optarg == "FIN") {
					ps_args.scans[FIN] = 1;
				} else if (opt == "SYN") {
					ps_args.scans[TCP_SYN] = 1;
				} else if (opt == "XMAS") {
					ps_args.scans[XMAS] = 1;
				} else if (opt == "ACK") {
					ps_args.scans[TCP_ACK] = 1;
				} else if (opt == "NULL") {
					ps_args.scans[TCP_NULL] = 1;
				}
			}
			break;
		default:
			break;
		}

	}
}
;

void get_next_ip_port(ps_args_t &ps_args, string &ip, int &port) {
	//synchronized
	ip = "finish";
	port = -1;
	while (1) {
		if (ps_args.port_iterator == ps_args.ports.end()) {
			ps_args.ip_iterator++;
			cout << "end of port list\n";
			ps_args.port_iterator = ps_args.ports.begin();
			if (ps_args.ip_iterator == ps_args.ip.end()) {
				//end of queue..... no more jobs
				cout << "end of ip list\n";
				return;
			}
		} else {
			//cout << "asdasdasd\n";
			ip = *(ps_args.ip_iterator);
			port = *(ps_args.port_iterator);
			ps_args.port_iterator++;
			ps_args.ip_iterator;
			return;
		}
	}
	//end of synchronized
}

void perform_scan(ps_args_t &ps_args) {
	string ip = "ip";
	int port = 0;
	while (ip != "finish" && port != -1) {
		get_next_ip_port(ps_args, ip, port);
		if (ip == "finish" && port == -1){
			break;
		}
		for (int s = 0; s < 6; s++) {
			if (ps_args.scans[s] == 1) {
				cout << ip << "\t" << port << "\t" << ps_args.scans[s];
				ScanType j;
				switch (s) {
				case SYN:
					packetSendRecv('s',ip,port,SYN);
					break;
				case NUL:
					packetSendRecv('s',ip,port,NUL);
					break;
				case FIN:
					packetSendRecv('s',ip,port,FIN);
					break;
				case XMAS:
					packetSendRecv('s',ip,port,XMAS);
					break;
				case ACK:
					packetSendRecv('s',ip,port,ACK);
					break;
				case UDP:
					packetSendRecvUDP('s',ip,port);
					break;
				}

			}
		}
	}
}
int main(int argc, char * argv[]) {
	cout << "a;jfnsdlkffjsdofkjasoibhgasduiofgasiugfjaofidfufd\n";
	ps_args_t ps_args;
	parse_args(ps_args, argc, argv);
	ps_args.ip_iterator = ps_args.ip.begin();
	//ps_args.ip_iterator = ps_args.ip_iterator+1;
	ps_args.port_iterator = ps_args.ports.begin();
	//ps_args.port_iterator++;
	vector<int>::iterator k = ps_args.ports.begin();

	///cout<<"dasdasdafs"<<*(k)<<"\n";
	//cout << "kgmblkdfmgod\n";
//	/cout<<"skkdmasd"<<*(ps_args.ip.begin()+1)<<"\n";
	//cout << "first" << *(ps_args.ip_iterator) << "\t\n";
	//cout << *(ps_args.port_iterator) << "\n";
	perform_scan(ps_args);
	/*for (vector<string>::iterator i = ps_args.ip.begin(); i != ps_args.ip.end();
	 ++i) {

	 for (vector<int>::iterator j = ps_args.ports.begin();
	 j != ps_args.ports.end(); ++j) {
	 cout << "ip" << *i << "\tport" << *j << "\n";
	 //			perform_scan(k.s_addr, *j);
	 }
	 }*/
}
