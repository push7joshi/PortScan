#include<iostream>
#include<cstdlib>
#include<cstring>
#include<stdio.h>
#include<vector>
#include <getopt.h>
#include <netinet/in.h>
#include <arpa/inet.h>
using namespace std;

#define TCP_SYN 0
#define TCP_NULL 1
#define FIN 2
#define XMAS 3
#define TCP_ACK 4
#define UDP 5

struct ps_args_t {
	vector<int> ports;
	vector<in_addr> ip;
	int num_threads;
	bool scans[6];
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
	int prev;
	char * next;
	while (1) {
		int position = strtol(string, &next, 10);
		//next++;
		cout << position << "\n";
		if (position == 0) {
			break;
		} else {
			cout<<"next"<<*next<<"\n";
			if (*next == '-') {
				cout<<"prev"<<position<<"\n";
				prev = position;
			}
			else{
				cout<<"not prev"<<position;
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
			string = next+1;
		}

	}
}


void parse_args(ps_args_t &ps_args, int argc, char * argv[]) {
ps_args.ports = vector<int>(1, -1);
ps_args.ip = vector<in_addr>();
ps_args.num_threads = 1;
memset(ps_args.scans, 0, sizeof(ps_args.scans));
/*
 --help <display invocation options>. Example: ”./portScanner --help”.
 --ports <ports to scan>. Example: ”./portScanner --ports 1,2,3-5”.
 --ip <IP address to scan>. Example: ”./portScanner--ip 127.0.0.1”.
 --preﬁx <IP preﬁx to scan>. Example: ”./portScanner--preﬁx 127.143.151.123/24”.
 --ﬁle <ﬁle name containing IP addresses to scan>. Example: ”./portScanner --ﬁle ﬁlename.txt”.
 --speedup <parallel threads to use>. Example: ”./portScanner --speedup 10”.
 --scan <one or more scans>. Example: ”./portScanner --scan SYN NULL FIN XMAS”
 */
static struct option long_options[] = { { "help", no_argument, NULL, 'h' }, {
		"ports", required_argument, NULL, 'p' }, { "ip", required_argument,
		NULL, 'i' }, { "prefix", required_argument, NULL, 'r' }, { "file",
		required_argument, NULL, 'f' }, { "speedup", required_argument, NULL,
		't' }, { "scan", required_argument, NULL, 's' }, };
int ch;
int scans_flag = 0;
int option_index = 0;
while ((ch = getopt_long_only(argc, argv, "hifr:p:s:c", long_options,
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
		ps_args.ip.push_back(iaddr);
		cout << "i " << ps_args.ip[0].s_addr << "\n";
		//exit(0);
		break;
	case 'f': //help
			  //usage(stdout);
		cout << "f" << optarg;
		//exit(0);
		break;
	case 'r': //help
		//usage(stdout);
		cout << "prfix " << optarg;
		//exit(0);
		break;
	case 'p': //help
		//usage(stdout);

		cout << "included ports\n";
		get_ports(ps_args.ports, optarg);
		for (vector<int>::iterator it = ps_args.ports.begin();
				it != ps_args.ports.end(); ++it) {
			cout << " " << *it << " \n";
		}
		break;
	case 't': //help
			  //usage(stdout);
		ps_args.num_threads = 0;

		ps_args.num_threads = strtol(optarg, NULL, 10);
		cout << "\nnum threads " << ps_args.num_threads << "\t" << optarg
				<< "\n";
		break;
	case 's': //help
		//usage(stdout);
		scans_flag = 1;
		char UDP_C[] = "UDP\0";
		char FIN_C[] = "FIN_C\0";
		char TCP_SYN_C[] = "SYN\0";
		char XMAS_C[] = "XMAS\0";
		char TCP_ACK_C[] = "ACK\0";
		char TCP_NULL_C[] = "NULL\0";
		int curr = optind - 1;
		for (; curr < argc && argv[curr] != "-"; curr++) {
			if (strcmp(optarg, UDP_C) == 0) {
				ps_args.scans[UDP] = 1;
			} else if (strcmp(optarg, FIN_C) == 0) {
				ps_args.scans[FIN] = 1;
			} else if (strcmp(optarg, TCP_SYN_C) == 0) {
				ps_args.scans[TCP_SYN] = 1;
			} else if (strcmp(optarg, XMAS_C) == 0) {
				ps_args.scans[XMAS] = 1;
			} else if (strcmp(optarg, TCP_ACK_C) == 0) {
				ps_args.scans[TCP_ACK] = 1;
			} else if (strcmp(optarg, TCP_NULL_C) == 0) {
				ps_args.scans[TCP_NULL] = 1;
			}
		}
		break;
		//			cout << option_index << "    " << argv[optind + 1] << "\n";
		//exit(0);			break;
	}
	if (scans_flag == 0) { //default case of no scans being specified
		int i = 0;
		for (i = 0; i < 6; i++) {
			ps_args.scans[i] = 1;
		}
	}
}
}

int main(int argc, char * argv[]) {
ps_args_t ps_args;
parse_args(ps_args, argc, argv);
}
