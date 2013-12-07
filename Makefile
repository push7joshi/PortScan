all:
	g++ raw_udp.cpp raw.cpp portScanner.cpp -o portScanner -lpcap -std=c++0x
clean:
	rm portScanner
