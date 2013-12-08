all:
	g++ scan.cpp helpers.cpp portScanner.cpp service.cpp -o portScanner -g -lpcap -lpthread -std=c++0x
clean:
	rm portScanner
