all:
	g++ scan.cpp helpers.cpp portScanner.cpp service.cpp -o portScanner -lpcap -std=c++0x
clean:
	rm portScanner
