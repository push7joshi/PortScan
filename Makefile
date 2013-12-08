all:
	g++ scan.cpp helpers.cpp portScanner.cpp -o portScanner -lpcap -std=c++0x
clean:
	rm portScanner
