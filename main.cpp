#include <iostream>
#include "pcap.h"
#include "send_deauth.h"
#include "mac.h"

int main(int argc, char** argv){
    if(argc!=3 && argc!=4){
        usage();
        return 0;
    }
    char* dev = argv[1];
    char
    char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1, errbuf);
	if (handle == nullptr) {
		fprintf(stderr, "couldn't open device %s(%s)\n", dev, errbuf);
		return -1;
	}

    deauth()
}