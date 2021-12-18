#pragma once
#include <pcap.h>

struct DeauthPacket {
    RadiotapHdr radiotapHdr;
    BeaconHdr beaconHdr;
};

void usage();
void deauth(pcap_t* handle);
bool pkt_handle(const u_char* pkt);