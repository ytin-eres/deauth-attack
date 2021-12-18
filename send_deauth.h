#pragma once
#include <pcap.h>
#include "radiotaphdr.h"
#include "beaconhdr.h"

void usage();
void deauth(pcap_t* handle, Mac apMac, Mac stationMac);