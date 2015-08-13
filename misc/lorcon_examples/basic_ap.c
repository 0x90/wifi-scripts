/*

	THIS IS INCOMPLETE CODE!


	basic_ap.c 
	by brad.antoniewicz@foundstone.com	

	Simple access point using LORCON - Right
	now its just doing 802.11 session establishment

	THIS IS INCOMPLETE CODE!
*/

#include <stdio.h>
#include <getopt.h>
#include <string.h>
#include <pthread.h>
#include <stdlib.h>


#include <sys/time.h> // Needed for timestamp

#include <lorcon2/lorcon.h> // For LORCON 
#include <lorcon2/lorcon_packasm.h> // For metapack packet assembly

/*
	Various Constants
*/
#define MAC_LEN 6
#define SRC_MAC_OFFSET 9
#define DST_MAC_OFFSET 3
#define BSSID_OFFSET 15

#define SSID_LEN_OFFSET 37
#define SSID_OFFSET 38

#define PSSID_OFFSET 26
#define PSRC_OFFSET 10


#define TYPE_OFFSET 0


/*
	This struct holds the AP information
*/

typedef struct {

	char *ssid;
	uint8_t ssid_len;

	uint8_t channel;
	
	uint8_t *src_mac;
	uint8_t *dst_mac;
	uint8_t *bssid;

	int beacon_interval;
	int capabilities;
	uint8_t *rates;
	
	struct timeval time;
	uint64_t timestamp;

	int got_probe_req;
	int got_assoc_req;
	int got_auth_req;

} ap_info;

ap_info ap_info_t;


void usage(char *argv[]) {
	printf("\t-s <SSID>\tSSID to flood\n");
	printf("\t-i <int> \tInterface\n");
	printf("\t-c <channel>\tChannel\n");
	//printf("\t-b <bssid> \tBSSID (XX:XX:XX:XX:XX:XX)\n");
	printf("\nExample:\n");
	printf("\t%s -s brad -i wlan0 -c 1\n\n",argv[0]);
}

void *beacon(void *context) {

        lcpa_metapack_t *metapack; // metapack for LORCON packet assembly
        lorcon_packet_t *txpack; // The raw packet to be sent


	//Set up AP
	ap_info_t.beacon_interval = 100;
	ap_info_t.capabilities = 0x0421;
	ap_info_t.rates = "\x8c\x12\x98\x24\xb0\x48\x60\x6c"; // 6,9,12,18,24,36,48,54

        /*
                The following is the packet creation and sending code
        */

        // Keep sending frames until interrupted
        while(1) {

                // Create timestamp
                gettimeofday(&ap_info_t.time, NULL);
                ap_info_t.timestamp = ap_info_t.time.tv_sec * 1000000 + ap_info_t.time.tv_usec;

                // Initialize the LORCON metapack
                metapack = lcpa_init();

                // Create a Beacon frame from 00:DE:AD:BE:EF:00
                lcpf_beacon(metapack,  ap_info_t.src_mac,  ap_info_t.bssid, 0x00, 0x00, 0x00, 0x00, ap_info_t.timestamp, ap_info_t.beacon_interval, ap_info_t.capabilities);

                // Append IE Tag 0 for SSID
                lcpf_add_ie(metapack, 0, ap_info_t.ssid_len, ap_info_t.ssid);

                // Most of the following IE tags are not needed, but added here as examples

                // Append IE Tag 1 for rates
                lcpf_add_ie(metapack, 1, sizeof(ap_info_t.rates)-1, ap_info_t.rates);

                // Append IE Tag 3 for Channel
                lcpf_add_ie(metapack, 3, 1, &ap_info_t.channel);

                // Append IE Tags 42/47 for ERP Info
                lcpf_add_ie(metapack, 42, 1, "\x05");
                lcpf_add_ie(metapack, 47, 1, "\x05");

                // Convert the LORCON metapack to a LORCON packet for sending
                txpack = (lorcon_packet_t *) lorcon_packet_from_lcpa(context, metapack);

                // Send and exit if error
                if ( lorcon_inject(context,txpack) < 0 )
                        exit(1);

               // Wait interval before next beacon
                usleep(ap_info_t.beacon_interval * 1000);

                // Free the metapack
                lcpa_free(metapack);
        }


}


/* 
	This function inspects packets, looking for a deauthentication frame
*/

int find_deauth(lorcon_packet_t *packet) {
	
	return 0;
}

/*
        This function sends a probe response
*/
void send_probe_resp(lorcon_t *context) {

        lcpa_metapack_t *metapack; // metapack for LORCON packet assembly
        lorcon_packet_t *txpack; // The raw packet to be sent


        /*
                The following is the packet creation and sending code
        */

	// Initialize the LORCON metapack
	metapack = lcpa_init();

	// Create  
        lcpf_proberesp(metapack,  ap_info_t.dst_mac, ap_info_t.src_mac, ap_info_t.bssid, 0x00, 0x00, 0x00, 0x00, ap_info_t.timestamp, ap_info_t.beacon_interval, ap_info_t.capabilities);

	// Append IE Tag 0 for SSID
	lcpf_add_ie(metapack, 0, ap_info_t.ssid_len, ap_info_t.ssid);

	// Send and exit if error
        if ( lorcon_inject(context,txpack) < 0 )
		exit(1);

	// Free the metapack
	lcpa_free(metapack);

}

/*
	This function inspects packets, looking for a probe request
*/

int find_probe_req(lorcon_packet_t *packet) {
	
	int ret, i;
	char ssid[256];
	char mac[MAC_LEN];

        // Looking for any probe requests with a valid SSID length
        if ((packet->packet_header[0] == 0x40) && (packet->packet_header[PSSID_OFFSET-1] < 255) && (packet->packet_header[PSSID_OFFSET-1] != 0)) {
		
		for(i=0;i<packet->packet_header[PSSID_OFFSET-1];i++)
			ssid[i] = packet->packet_header[PSSID_OFFSET + i];
		ssid[packet->packet_header[PSSID_OFFSET-1]] = '\0';
		
		ret = strncmp(ssid,ap_info_t.ssid, packet->packet_header[PSSID_OFFSET-1]);

		if ( ret == 0 ) {
			// TODO: Set MAC in ap_info_t	
			ap_info_t.got_probe_req = 1;
			return 1; // Found probe request for my SSID
		}

        }

	return 0; // Didn't find a probe request for my SSID

	
}

/*
	This function waits for a probe request then responds
	with a probe response
*/
void probe_state(lorcon_t *context, lorcon_packet_t *packet, u_char *user) {

	if (find_probe_req(packet) && ap_info_t.got_probe_req == 1) {
		printf("[+] Got probe request\n");
	
	}

	if (find_deauth(packet) && ap_info_t.got_probe_req == 1) {
		printf("[!] Got deauthentication frame!\n");
		ap_info_t.got_probe_req = 0;
		lorcon_breakloop(context);
	}

}

/*
	This function sends a association response
*/
void send_assoc_resp(lorcon_t *context) {

	
}

/*
        This function waits for a association request then responds
        with a association response
*/
void assoc_state(lorcon_t *context, lorcon_packet_t *packet, u_char *user) {

	if ( !ap_info_t.got_probe_req ) {
		lorcon_loop(context, 0, probe_state, NULL);
	}

	
}


/*
        This function sends a authentication response
*/
void send_auth_resp(lorcon_t *context) {


}


/*
        This function waits for a authentication request then responds
        with a association response
*/
void auth_state(lorcon_t *context, lorcon_packet_t *packet, u_char *user) {

        if ( !ap_info_t.got_probe_req ) {
		lorcon_loop(context, 0, probe_state, NULL);
        }

        if ( !ap_info_t.got_assoc_req ) {
		lorcon_loop(context, 0, assoc_state, NULL);
        }


}


int main(int argc, char *argv[]) {

	char *interface = NULL;
	int c, ret;

	pthread_t beacon_thread;

	lorcon_driver_t *drvlist, *driver; // Needed to set up interface/context
	lorcon_t *context; // LORCON context

	// BSSID and source MAC address
	ap_info_t.src_mac = "\x00\xDE\xAD\xBE\xEF\x00";
	ap_info_t.bssid = "\x00\xDE\xAD\xBE\xEF\x00";

	ap_info_t.ssid = NULL;
        ap_info_t.got_probe_req = 0;
        ap_info_t.got_assoc_req = 0;
        ap_info_t.got_auth_req = 0;

	printf ("%s - Simple 802.11 Access Point\n", argv[0]);
	printf ("-----------------------------------------------------\n\n");

	/* 
		This handles all of the command line arguments
	*/
	
	while ((c = getopt(argc, argv, "i:s:hc:b:")) != EOF) {
		switch (c) {
			case 'i': 
				interface = strdup(optarg);
				break;
			case 's': 
				if ( strlen(strdup(optarg)) < 255 ) {
					ap_info_t.ssid = strdup(optarg);
					ap_info_t.ssid_len = strlen(ap_info_t.ssid);
				} else {
					printf("ERROR: SSID Length too long! Should not exceed 255 characters\n");
					return -1;
				}
				break;
			case 'c':
				ap_info_t.channel = atoi(optarg);
				break;
			case 'h':
				usage(argv);
				break;
			default:
				usage(argv);
				break;
			}
	}

	if ( interface == NULL || ap_info_t.ssid == NULL ) { 
		printf ("ERROR: Interface, channel, or SSID not set (see -h for more info)\n");
		return -1;
	}

	printf("[+] Using interface %s\n",interface);
	
	/*	
	 	The following is all of the standard interface, driver, and context setup
	*/

	// Automatically determine the driver of the interface
	
	if ( (driver = lorcon_auto_driver(interface)) == NULL) {
		printf("[!] Could not determine the driver for %s\n",interface);
		return -1;
	} else {
		printf("[+]\t Driver: %s\n",driver->name);
	}

	// Create LORCON context
        if ((context = lorcon_create(interface, driver)) == NULL) {
                printf("[!]\t Failed to create context");
               	return -1; 
        }

	// Create Monitor Mode Interface
	if (lorcon_open_injmon(context) < 0) {
		printf("[!]\t Could not create Monitor Mode interface!\n");
		return -1;
	} else {
		printf("[+]\t Monitor Mode VAP: %s\n",lorcon_get_vap(context));
		lorcon_free_driver_list(driver);
	}

	// Set the channel we'll be injecting on
	lorcon_set_channel(context, ap_info_t.channel);
	printf("[+]\t Using channel: %d\n\n",ap_info_t.channel);

	/* 
		Bulk of program
	*/

	// Start thread for beacons
	printf("[+] Spawning Beacon Thread for SSID: %s ....",ap_info_t.ssid);

	ret = pthread_create( &beacon_thread, NULL, beacon, (void*) context );

        if ( ret == 0 ) {
                printf("STARTED\n");
        } else {
                printf("FAILED (%d) \n", ret);
                exit(1);
        }

	//sleep(1000);

	printf("[+] Waiting for a probe request\n");
	lorcon_loop(context, 0, probe_state, NULL);	

	/* 
	 	The following is all of the standard cleanup stuff
	*/
	
	// Close the interface
	lorcon_close(context);

	// Free the LORCON Context
	lorcon_free(context);	
	
	return 0;
	
}

