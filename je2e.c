#if HAVE_CONFIG_H
#include "config.h"
#endif

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/stat.h>

#include <arpa/inet.h>
#include <net/ethernet.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <pcap.h>

#define JUNIPER_BPF_NO_L2         0x2     /* L2 header stripped */
#define JUNIPER_BPF_EXT           0x80    /* extensions present */

void
usage(int ecode)
{
	printf("Usage: je2e [-fv] infile outfile\n");
	printf(" -f : force overwrite of outfile\n");
	printf(" -v : be a bit more verbose on operations\n");
	printf("\n");
	printf("(c) Alexandre Snarskii, 2018\n");
	exit(ecode);
};

int
main(int argc, char* argv[])
{
	char *filename = NULL;
	char *dumpfile = NULL;
	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t* pcap, *pcd; 
	pcap_dumper_t *dumper;
	const unsigned char* pdata;
	unsigned char packet[65536];
	struct pcap_pkthdr ph;
	int c, force = 0, verbose = 0;
	uint32_t packetno = 0;

	while ((c = getopt(argc, argv, "fv")) != EOF) {
	switch (c) {
		case 'f': force = 1;
			break;
		case 'v': verbose++;
			break;
		default : usage(1);
	};
	};

	argc -= optind;
	argv += optind;

	if (!argv[0]) {
		fprintf(stderr, "No infile specified\n");
		usage(1);
	};
	filename = argv[0];
	if (!argv[1]) { 
		fprintf(stderr, "No outfile specified\n");
		usage(1);
	};
	dumpfile = argv[1];

	if (verbose) {
		fprintf(stderr, "... will try to copy data from %s to %s\n", filename, dumpfile);
	};

	if (!force) {
		struct stat sb;
		if (stat(dumpfile, &sb) == -1) {
			if (errno != ENOENT) {
				fprintf(stderr, "Error accessing outfile %s: %s\n", dumpfile,
					strerror(errno));
				exit(1);
			};
		} else {
			fprintf(stderr, "Outfile %s already present. Use -f to overwrite\n",
				dumpfile);
			exit(1);
		};
	};

	pcap = pcap_open_offline(filename, errbuf);
	if (!pcap) {
		fprintf(stderr, "Error opening infile %s: %s\n", filename, errbuf);
		exit(1);
	};

	if (pcap_datalink(pcap) != DLT_JUNIPER_ETHER) {
		fprintf(stderr, "Datalink type is not Juniper Ether(%d): %d %s\n",
			DLT_JUNIPER_ETHER, pcap_datalink(pcap),
			pcap_datalink_val_to_name(pcap_datalink(pcap)));
		exit(1);
	};

	if (verbose) {
		fprintf(stderr, "... opened %s, dlt: %i %s\n", filename,
			pcap_datalink(pcap),
			pcap_datalink_val_to_name(pcap_datalink(pcap)));
	};

	pcd = pcap_open_dead(DLT_EN10MB, 65535);
	if (!pcd) {
		fprintf(stderr, "Error opening EN10MB dead: %s\n", strerror(errno));
		exit(1);
	};

	dumper = pcap_dump_open(pcd, dumpfile);
	if (!dumper) {
		fprintf(stderr, "Error opening outfile %s: %s\n", dumpfile,
			strerror(errno));
		exit(1);
	};

	while ((pdata = pcap_next(pcap, &ph)) != NULL) {
		uint8_t flags = pdata[3];
		uint32_t jnx_header_len, jnx_ext_len;
		packetno ++;
		if (ph.caplen < 4) {
			fprintf(stderr, "packet %d: too short (%d bytes) to hold magic "
				"and flags\n", packetno, ph.caplen);
			continue;
		};
		if (pdata[0] != 0x4d || pdata[1] != 0x47  || pdata[2] != 0x43) {
			fprintf(stderr, "packet %d: wrong magic %2.2x%2.2x%2.2x\n",
				packetno, pdata[0], pdata[1], pdata[2]);
			continue;
		};
		if (verbose) {
			printf("... got packet %u, flags %2.2x (%s%s)\n", packetno, flags,
				((flags & JUNIPER_BPF_EXT) == JUNIPER_BPF_EXT) ? "ext " : "",
				((flags & JUNIPER_BPF_NO_L2) == JUNIPER_BPF_NO_L2) ? 
					"No-L2 " : "");
		};
		jnx_header_len = 4;
		if ((flags & JUNIPER_BPF_EXT) == JUNIPER_BPF_EXT) {
			jnx_header_len += 2;
			jnx_ext_len = ntohs(*(uint16_t*)(pdata+4));
			jnx_header_len += jnx_ext_len;
			if (ph.caplen < jnx_header_len) {
				fprintf(stderr, "packet %d: too short to hold full header\n",
					packetno);
				continue;
			};
		};
		if ((flags & JUNIPER_BPF_NO_L2) == JUNIPER_BPF_NO_L2) {
			struct ether_header* eh;
			uint16_t etype;
			if (ph.caplen < jnx_header_len + 5) {
				fprintf(stderr, "packet %d: too short to contain data\n",
					packetno);
				continue;
			};
			jnx_header_len += 4;
			struct pcap_pkthdr ohdr = { .ts = ph.ts,
				.len = ph.len - jnx_header_len + sizeof(struct ether_header),
				.caplen = ph.caplen - jnx_header_len +
					sizeof(struct ether_header) };
			if ((pdata[jnx_header_len] >> 4) == 4) {
				etype = ETHERTYPE_IP;
			} else if ((pdata[jnx_header_len] >> 4) == 6) {
				etype = ETHERTYPE_IPV6;
			} else {
				fprintf(stderr, "packet %d: non-ip packet (%2.2x), skip\n",
					packetno, pdata[jnx_header_len]);
				continue;
			};
			eh = (struct ether_header*) packet;
			eh->ether_type = htons(etype);
			memcpy(eh+1, pdata+jnx_header_len, ph.caplen - jnx_header_len);
			pcap_dump((u_char*)dumper, &ohdr, packet);
		} else {
			struct pcap_pkthdr ohdr = { .ts = ph.ts,
				.len = ph.len - jnx_header_len,
				.caplen = ph.caplen - jnx_header_len};
			pcap_dump((u_char*)dumper, &ohdr, pdata + jnx_header_len);
		};
	};
	pcap_dump_close(dumper);
	pcap_close(pcap);
	pcap_close(pcd);
};
