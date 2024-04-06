#include <stdio.h>
#include <stdlib.h>
#include <pcap.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>

/* Ethernet header */
struct ethheader {
    u_char  ether_dhost[6];    /* destination host address */
    u_char  ether_shost[6];    /* source host address */
    u_short ether_type;        /* protocol type (IP, ARP, RARP, etc) */
};

/* IP Header */
struct ipheader {
    unsigned char   iph_ihl:4,     /* IP header length */
                    iph_ver:4;     /* IP version */
    unsigned char   iph_tos;       /* Type of service */
    unsigned short  iph_len;       /* IP Packet length (data + header) */
    unsigned short  iph_ident;     /* Identification */
    unsigned short  iph_flag:3,    /* Fragmentation flags */
                    iph_offset:13; /* Flags offset */
    unsigned char   iph_ttl;       /* Time to Live */
    unsigned char   iph_protocol;  /* Protocol type */
    unsigned short  iph_chksum;    /* IP datagram checksum */
    struct in_addr  iph_sourceip;  /* Source IP address */
    struct in_addr  iph_destip;    /* Destination IP address */
};

/* TCP Header */
struct tcpheader {
    u_short  th_sport;   /* source port */
    u_short  th_dport;   /* destination port */
    u_int    th_seq;     /* sequence number */
    u_int    th_ack;     /* acknowledgement number */
    u_char   th_offx2;   /* data offset, rsvd */
#define TH_OFF(th)  (((th)->th_offx2 & 0xf0) >> 4)
    u_char   th_flags;
    u_short  th_win;     /* window */
    u_short  th_sum;     /* checksum */
    u_short  th_urp;     /* urgent pointer */
};

void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) {
    struct ethheader *eth = (struct ethheader*)packet;

    // Check IP type
    if (ntohs(eth->ether_type) == 0x0800) {
        struct ipheader *ip = (struct ipheader*)(packet + sizeof(struct ethheader));

        // Check TCP protocol
        if (ip->iph_protocol == IPPROTO_TCP) {
            struct tcpheader *tcp = (struct tcpheader*)(packet + sizeof(struct ethheader) + (ip->iph_ihl * 4));
            
            printf("========================================================\n");
            // Print Ethernet Header
            printf("[1] Ethernet Header:\n");
            printf("Source MAC: %.2x:%.2x:%.2x:%.2x:%.2x:%.2x\n", eth->ether_shost[0], eth->ether_shost[1], eth->ether_shost[2], eth->ether_shost[3], eth->ether_shost[4], eth->ether_shost[5]);
            printf("Destination MAC: %.2x:%.2x:%.2x:%.2x:%.2x:%.2x\n", eth->ether_dhost[0], eth->ether_dhost[1], eth->ether_dhost[2], eth->ether_dhost[3], eth->ether_dhost[4], eth->ether_dhost[5]);
            printf("--------------------------------------------------------\n");
            // Print IP Header
            printf("[2] IP Header:\n");
            printf("Source IP: %s\n", inet_ntoa(ip->iph_sourceip));
            printf("Destination IP: %s\n", inet_ntoa(ip->iph_destip));
            printf("--------------------------------------------------------\n");
            // Print TCP Header
            printf("[3] TCP Header:\n");
            printf("Source Port: %d\n", ntohs(tcp->th_sport));
            printf("Destination Port: %d\n", ntohs(tcp->th_dport));
            printf("--------------------------------------------------------\n");
            // Print Message (just 16 bytes)
            printf("[4] Message:\n");
            const u_char *payload = packet + sizeof(struct ethheader) + (ip->iph_ihl * 4) + (tcp->th_offx2 >> 4) * 4;
            int payload_len = ntohs(ip->iph_len) - (ip->iph_ihl * 4) - ((tcp->th_offx2 >> 4) * 4);
            for (int i = 0; i < payload_len && i < 16; ++i) {
                printf("%02x ", payload[i]);
            }
            printf("\n");
            printf("========================================================\n");
            printf("\n");
        }
    }
}

int main() {
    pcap_t *handle;
    char errbuf[PCAP_ERRBUF_SIZE];
    struct bpf_program fp;
    char filter_exp[] = "tcp";
    bpf_u_int32 net;

    // Open live pcap session on NIC with name "ens33"
    handle = pcap_open_live("ens33", BUFSIZ, 1, 1000, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "Couldn't open device %s: %s\n", "ens33", errbuf);
        return(2);
    }

    // Compile the filter expression
    if (pcap_compile(handle, &fp, filter_exp, 0, net) == -1) {
        fprintf(stderr, "Couldn't parse filter %s: %s\n", filter_exp, pcap_geterr(handle));
        return(2);
    }

    // Set the filter for the pcap session
    if (pcap_setfilter(handle, &fp) == -1) {
        fprintf(stderr, "Couldn't install filter %s: %s\n", filter_exp, pcap_geterr(handle));
        return(2);
    }

    // Capture packets
    pcap_loop(handle, -1, got_packet, NULL);

    // Close the handle
    pcap_close(handle);

    return(0);
}

