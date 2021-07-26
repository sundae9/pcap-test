#include <pcap.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <memory.h>
void usage() {
	printf("syntax: pcap-test <interface>\n");
	printf("sample: pcap-test wlan0\n");
}

typedef struct{
    u_int8_t dst_mac[6];
    u_int8_t src_mac[6];
}Ether;

typedef struct{
    u_int8_t dst_ip[4];
    u_int8_t src_ip[4];
}IP;

typedef struct{
    u_int8_t dst_port[2];
    u_int8_t src_port[2];
}TCP;

typedef struct{
    u_int8_t payload[8];
}DATA;

typedef struct {
	char* dev_;
} Param;

Param param  = {
	.dev_ = NULL
};

bool parse(Param* param, int argc, char* argv[]) {
	if (argc != 2) {
		usage();
		return false;
	}
	param->dev_ = argv[1];
	return true;
}

int main(int argc, char* argv[]) {
	if (!parse(&param, argc, argv))
		return -1;

	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t* pcap = pcap_open_live(param.dev_, BUFSIZ, 1, 1000, errbuf);
	if (pcap == NULL) {
		fprintf(stderr, "pcap_open_live(%s) return null - %s\n", param.dev_, errbuf);
		return -1;
	}
    Ether * eth;
    IP * ip;
    TCP * tcp;
    DATA * data;
    u_int16_t dst_port;
    u_int16_t src_port;
	while (true) {
		struct pcap_pkthdr* header;
        const u_char* packet;
		int res = pcap_next_ex(pcap, &header, &packet);
		if (res == 0) continue;
		if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {
			printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(pcap));
			break;
		}
		printf("%u bytes captured\n", header->caplen);
        eth=(Ether *)packet;
        printf("ETHERNET\ndst_mac : ");
        for(int i=0;i<6;i++){
            printf("%02x",eth->dst_mac[i]);
            if(i!=5){
                printf(":");
            }
        }
        printf("\nsrc_mac : ");
        for(int i=0;i<6;i++){
            printf("%02x",eth->src_mac[i]);
            if(i!=5){
                printf(":");
            }
        }
        printf("\n\nIP\n");

        ip=(IP *)(packet+0x1a);
        printf("dst_ip : ");
        for(int i=0;i<4;i++){
            printf("%d",ip->dst_ip[i]);
            if(i!=3){
                printf(".");
            }
        }
        printf("\nsrc_ip : ");
        for(int i=0;i<4;i++){
            printf("%d",ip->src_ip[i]);
            if(i!=3){
                printf(".");
            }
        }
        printf("\n\nTCP");
        printf("\ndst_port : ");
        tcp = (TCP *)(packet+0x22);

        dst_port=tcp->dst_port[1] | tcp->dst_port[0]<<8;
        printf("%d",dst_port);

        printf("\nsrc_port : ");

        src_port=tcp->src_port[1] | tcp->src_port[0]<<8;
        printf("%d",src_port);

        printf("\nDATA : ");

        if(header->caplen >= 54){
            data = (DATA *)(packet+0x36);
            for(int i=0;i<(int)(62-header->caplen);i++){
                data->payload[7-i]=0;
            }
            for(int i=0;i<8;i++){
                printf("%02x ",data->payload[i]);
            }

            printf("\n");
        }else{
            printf("00 00 00 00 00 00 00 00");
        }
        printf("=====================================\n");
    }

	pcap_close(pcap);
}
