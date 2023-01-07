#include <pcap.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>

#include "pcap-test.h"

void usage() {
	printf("syntax: pcap-test <interface>\n");
	printf("sample: pcap-test wlan0\n");
}
typedef struct {
	char* dev_;
} Param;
Param param = {
	.dev_ = NULL
};

RTH *rth;
DP *dp;
BD *bd;
ESSID * essid;

bool parse(Param* param, int argc, char* argv[]) {
	if (argc != 2) {
		usage();
		return false;
	}
	param->dev_ = argv[1];
// 아래의 코드는 param.dev_에 mon0 즉 인터페이스가 입력 되는 것을 확인하는 것이다.
//    printf("\n %s \n", param->dev_); 
	return true;
}

void analysis_packet(int len, const u_char* packet){
    rth = (RTH*)packet;
    dp = (DP*)(packet+rth->it_len);
    bd = (BD*)(packet + rth->it_len + sizeof(ieee80211_header) - 1);
    essid = (ESSID*)(packet + rth->it_len-1 + sizeof(ieee80211_header) - 1 + sizeof(beacon_data) -1);
    char ressid[32];

    if (dp->sub_type == 0x80){      // sub_type == 0x80 -> beaconf packet filter
        if(essid->ESSID[0] != 00){  // SSID 중 0x00이 있는 값이 있던데.... 삭제...
//            printf("bd->ssid_length : %d \n", bd->ssid_length);
            memcpy(ressid, essid->ESSID, bd->ssid_length);
            printf("%02x:%02x:%02x:%02x:%02x:%02x", dp->bssid[0], dp->bssid[1], dp->bssid[2], dp->bssid[3], dp->bssid[4], dp->bssid[5]);        
            printf("  ");
            //끝에 \0으로 안끝나다 보니 이상한 문자도 같이 출력 -> 길이 만큼 글자 하나하나 추가
            for(int i = 0; i <= bd->ssid_length-1; i++){
                printf("%c", ressid[i]);
            }
            printf("\n");
        }
    }
}


int main(int argc, char* argv[]) {


	if (!parse(&param, argc, argv)){
        printf("cand1_Error");
		return -1;
    }
	char errbuf[PCAP_ERRBUF_SIZE];  // PCAP_ERRBUF_SIZE = 256

	pcap_t* pcap = pcap_open_live(param.dev_, BUFSIZ, 1, 1000, errbuf);

    // pcap의 에러처리 -> 값을 못받아 올 때
	if (pcap == NULL) {
		fprintf(stderr, "pcap_open_live(%s) return null - %s\n", param.dev_, errbuf);
		return -1;
	}

    // 실제 데이터의 처리를 해야 하는 부분
    printf("BSSID             ESSID \n");
	while (true) {
		struct pcap_pkthdr* header;
		const u_char* packet;
		int res = pcap_next_ex(pcap, &header, &packet);     // res == pcap의 데이터를 잘못 가져올 경우 에러 처리를 위함
		if (res == 0) continue;
		if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {
			printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(pcap));
			break;
		}
//        printf("=====%d===", packet);
//		printf("%u bytes captured\n", header->caplen);

        // 패킷의 크기와 실제 내용을 전달
        analysis_packet(header->len, packet);
//        printf("-------------\n");
//        printf("%x", header->len);
//        printf("-------------\n");
	}

	pcap_close(pcap);
}
