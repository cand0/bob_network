#include <pcap.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <map>
using namespace std;

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
map <char, int> beacons;

bool parse(Param* param, int argc, char* argv[]) {
	if (argc != 2) {
		usage();
		return false;
	}
	param->dev_ = argv[1];
	return true;
}


void analysis_packet(int len, const u_char* packet){

    rth = (RTH*)packet;
    dp = (DP*)(packet+rth->it_len);
    bd = (BD*)(packet + rth->it_len + sizeof(ieee80211_header) - 1);

    essid = (ESSID*)(packet + rth->it_len-1 + sizeof(ieee80211_header) - 1 + sizeof(beacon_data) -1);
	uint8_t rbssid[7];
    char ressid[32];

	//bssid 변수 저장
	for (int i = 0; i < sizeof(rbssid); i++){
		rbssid[i] = dp->bssid[i];
	}

    if (dp->sub_type == 0x80){      // sub_type == 0x80 -> beaconf packet filter
        if(essid->ESSID[0] != 00){  // SSID 중 0x00이 있는 값이 있던 것 삭제
			beacons[rbssid[0]] += 1;

            memcpy(ressid, essid->ESSID, bd->ssid_length);
			printf("%02x:%02x:%02x:%02x:%02x:%02x", rbssid[0], rbssid[1], rbssid[2], rbssid[3], rbssid[4], rbssid[5]);
			printf("\t%d", beacons.at(rbssid[0]));
            printf("\t");
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
    printf("BSSID\t\t beacons \t\tESSID \n");
	while (true) {
		struct pcap_pkthdr* header;
		const u_char* packet;
		int res = pcap_next_ex(pcap, &header, &packet);     // res == pcap의 데이터를 잘못 가져올 경우 에러 처리를 위함
		if (res == 0) continue;
		if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {
			printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(pcap));
			break;
		}

        analysis_packet(header->len, packet);
	}

	pcap_close(pcap);
}
