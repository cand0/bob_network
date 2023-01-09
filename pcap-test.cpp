#include <pcap.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <map>
#include <vector>

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
FLAG *flag;

vector<RESULT> result;
int power;

bool parse(Param* param, int argc, char* argv[]) {
	if (argc != 2) {
		usage();
		return false;
	}
	param->dev_ = argv[1];
	return true;
}

void print_screen(int ssid_length){
	printf("\033[H\033[J\n");
	printf("BSSID\t\t  \t\tbeacons \tPWR \t\tESSID \n");
	printf("============================================================================================\n");

	for (int i = 0; i < result.size(); i++){
		printf("%02x:%02x:%02x:%02x:%02x:%02x", result[i].bssid[0], result[i].bssid[1], result[i].bssid[2], result[i].bssid[3], result[i].bssid[4], result[i].bssid[5]);	//BSSID
		printf("\t\t%d", result[i].beacons);				//beacons count
		printf("\t");
		printf("\t%d \t\t", result[i].pwr);
		printf("%s", result[i].essid);
		printf("\n");		
	}

}

int analysis_flags(const u_char* packet){
	int idx = 16-4;						//start -> flag까지

	flag = (FLAG*)packet+4;

	if(!(flag->flag & 0x20))			// 0x20이 아니면 power를 측정하지 않음
		return 0;

	if(flag->flag & 0x1)	// mac timestamp가 들어가 있음
		idx += 8;
	if(flag->flag & 0x2)	// Flags
		idx += 1;
	if(flag->flag & 0x4)	// Rate
		idx += 4;
	if(flag->flag & 0x8)	// Channel 
		idx += 4;
	if(flag->flag & 0x10)	// FHSS
		idx += 1;
	if(flag->flag & 0x80000000)	//present flag 필드가 하나 더 있음
		idx += 4;
	return *(int8_t*)(packet + idx + 1);		// int로 그냥 보내면 -가 안됨 -> byte로 바꿔줌
}

void analysis_packet(int len, const u_char* packet){
    rth = (RTH*)packet;
    dp = (DP*)(packet+rth->it_len);
    bd = (BD*)(packet + rth->it_len + sizeof(ieee80211_header) - 1);

    essid = (ESSID*)(packet + rth->it_len-1 + sizeof(ieee80211_header) - 1 + sizeof(beacon_data) -1);
	uint8_t rbssid[7];
    char ressid[32];
	int chk = 1;

	//bssid 변수 저장
	for (int i = 0; i < sizeof(rbssid); i++){
		rbssid[i] = dp->bssid[i];
	}

    if (dp->sub_type == 0x80){      // sub_type == 0x80 -> beaconf packet filter
        if(essid->ESSID[0] != 00){  // SSID 중 0x00이 있는 값이 있던 것 삭제
			memset(ressid, 0x00, sizeof(ressid));				//essid 끝에 값 꺠지는거 제거
            memcpy(ressid, essid->ESSID, bd->ssid_length);		//SSID
			power = analysis_flags(packet);						//PWR

			struct result tmp;

			for(int i = 0; i < sizeof(rbssid); i++){
				tmp.bssid[i] = rbssid[i];
			}
			tmp.pwr = power;

			for(int i = 0; i< sizeof(ressid); i++){
				tmp.essid[i] = ressid[i];
			}

			for (int i = 0; i < (int)result.size(); i++){				
				if (!memcmp(result[i].bssid, dp->bssid, 6)){
					result[i].beacons++;
					chk = 0;
				}
			}
			if (chk){
				result.push_back(tmp);
			}
			
			print_screen(bd->ssid_length);
		}
    }
}


int main(int argc, char* argv[]) {
	if (!parse(&param, argc, argv)){
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
    printf("BSSID\t\t    beacons \tPWR \tESSID \n");
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
