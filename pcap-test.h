#include <pcap.h>

// radiotap_header
typedef struct ieee80211_radiotap_header {
        u_int8_t        it_version;     /* set to 0 */
        u_int8_t        it_pad;
        u_int16_t       it_len;         /* entire length */
        u_int32_t       it_present;     /* fields present */
} __attribute__((__packed__)) RTH;

typedef struct ieee80211_header {
    uint8_t sub_type;
    uint8_t flags;
    uint16_t duration_id;
    uint8_t dstaddr[6];
    uint8_t srcaddr[6];
    uint8_t bssid[6];
    uint16_t seq_ctl;
    uint8_t payload;
} __attribute__((__packed__)) DP;

typedef struct beacon_data {
    uint64_t timestamp;
    uint16_t beacon_interval;
    uint16_t capa_info;
    uint8_t  ssid_elementID;
    uint8_t  ssid_length;
} BD;

typedef struct flags {
    uint8_t flag;
} FLAG;

typedef struct ssid{
    uint8_t   ESSID[32];
} ESSID;

typedef struct result{
    uint8_t bssid[6];
    int beacons;
    int pwr;
    char essid[32];
} RESULT;
