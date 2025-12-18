#ifndef SENDER_CORE_H
#define SENDER_CORE_H

#include <atomic>

#ifdef __cplusplus
extern std::atomic<bool> g_is_sending;
extern std::atomic<uint64_t> g_total_sent;
extern std::atomic<uint64_t> g_total_bytes;

extern std::atomic<bool> g_is_sock_sending;
extern std::atomic<uint64_t> g_sock_total_sent;
extern std::atomic<uint64_t> g_sock_total_bytes;

typedef void (*StatsCallback)(uint64_t total_sent, uint64_t total_bytes);

// [新增] Hex 数据回调定义
typedef void (*HexCallback)(const unsigned char* data, int len);

extern "C" {
#endif

enum PayloadMode {
    PAYLOAD_RANDOM = 0,
    PAYLOAD_FIXED = 1,
    PAYLOAD_CUSTOM = 2
};

#define UDP_PACKAGE 1
#define TCP_PACKAGE 2
#define ICMP_PACKAGE 3
#define DNS_PACKAGE 4
#define ARP_PACKAGE 5

struct SenderConfig {
    char dev_name[256];
    unsigned char src_mac[6];
    unsigned char des_mac[6];
    unsigned char src_ip[4];
    unsigned char des_ip[4];

    unsigned int send_interval_us;
    unsigned short packet_type;

    unsigned short src_port;
    unsigned short dst_port;
    unsigned char tcp_flags;

    PayloadMode payload_mode;
    unsigned int payload_len;
    unsigned char fixed_byte_val;
    const char* custom_data;
    int custom_data_len;

    char dns_domain[256];
    StatsCallback stats_callback;

    // [新增] Hex 数据回调指针
    HexCallback hex_callback;
};

typedef void (*LogCallback)(const char* msg, int level);

struct SocketConfig {
    char target_ip[32];
    unsigned short target_port;
    char source_ip[32];
    bool is_udp;
    int payload_len;
    unsigned int interval_us;
    StatsCallback stats_callback;
    LogCallback log_callback;
};

__declspec(dllexport) void start_send_mode(const SenderConfig* config);
__declspec(dllexport) void start_socket_send_mode(const SocketConfig* config);

#ifdef __cplusplus
}
#endif

#endif // SENDER_CORE_H
