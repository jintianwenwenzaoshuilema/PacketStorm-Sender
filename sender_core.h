#ifndef SENDER_CORE_H
#define SENDER_CORE_H

#include <atomic>

#ifdef __cplusplus
// === 1. 全局控制标志 ===
extern std::atomic<bool> g_is_sending; // 只保留发送标志

extern "C" {
#endif

// 包类型常量
#define UDP_PACKAGE  1
#define TCP_PACKAGE  2
#define ICMP_PACKAGE 3
#define DNS_PACKAGE  4

// === 启动发送 ===
__declspec(dllexport) void start_send_mode(
    const char* dev_name,
    const unsigned char src_mac[6],
    const unsigned char des_mac[6],
    const unsigned char src_ip[4],
    const unsigned char des_ip[4],
    unsigned int send_interval_us,
    unsigned short packet_type,
    unsigned short src_port,
    unsigned short dst_port,
    unsigned short payload_len,
    unsigned char tcp_flags,
    const char* domain_url
    );

#ifdef __cplusplus
} // extern "C"
#endif

#endif // SENDER_CORE_H
