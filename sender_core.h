#ifndef SENDER_CORE_H
#define SENDER_CORE_H

#include <atomic>

#ifdef __cplusplus
// 全局停止标志
extern std::atomic<bool> g_is_sending;

extern std::atomic<uint64_t> g_total_sent;   // 总发包数
extern std::atomic<uint64_t> g_total_bytes;  // 总发送字节数

typedef void (*StatsCallback)(uint64_t total_sent, uint64_t total_bytes);

extern "C" {
#endif

// === 1. 定义填充模式枚举 ===
enum PayloadMode {
    PAYLOAD_RANDOM = 0, // 随机字节
    PAYLOAD_FIXED  = 1, // 固定字节 (例如全 0x00 或 全 0xFF)
    PAYLOAD_CUSTOM = 2  // 用户自定义字符串
};

// 包类型常量
#define UDP_PACKAGE  1
#define TCP_PACKAGE  2
#define ICMP_PACKAGE 3
#define DNS_PACKAGE  4

// === 2. 定义配置结构体 (优化参数传递) ===
struct SenderConfig {
    // --- 基础网络参数 ---
    char dev_name[256];
    unsigned char src_mac[6];
    unsigned char des_mac[6];
    unsigned char src_ip[4];
    unsigned char des_ip[4];

    // --- 发送控制 ---
    unsigned int send_interval_us;
    unsigned short packet_type;

    // --- 传输层参数 ---
    unsigned short src_port;
    unsigned short dst_port;
    unsigned char tcp_flags;

    // --- 载荷控制 (新增) ---
    PayloadMode payload_mode;      // 填充模式
    unsigned int payload_len;      // 载荷长度
    unsigned char fixed_byte_val;  // 固定填充值 (当模式为 FIXED 时)
    const char* custom_data;       // 自定义数据指针 (当模式为 CUSTOM 时)
    int custom_data_len;           // 自定义数据实际长度 (方便处理)

    // --- 应用层 ---
    char dns_domain[256];
    StatsCallback stats_callback;
};

// === 3. 启动发送 (参数简化为结构体指针) ===
__declspec(dllexport) void start_send_mode(const SenderConfig* config);

#ifdef __cplusplus
} // extern "C"
#endif

#endif // SENDER_CORE_H
