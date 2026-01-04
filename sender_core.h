#ifndef SENDER_CORE_H
#define SENDER_CORE_H

#include <atomic>

// ============================================================================
// [优化] 常量定义 - 消除魔法数字
// ============================================================================
namespace PacketConfig {
// 网络协议常量
constexpr unsigned int MAX_UDP_LENGTH = 65535;         // UDP 最大长度
constexpr unsigned int MIN_ETHERNET_FRAME = 60;        // 以太网最小帧长度（字节）
constexpr unsigned int MAX_PACKET_BUFFER_SIZE = 10000; // 数据包缓冲区最大大小（字节）

// 批量发送配置
constexpr unsigned int BURST_BATCH_SIZE = 2048;           // 突发模式批量包数量
constexpr unsigned int MAX_BATCH_SIZE = 5000;             // 正常模式最大批量包数量
constexpr unsigned int QUEUE_MEMORY_OVERHEAD = 1000;      // 队列内存额外空间（字节）
constexpr unsigned int NORMAL_MODE_QUEUE_ESTIMATE = 2000; // 正常模式队列估算大小（字节）

// 时间配置（微秒）
constexpr unsigned int TARGET_BATCH_TIME_US = 1000000; // 目标批量时间（1秒）
constexpr unsigned int MIN_SLEEP_THRESHOLD_US = 1000;  // 最小睡眠阈值（微秒）

// 统计更新间隔（毫秒）
constexpr unsigned int STATS_UPDATE_INTERVAL_MS = 200;       // 原始包模式统计更新间隔
constexpr unsigned int SOCKET_STATS_UPDATE_INTERVAL_MS = 30; // Socket模式统计更新间隔

// TCP 连接配置
constexpr int TCP_CONNECT_MAX_RETRIES = 30; // TCP连接最大重试次数

// PCAP 配置
constexpr int PCAP_SNAPLEN = 65535; // PCAP 抓包长度
} // namespace PacketConfig

#ifdef __cplusplus
extern std::atomic<bool> g_is_sending;
extern std::atomic<uint64_t> g_total_sent;
extern std::atomic<uint64_t> g_total_bytes;

extern std::atomic<bool> g_is_sock_sending;
extern std::atomic<uint64_t> g_sock_total_sent;
extern std::atomic<uint64_t> g_sock_total_bytes;

typedef void (*StatsCallback)(uint64_t total_sent, uint64_t total_bytes, void* user_data);

// [新增] Hex 数据回调定义
typedef void (*HexCallback)(const unsigned char* data, int len, void* user_data);

// [新增] 错误回调定义
typedef void (*ErrorCallback)(const char* error_msg, void* user_data);

extern "C" {
#endif

enum PayloadMode { PAYLOAD_RANDOM = 0, PAYLOAD_FIXED = 1, PAYLOAD_CUSTOM = 2 };

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

    // [新增] 错误回调指针
    ErrorCallback error_callback;

    // [新增] 用户数据指针，用于回调上下文
    void* user_data;

    // [新增] SYN Flood 模式配置
    bool use_random_src_port;  // 是否使用随机源端口（SYN Flood模式）
    bool use_random_seq;       // 是否使用随机序列号（SYN Flood模式）
    bool use_random_src_mac;   // 是否使用随机源MAC地址（SYN Flood模式）
    bool use_random_src_ip;    // 是否使用随机源IP地址（SYN Flood模式）
    
    // [新增] 随机IP地址范围配置（用于use_random_src_ip）
    unsigned char random_ip_base[4];  // 基础IP地址（用于计算随机IP范围）
    unsigned char random_ip_mask[4];  // 子网掩码（用于限制随机IP范围）

    // [新增] 停止标志位指针，支持多线程独立控制
    std::atomic<bool>* stop_flag;
};

typedef void (*LogCallback)(const char* msg, int level, void* user_data);

struct SocketConfig {
    char target_ip[32];
    unsigned short target_port;
    char source_ip[32];
    unsigned short source_port; // [新增] 固定源端口
    bool is_udp;
    bool is_connect_only;
    
    // [新增] 随机化选项
    bool use_random_src_port;
    bool use_random_src_mac;
    bool use_random_src_ip;
    bool use_random_seq;
    
    // [新增] 随机IP范围
    unsigned char random_ip_base[4];
    unsigned char random_ip_mask[4];
    unsigned char src_mac[6]; // 基础MAC用于随机化参考

    int payload_len;
    unsigned int interval_us;
    StatsCallback stats_callback;
    LogCallback log_callback;
    
    // [新增] 用户数据指针
    void* user_data;

    // [新增] 增加网卡名称，用于在伪造模式下进行监听和注入
    char dev_name[256];

    // [新增] 停止标志位指针，支持多线程独立控制
    std::atomic<bool>* stop_flag;
};

__declspec(dllexport) void start_send_mode(const SenderConfig* config);
__declspec(dllexport) void start_socket_send_mode(const SocketConfig* config);

#ifdef __cplusplus
}
#endif

#endif // SENDER_CORE_H
