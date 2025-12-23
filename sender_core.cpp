#include "sender_core.h"
#include <chrono>
#include <iostream>
#include <pcap.h>
#include <random>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <string>
#include <thread>
#include <vector>
#include <ws2tcpip.h>

#ifndef WIN32
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>

#else
#include <winsock.h>
#endif

using namespace std;

// === Global Control Flags ===
std::atomic<bool> g_is_sending{false};
std::atomic<uint64_t> g_total_sent{0};
std::atomic<uint64_t> g_total_bytes{0};

// === [优化] 线程局部随机数生成器 ===
// 使用线程局部存储，每个线程有独立的随机数生成器，避免竞争
thread_local std::mt19937* g_rng = nullptr;
thread_local std::uniform_int_distribution<unsigned int>* g_byte_dist = nullptr;

static void init_random_generator() {
    if (!g_rng) {
        std::random_device rd;
        g_rng = new std::mt19937(rd());
        // uniform_int_distribution 不支持 unsigned char，使用 unsigned int 然后转换
        g_byte_dist = new std::uniform_int_distribution<unsigned int>(0, 255);
    }
}

static unsigned char get_random_byte() {
    init_random_generator();
    return static_cast<unsigned char>((*g_byte_dist)(*g_rng));
}

static unsigned short get_random_ushort() {
    init_random_generator();
    std::uniform_int_distribution<unsigned int> dist(0, PacketConfig::MAX_UDP_LENGTH);
    return static_cast<unsigned short>(dist(*g_rng));
}

// [新增] 生成随机MAC地址（避免多播位和本地管理位）
static void get_random_mac(unsigned char* mac) {
    init_random_generator();
    std::uniform_int_distribution<unsigned int> byte_dist(0, 255);
    
    // MAC地址格式：XX:XX:XX:XX:XX:XX
    // 第一个字节的最低位（bit 0）必须为0（单播地址）
    // 第一个字节的次低位（bit 1）必须为0（全局管理地址，非本地管理）
    // 所以第一个字节的范围是：0x00-0xFD（排除0xFE和0xFF）
    mac[0] = (unsigned char)(byte_dist(*g_rng) & 0xFE); // 确保bit 0为0
    if (mac[0] >= 0xFE) mac[0] = 0xFC; // 确保bit 1也为0
    
    // 其余5个字节可以是任意值（0-255）
    for (int i = 1; i < 6; ++i) {
        mac[i] = (unsigned char)byte_dist(*g_rng);
    }
}

// [新增] 生成随机IP地址（基于子网范围）
static void get_random_ip(const unsigned char* base_ip, const unsigned char* mask, unsigned char* out_ip) {
    init_random_generator();
    std::uniform_int_distribution<unsigned int> byte_dist(0, 255);
    
    // 计算网络地址
    unsigned char network[4];
    for (int i = 0; i < 4; ++i) {
        network[i] = base_ip[i] & mask[i];
    }
    
    // 生成网络范围内的随机IP
    // 对于每个字节：
    // - 如果掩码字节为255，使用网络地址的该字节（保持不变）
    // - 如果掩码字节为0，完全随机
    // - 如果掩码字节在中间，需要按位处理（简化处理：如果掩码不是0或255，使用网络地址）
    for (int i = 0; i < 4; ++i) {
        if (mask[i] == 255) {
            // 掩码为255，该字节必须与网络地址相同
            out_ip[i] = network[i];
        } else if (mask[i] == 0) {
            // 掩码为0，该字节完全随机
            out_ip[i] = (unsigned char)byte_dist(*g_rng);
        } else {
            // 掩码在中间（如128, 192等），简化处理：使用网络地址部分+随机部分
            // 为了简化，这里也使用随机值，但实际应该按位处理
            out_ip[i] = (unsigned char)byte_dist(*g_rng);
        }
    }
    
    // 确保生成的IP不是网络地址（最后一个字节为0）或广播地址（最后一个字节为255）
    // 对于/24子网，只需要检查最后一个字节
    if (mask[3] == 0) {
        // 如果最后一个字节的掩码为0，确保不是0或255
        if (out_ip[3] == 0) out_ip[3] = 1;
        if (out_ip[3] == 255) out_ip[3] = 254;
    } else if (mask[3] == 255) {
        // 如果最后一个字节的掩码为255，使用网络地址（但通常不会是0，因为base_ip[3]通常是0）
        // 这里保持原值
    } else {
        // 其他情况，确保不是0或255
        if (out_ip[3] == 0) out_ip[3] = 1;
        if (out_ip[3] == 255) out_ip[3] = 254;
    }
}

// === Socket Specific Variables ===
std::atomic<bool> g_is_sock_sending{false};
std::atomic<uint64_t> g_sock_total_sent{0};
std::atomic<uint64_t> g_sock_total_bytes{0};

#pragma pack(1)

/* ==========================================================================
   Helper: Payload Filling
   ========================================================================== */
static void fill_payload_data(unsigned char* data_ptr, int target_len, const SenderConfig* cfg) {
    if (target_len <= 0) return;
    switch (cfg->payload_mode) {
        case PAYLOAD_FIXED:
            memset(data_ptr, cfg->fixed_byte_val, target_len);
            break;
        case PAYLOAD_CUSTOM:
            if (cfg->custom_data && cfg->custom_data_len > 0) {
                int filled = 0;
                while (filled < target_len) {
                    int rem = target_len - filled;
                    int copy = (rem > cfg->custom_data_len) ? cfg->custom_data_len : rem;
                    memcpy(data_ptr + filled, cfg->custom_data, copy);
                    filled += copy;
                }
            } else {
                memset(data_ptr, 0, target_len);
            }
            break;
        case PAYLOAD_RANDOM:
        default:
            // [优化] 使用 C++11 随机数生成器替代 rand()
            for (int i = 0; i < target_len; ++i) data_ptr[i] = get_random_byte();
            break;
    }
}

/* ==========================================================================
   Protocol Headers
   ========================================================================== */
struct ip_v4_address {
    u_char byte1, byte2, byte3, byte4;
};
struct mac_address {
    u_char byte1, byte2, byte3, byte4, byte5, byte6;
};

struct ethernet_header {
    mac_address des_mac_addr;
    mac_address src_mac_addr;
    u_short type;
};

// [新增] ARP 头部结构
struct arp_header {
    u_short htype;     // Hardware type (Ethernet = 1)
    u_short ptype;     // Protocol type (IPv4 = 0x0800)
    u_char hlen;       // Hardware address length (6)
    u_char plen;       // Protocol address length (4)
    u_short oper;      // Operation (Request=1, Reply=2)
    mac_address sha;   // Sender Hardware Address
    ip_v4_address spa; // Sender Protocol Address
    mac_address tha;   // Target Hardware Address
    ip_v4_address tpa; // Target Protocol Address
};

struct ip_v4_header {
    u_char ver_ihl;
    u_char tos;
    u_short tlen;
    u_short identification;
    u_short flags_fo;
    u_char ttl;
    u_char proto;
    u_short checksum;
    ip_v4_address src_ip_addr;
    ip_v4_address des_ip_addr;
    u_int op_pad;
};

struct udp_header {
    u_short sport;
    u_short dport;
    u_short len;
    u_short checksum;
};

struct tcp_header {
    u_short sport;
    u_short dport;
    u_int sequence;
    u_int acknowledgement;
    u_char offset;
    u_char flags;
    u_short windows;
    u_short checksum;
    u_short urgent_pointer;
};

struct icmp_echo {
    uint8_t type;
    uint8_t code;
    uint16_t checksum;
    uint16_t ident;
    uint16_t seq;
};

struct psd_header {
    ip_v4_address s_ip;
    ip_v4_address d_ip;
    u_char mbz;
    u_char proto;
    u_short plen;
};

struct dns_header {
    unsigned short id;
    unsigned short flags;
    unsigned short questions;
    unsigned short answer;
    unsigned short authority;
    unsigned short additional;
};

struct dns_queries {
    int length;
    unsigned short qtype;
    unsigned short qclass;
    char* name;
};
#pragma pack()

/* ==========================================================================
   Checksum & Builders
   ========================================================================== */
static u_short checksum(u_short* buffer, int size) {
    unsigned long cksum = 0;
    while (size > 1) {
        cksum += *buffer++;
        size -= sizeof(u_short);
    }
    if (size) {
        cksum += *(u_short*)buffer;
    }
    cksum = (cksum >> 16) + (cksum & 0xffff);
    cksum += (cksum >> 16);
    return (u_short)(~cksum);
}

static uint16_t calculate_checksum(unsigned char* buffer, int bytes) {
    uint32_t checksum_val = 0;
    unsigned char* end = buffer + bytes;
    if (bytes % 2 == 1) {
        end = buffer + bytes - 1;
        checksum_val += (*end) << 8;
    }
    while (buffer < end) {
        checksum_val += buffer[0] << 8;
        checksum_val += buffer[1];
        buffer += 2;
    }
    uint32_t carry = checksum_val >> 16;
    while (carry) {
        checksum_val = (checksum_val & 0xffff) + carry;
        carry = checksum_val >> 16;
    }
    checksum_val = ~checksum_val;
    return (uint16_t)(checksum_val & 0xffff);
}

static void build_ethernet_header(unsigned char* package, const u_char des_mac[6], const u_char src_mac[6],
                                  u_short type) {
    ethernet_header* eh = (ethernet_header*)package;
    memcpy(&eh->des_mac_addr, des_mac, 6);
    memcpy(&eh->src_mac_addr, src_mac, 6);
    eh->type = htons(type);
}

// [修改] 增加 seq_num 参数
static void build_arp_header(unsigned char* package, int seq_num, const SenderConfig* cfg) {
    arp_header* ah = (arp_header*)(package + 14); // Ethernet header is 14 bytes

    ah->htype = htons(1);      // Ethernet
    ah->ptype = htons(0x0800); // IPv4
    ah->hlen = 6;
    ah->plen = 4;
    ah->oper = htons(1); // 1 = ARP Request (Default)

    // === [关键修改] Sender MAC (SHA) ===
    // 我们将 seq_num 嵌入到 Sender MAC 的后 4 个字节中，作为唯一 ID。
    // 这样每个 ARP 包都有唯一的 "Sender MAC"，接收端回复时会发给这个 MAC。
    // 保留前 2 个字节 (byte1, byte2) 使用用户配置的值 (通常是厂商 OUI)，
    // 后 4 个字节 (byte3-6) 变成序列号。

    // 1. 先复制用户配置的基础 MAC
    memcpy(&ah->sha, cfg->src_mac, 6);

    // 2. 覆盖后 4 个字节为 seq_num
    ah->sha.byte3 = (seq_num >> 24) & 0xFF;
    ah->sha.byte4 = (seq_num >> 16) & 0xFF;
    ah->sha.byte5 = (seq_num >> 8) & 0xFF;
    ah->sha.byte6 = (seq_num) & 0xFF;

    // Sender IP (SPA) - 保持不变
    memcpy(&ah->spa, cfg->src_ip, 4);

    // Target MAC (THA) - 保持不变
    memcpy(&ah->tha, cfg->des_mac, 6);

    // Target IP (TPA) - 保持不变
    memcpy(&ah->tpa, cfg->des_ip, 4);
}

static void build_ip_header(u_char* package, const u_char src_ip[4], const u_char des_ip[4], u_short ip_len,
                            u_char proto_type) {
    ip_v4_header* ih = (ip_v4_header*)(package + 14);
    ih->ver_ihl = 0x45;
    ih->tos = 0x00;
    ih->tlen = htons(ip_len);
    ih->identification = 0;
    ih->flags_fo = htons(0x4000);
    ih->ttl = 0x80;
    ih->proto = proto_type;
    ih->checksum = 0;
    memcpy(&ih->src_ip_addr, src_ip, 4);
    memcpy(&ih->des_ip_addr, des_ip, 4);
    ih->checksum = checksum((u_short*)ih, 20);
}

static void build_udp_header(unsigned char* package, u_short s_port, u_short d_port, u_short udp_len) {
    udp_header* uh = (udp_header*)(package + 14 + 20);
    ip_v4_header* ih = (ip_v4_header*)(package + 14);
    uh->sport = htons(s_port);
    uh->dport = htons(d_port);
    uh->len = htons(udp_len);
    uh->checksum = 0;

    psd_header psd;
    psd.s_ip = ih->src_ip_addr;
    psd.d_ip = ih->des_ip_addr;
    psd.mbz = 0;
    psd.proto = 0x11;
    psd.plen = htons(udp_len);

    // [优化] 使用栈缓冲区替代堆分配，最大 UDP 长度 + psd_header
    constexpr int MAX_UDP_PSEUDO_LEN = sizeof(psd_header) + PacketConfig::MAX_UDP_LENGTH;
    if (udp_len > PacketConfig::MAX_UDP_LENGTH) return; // 安全检查

    int pseudo_len = sizeof(psd) + udp_len;
    // 对于小包使用栈缓冲区，大包使用动态分配（但这种情况很少）
    if (pseudo_len <= MAX_UDP_PSEUDO_LEN) {
        char tmp[MAX_UDP_PSEUDO_LEN];
        memcpy(tmp, &psd, sizeof(psd));
        memcpy(tmp + sizeof(psd), uh, udp_len);
        uh->checksum = checksum((u_short*)tmp, pseudo_len);
    } else {
        // 极端情况：使用动态分配（理论上不会发生，因为 UDP 最大长度有限制）
        std::vector<char> tmp(pseudo_len);
        memcpy(tmp.data(), &psd, sizeof(psd));
        memcpy(tmp.data() + sizeof(psd), uh, udp_len);
        uh->checksum = checksum((u_short*)tmp.data(), pseudo_len);
    }
}

static void build_tcp_header(unsigned char* package, u_short s_port, u_short d_port, u_int seq, u_int ack, u_char flags,
                             u_short win, u_short tcp_payload_len, const u_char* src_ip, const u_char* dst_ip) {
    tcp_header* th = (tcp_header*)(package + 14 + 20);
    th->sport = htons(s_port);
    th->dport = htons(d_port);
    th->sequence = htonl(seq);
    th->acknowledgement = htonl(ack);
    th->offset = (5 << 4);
    th->flags = flags;
    th->windows = htons(win);
    th->urgent_pointer = 0;
    th->checksum = 0;

    int tcp_total_len = 20 + tcp_payload_len;
    psd_header psd;
    memcpy(&psd.s_ip, src_ip, 4);
    memcpy(&psd.d_ip, dst_ip, 4);
    psd.mbz = 0;
    psd.proto = 0x06;
    psd.plen = htons((u_short)tcp_total_len);

    // [优化] 使用栈缓冲区替代堆分配，最大 TCP 数据长度通常不超过 1460 (MTU - IP - TCP)
    constexpr int MAX_TCP_PSEUDO_LEN = sizeof(psd_header) + 20 + 1460;
    int pseudo_total_len = sizeof(psd) + tcp_total_len;

    if (pseudo_total_len <= MAX_TCP_PSEUDO_LEN) {
        // 常见情况：使用栈缓冲区
        char tmp[MAX_TCP_PSEUDO_LEN];
        memcpy(tmp, &psd, sizeof(psd));
        memcpy(tmp + sizeof(psd), th, 20);
        if (tcp_payload_len > 0) memcpy(tmp + sizeof(psd) + 20, package + 14 + 20 + 20, tcp_payload_len);
        th->checksum = checksum((u_short*)tmp, pseudo_total_len);
    } else {
        // 极端情况：使用动态分配（理论上很少发生）
        std::vector<char> tmp(pseudo_total_len);
        memcpy(tmp.data(), &psd, sizeof(psd));
        memcpy(tmp.data() + sizeof(psd), th, 20);
        if (tcp_payload_len > 0) memcpy(tmp.data() + sizeof(psd) + 20, package + 14 + 20 + 20, tcp_payload_len);
        th->checksum = checksum((u_short*)tmp.data(), pseudo_total_len);
    }
}

static void build_icmp_header(unsigned char* package, int seq_num, int payload_len, const SenderConfig* cfg) {
    icmp_echo* icmph = (icmp_echo*)(package + 14 + 20);
    int icmp_total_len = 8 + payload_len;
    memset(icmph, 0, icmp_total_len);
    icmph->type = 8;
    icmph->code = 0;
    icmph->checksum = 0;
    // [修复] 使用随机 ident，更符合实际 ping 工具的行为
    icmph->ident = htons(get_random_ushort());
    icmph->seq = htons((uint16_t)seq_num);

    unsigned char* data_ptr = (unsigned char*)(package + 14 + 20 + 8);
    fill_payload_data(data_ptr, payload_len, cfg);
    icmph->checksum = htons(calculate_checksum((unsigned char*)icmph, icmp_total_len));
}

static int dns_create_header(struct dns_header* header) {
    if (!header) return -1;
    memset(header, 0, sizeof(struct dns_header));
    // [优化] 使用 C++11 随机数生成器替代 rand()
    header->id = get_random_ushort();
    header->flags = htons(0x0100);
    header->questions = htons(1);
    return 0;
}
// [优化] 修改函数签名，返回 vector 而不是修改 question->name
// 这样调用者可以管理内存生命周期
static std::vector<char> dns_create_queries(const char* hostname, int* out_length) {
    std::vector<char> name_buffer;
    if (!hostname) {
        if (out_length) *out_length = 0;
        return name_buffer;
    }

    size_t len = strlen(hostname);
    name_buffer.resize(len + 2, 0);
    char* qname = name_buffer.data();

    // [优化] 使用 std::string 替代 strdup/strtok，更安全
    std::string host_str(hostname);
    size_t start = 0;
    size_t pos = host_str.find('.');
    while (pos != std::string::npos) {
        size_t tlen = pos - start;
        if (tlen > 0 && tlen <= 63) { // DNS 标签长度限制
            *qname++ = (char)tlen;
            memcpy(qname, host_str.c_str() + start, tlen);
            qname += tlen;
        }
        start = pos + 1;
        pos = host_str.find('.', start);
    }
    // 处理最后一个标签
    size_t tlen = host_str.length() - start;
    if (tlen > 0 && tlen <= 63) {
        *qname++ = (char)tlen;
        memcpy(qname, host_str.c_str() + start, tlen);
        qname += tlen;
    }
    *qname = 0;

    if (out_length) {
        *out_length = (int)(qname - name_buffer.data() + 1);
    }
    return name_buffer;
}
static void build_dns(unsigned char* package, const char* domain, int dns_package_len) {
    udp_header* uh = (udp_header*)(package + 14 + 20);
    ip_v4_header* ih = (ip_v4_header*)(package + 14);
    int udp_len = 8 + dns_package_len;
    uh->sport = htons(10086);
    uh->dport = htons(53);
    uh->len = htons((u_short)udp_len);
    uh->checksum = 0;

    struct dns_header header;
    dns_create_header(&header);

    // [优化] 使用 vector 管理 DNS 查询内存，自动释放
    int query_length = 0;
    std::vector<char> query_buffer = dns_create_queries(domain, &query_length);
    if (query_buffer.empty() || query_length == 0) {
        return; // 查询创建失败
    }

    char* req = (char*)(package + 14 + 20 + 8);
    memcpy(req, &header, sizeof(header));
    memcpy(req + sizeof(header), query_buffer.data(), query_length);
    u_short qtype = htons(1), qclass = htons(1);
    memcpy(req + sizeof(header) + query_length, &qtype, 2);
    memcpy(req + sizeof(header) + query_length + 2, &qclass, 2);

    psd_header psd;
    psd.s_ip = ih->src_ip_addr;
    psd.d_ip = ih->des_ip_addr;
    psd.mbz = 0;
    psd.proto = 0x11;
    psd.plen = htons((u_short)udp_len);

    // [优化] 使用栈缓冲区替代堆分配
    constexpr int MAX_DNS_PSEUDO_LEN = sizeof(psd_header) + PacketConfig::MAX_UDP_LENGTH;
    int pseudo_len = sizeof(psd) + udp_len;

    if (pseudo_len <= MAX_DNS_PSEUDO_LEN) {
        char tmp[MAX_DNS_PSEUDO_LEN];
        memcpy(tmp, &psd, sizeof(psd));
        memcpy(tmp + sizeof(psd), uh, udp_len);
        uh->checksum = checksum((u_short*)tmp, pseudo_len);
    } else {
        std::vector<char> tmp(pseudo_len);
        memcpy(tmp.data(), &psd, sizeof(psd));
        memcpy(tmp.data() + sizeof(psd), uh, udp_len);
        uh->checksum = checksum((u_short*)tmp.data(), pseudo_len);
    }
    // query_buffer 在函数结束时自动释放（RAII）
}

// === Build Package (Single) ===
static void build_package(unsigned char* package, int* package_len, int seq_num, const SenderConfig* cfg) {
    int udp_len, icmp_len, ip_len;
    unsigned short s_port = (cfg->src_port == 0) ? 10086 : cfg->src_port;
    unsigned short d_port = (cfg->dst_port == 0) ? 10086 : cfg->dst_port;

    switch (cfg->packet_type) {
        // [修改] ARP 构造逻辑
        case ARP_PACKAGE: {
            // Ethernet Header (14) + ARP Header (28) = 42 Bytes
            *package_len = 14 + 28;
            if (*package_len < PacketConfig::MIN_ETHERNET_FRAME)
                *package_len = PacketConfig::MIN_ETHERNET_FRAME; // Padding to min ethernet frame

            // 1. Ethernet Header (Type = 0x0806 for ARP)
            // 注意：以太网头的 Source MAC 我们通常保持不变（使用物理网卡真实 MAC），
            // 否则交换机可能会因为端口安全限制而丢包。
            // 我们只修改 ARP 载荷内部的 "Sender MAC" (SHA) 来做 ID 标记。
            build_ethernet_header(package, cfg->des_mac, cfg->src_mac, 0x0806);

            // 2. ARP Header (传入 seq_num)
            build_arp_header(package, seq_num, cfg);

            // 3. Padding (Zero out remaining bytes)
            int data_end = 14 + 28;
            if (*package_len > data_end) {
                memset(package + data_end, 0, *package_len - data_end);
            }
        } break;

        case UDP_PACKAGE:
            udp_len = 8 + cfg->payload_len;
            ip_len = 20 + udp_len;
            *package_len = 14 + ip_len;
            build_ethernet_header(package, cfg->des_mac, cfg->src_mac, 0x0800);
            build_ip_header(package, cfg->src_ip, cfg->des_ip, (unsigned short)ip_len, 0x11);
            fill_payload_data(package + 14 + 20 + 8, cfg->payload_len, cfg);
            build_udp_header(package, s_port, d_port, (unsigned short)udp_len);
            break;
        case ICMP_PACKAGE: {
            icmp_len = 8 + cfg->payload_len;
            ip_len = 20 + icmp_len;
            *package_len = 14 + ip_len;
            build_ethernet_header(package, cfg->des_mac, cfg->src_mac, 0x0800);
            build_ip_header(package, cfg->src_ip, cfg->des_ip, (unsigned short)ip_len, 0x01);
            build_icmp_header(package, seq_num, cfg->payload_len, cfg);
        } break;
        case DNS_PACKAGE: {
            const char* domain = (*cfg->dns_domain) ? cfg->dns_domain : "baidu.com";
            int dlen = (int)strlen(domain);
            int dns_pkg_len = 12 + dlen + 2 + 4;
            *package_len = 14 + 20 + 8 + dns_pkg_len;
            build_ethernet_header(package, cfg->des_mac, cfg->src_mac, 0x0800);
            build_ip_header(package, cfg->src_ip, cfg->des_ip, (unsigned short)(*package_len - 14), 0x11);
            build_dns(package, domain, dns_pkg_len);
        } break;
        case TCP_PACKAGE: {
            // [新增] SYN Flood 模式：随机源端口和随机序列号
            unsigned short actual_s_port = s_port;
            unsigned int actual_seq = seq_num;
            
            // [新增] 随机源MAC地址
            unsigned char actual_src_mac[6];
            if (cfg->use_random_src_mac) {
                get_random_mac(actual_src_mac);
            } else {
                memcpy(actual_src_mac, cfg->src_mac, 6);
            }
            
            // [新增] 随机源IP地址
            unsigned char actual_src_ip[4];
            if (cfg->use_random_src_ip) {
                get_random_ip(cfg->random_ip_base, cfg->random_ip_mask, actual_src_ip);
            } else {
                memcpy(actual_src_ip, cfg->src_ip, 4);
            }
            
            if (cfg->use_random_src_port) {
                // 使用随机源端口（范围：1024-65535，避免使用系统保留端口）
                init_random_generator();
                std::uniform_int_distribution<unsigned int> port_dist(1024, 65535);
                actual_s_port = (unsigned short)port_dist(*g_rng);
            }
            
            if (cfg->use_random_seq) {
                // 使用随机序列号（32位，包含0）
                init_random_generator();
                std::uniform_int_distribution<unsigned int> seq_dist(0, 0xFFFFFFFF);
                actual_seq = seq_dist(*g_rng);
            }
            
            int tcp_data_len = cfg->payload_len;
            int tcp_total_len = 20 + tcp_data_len;
            ip_len = 20 + tcp_total_len;
            *package_len = 14 + ip_len;
            build_ethernet_header(package, cfg->des_mac, actual_src_mac, 0x0800);
            build_ip_header(package, actual_src_ip, cfg->des_ip, (unsigned short)ip_len, 0x06);
            fill_payload_data(package + 14 + 20 + 20, tcp_data_len, cfg);
            build_tcp_header(package, actual_s_port, d_port, actual_seq, 0, cfg->tcp_flags, 64240, (u_short)tcp_data_len,
                             actual_src_ip, cfg->des_ip);
        } break;
        default:
            *package_len = 0;
            break;
    }
}

static timeval add_stamp(timeval* ptv, unsigned int dus) {
    ptv->tv_usec += dus;
    if (ptv->tv_usec >= 1000000) {
        ptv->tv_sec++;
        ptv->tv_usec -= 1000000;
    }
    return *ptv;
}

/* ==========================================================================
   Logic Separation: Burst vs Normal (Remaining code is unchanged but included
   for context)
   ========================================================================== */
void run_burst_mode(pcap_t* fp, const SenderConfig* cfg) {
    std::cout << "[INFO] Running BURST mode (Pre-built packets)." << std::endl;
    std::vector<unsigned char> raw_packet(PacketConfig::MAX_PACKET_BUFFER_SIZE, 0);
    int packet_len = 0;
    build_package(raw_packet.data(), &packet_len, 1, cfg);

    if (packet_len <= 0) return;

    const unsigned int npacks = PacketConfig::BURST_BATCH_SIZE;
    unsigned int queue_mem_size =
        (packet_len + sizeof(struct pcap_pkthdr)) * npacks + PacketConfig::QUEUE_MEMORY_OVERHEAD;
    pcap_send_queue* squeue = pcap_sendqueue_alloc(queue_mem_size);
    if (!squeue) return;

    struct pcap_pkthdr pktheader;
    pktheader.ts.tv_sec = 0;
    pktheader.ts.tv_usec = 0;
    pktheader.caplen = packet_len;
    pktheader.len = packet_len;

    unsigned int actual_queued_packs = 0;
    for (unsigned int i = 0; i < npacks; ++i) {
        if (pcap_sendqueue_queue(squeue, &pktheader, raw_packet.data()) == -1) break;
        actual_queued_packs++;
    }
    uint64_t bytes_per_batch = (uint64_t)packet_len * actual_queued_packs;
    auto last_stats_time = std::chrono::steady_clock::now();

    while (g_is_sending) {
        pcap_sendqueue_transmit(fp, squeue, 0);
        g_total_sent += actual_queued_packs;
        g_total_bytes += bytes_per_batch;

        auto now = std::chrono::steady_clock::now();
        auto elapsed_ms = std::chrono::duration_cast<std::chrono::milliseconds>(now - last_stats_time).count();
        if (elapsed_ms >= PacketConfig::STATS_UPDATE_INTERVAL_MS) {
            if (cfg->stats_callback) cfg->stats_callback(g_total_sent, g_total_bytes);
            last_stats_time = now;
        }
    }
    if (cfg->stats_callback) cfg->stats_callback(g_total_sent, g_total_bytes);
    pcap_sendqueue_destroy(squeue);
}

void run_normal_mode(pcap_t* fp, const SenderConfig* cfg) {
    std::cout << "[INFO] Running INTERVAL mode (Rebuild packets)." << std::endl;
    unsigned int target_batch_time_us = PacketConfig::TARGET_BATCH_TIME_US;
    unsigned int safe_interval = (cfg->send_interval_us == 0) ? 1 : cfg->send_interval_us;
    unsigned int npacks = target_batch_time_us / safe_interval;
    if (npacks < 1) npacks = 1;
    if (npacks > PacketConfig::MAX_BATCH_SIZE) npacks = PacketConfig::MAX_BATCH_SIZE;

    long long batch_duration_us = (long long)npacks * cfg->send_interval_us;
    std::vector<unsigned char> shared_buffer(PacketConfig::MAX_PACKET_BUFFER_SIZE, 0);
    unsigned int queue_mem_size = (PacketConfig::NORMAL_MODE_QUEUE_ESTIMATE + sizeof(struct pcap_pkthdr)) * npacks;
    pcap_send_queue* squeue = pcap_sendqueue_alloc(queue_mem_size);
    if (!squeue) return;

    unsigned int seq_counter = 0; // [修改] 序列号从0开始
    auto next_batch_time = std::chrono::steady_clock::now();

    struct pcap_pkthdr pktheader;
    timeval tv;
    tv.tv_sec = 0;
    tv.tv_usec = 0;

    while (g_is_sending) {
        next_batch_time += std::chrono::microseconds(batch_duration_us);
        squeue->len = 0;
        uint64_t batch_bytes = 0;
        unsigned int actual_sent_packs = 0;
        int packet_len = 0;

        // 用于存储每批最后一个包的数据（用于 Hex 回调）
        std::vector<unsigned char> last_packet_buffer(PacketConfig::MAX_PACKET_BUFFER_SIZE, 0);
        int last_packet_len = 0;
        bool has_last_packet = false;

        for (unsigned int i = 0; i < npacks; ++i) {
            build_package(shared_buffer.data(), &packet_len, (int)seq_counter++, cfg);
            if (packet_len <= 0) continue;

            // 保存最后一个包的数据（复制到独立缓冲区），每批只回调一次（最后一个包）
            if (packet_len > 0 && packet_len <= PacketConfig::MAX_PACKET_BUFFER_SIZE) {
                memcpy(last_packet_buffer.data(), shared_buffer.data(), packet_len);
                last_packet_len = packet_len;
                has_last_packet = true;
            }

            pktheader.ts = tv;
            pktheader.caplen = packet_len;
            pktheader.len = packet_len;
            if (pcap_sendqueue_queue(squeue, &pktheader, shared_buffer.data()) == -1) break;
            batch_bytes += packet_len;
            actual_sent_packs++;
            add_stamp(&tv, cfg->send_interval_us);
        }

        // 每批只调用一次 Hex 回调，传递最后一个包
        if (cfg->hex_callback && has_last_packet && last_packet_len > 0) {
            cfg->hex_callback(last_packet_buffer.data(), last_packet_len);
        }

        if (squeue->len > 0) pcap_sendqueue_transmit(fp, squeue, 1);
        g_total_sent += actual_sent_packs;
        g_total_bytes += batch_bytes;

        if (cfg->stats_callback) cfg->stats_callback(g_total_sent, g_total_bytes);
        auto now = std::chrono::steady_clock::now();
        if (now < next_batch_time) {
            auto remaining = std::chrono::duration_cast<std::chrono::microseconds>(next_batch_time - now).count();
            if (remaining > PacketConfig::MIN_SLEEP_THRESHOLD_US)
                std::this_thread::sleep_for(std::chrono::microseconds(remaining));
            else if (remaining > 0)
                std::this_thread::yield();
        } else {
            next_batch_time = std::chrono::steady_clock::now();
        }
    }
    pcap_sendqueue_destroy(squeue);
}

// [新增] 辅助函数：解析字符串IP到字节数组
static void parse_ip_str(const char* ip_str, unsigned char* out_ip) {
    if (!ip_str || !out_ip) return;
    int a, b, c, d;
    if (sscanf(ip_str, "%d.%d.%d.%d", &a, &b, &c, &d) == 4) {
        out_ip[0] = (unsigned char)a;
        out_ip[1] = (unsigned char)b;
        out_ip[2] = (unsigned char)c;
        out_ip[3] = (unsigned char)d;
    }
}

extern "C" void start_send_mode(const SenderConfig* config) {
    char errbuf[PCAP_ERRBUF_SIZE];
    if (!config || !config->dev_name[0]) {
        // [优化] 错误处理增强：通过回调通知 UI
        if (config && config->error_callback) {
            config->error_callback("Invalid configuration: device name is empty");
        }
        return;
    }

    pcap_t* handler =
        pcap_open(config->dev_name, PacketConfig::PCAP_SNAPLEN, PCAP_OPENFLAG_PROMISCUOUS, 1, NULL, errbuf);
    if (!handler) {
        // [优化] 错误处理增强：通过回调通知 UI，而不是仅打印到 stderr
        std::string error_msg = std::string("pcap_open failed: ") + errbuf;
        std::cerr << "[ERROR] " << error_msg << std::endl;
        if (config->error_callback) {
            config->error_callback(error_msg.c_str());
        }
        return;
    }

    // 初始化随机数生成器（如果尚未初始化）
    init_random_generator();

    if (config->send_interval_us == 0)
        run_burst_mode(handler, config);
    else
        run_normal_mode(handler, config);

    pcap_close(handler);
    std::cout << "[INFO] Sending stopped." << std::endl;
}

// === Socket Sender (Unchanged) ===
#define LOG_SOCK(level, fmt, ...)                                                                                      \
    do {                                                                                                               \
        if (config->log_callback) {                                                                                    \
            char buf[512];                                                                                             \
            snprintf(buf, sizeof(buf), fmt, ##__VA_ARGS__);                                                            \
            config->log_callback(buf, level);                                                                          \
        }                                                                                                              \
    } while (0)

extern "C" void start_socket_send_mode(const SocketConfig* config) {
    if (!config) return;

    WSADATA wsaData;
    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) return;

    struct sockaddr_in dest_addr;
    memset(&dest_addr, 0, sizeof(dest_addr));
    dest_addr.sin_family = AF_INET;
    dest_addr.sin_port = htons(config->target_port);
    dest_addr.sin_addr.s_addr = inet_addr(config->target_ip);

    // --- [修正：逻辑优先级] 只要开启了伪造模式（随机MAC或随机IP），就强制进入 Raw 模式 ---
    // 因为标准 Socket 无法伪造身份，无论用户是否勾选了 Connect Mode。
    if (!config->is_udp && (config->use_random_src_mac || config->use_random_src_ip)) {
        LOG_SOCK(1, "[SOCK] Mode: Raw SYN Flood (Spoofing Enabled)");
        if (config->is_connect_only) {
            LOG_SOCK(2, "[SOCK] Note: Full Handshake is not possible with Spoofing. Using Raw SYN instead.");
        }
        
        char errbuf[PCAP_ERRBUF_SIZE];
        pcap_t* adhandle = pcap_open(config->dev_name, 65536, PCAP_OPENFLAG_PROMISCUOUS, 1000, NULL, errbuf);
        if (adhandle == NULL) {
            LOG_SOCK(2, "[SOCK] Error: Unable to open adapter %s", config->dev_name);
            WSACleanup();
            return;
        }

        // 构造基本的 SenderConfig 用于复用左侧的 build_package 逻辑
        SenderConfig raw_cfg;
        memset(&raw_cfg, 0, sizeof(raw_cfg));
        raw_cfg.packet_type = TCP_PACKAGE;
        raw_cfg.tcp_flags = 0x02; // SYN
        raw_cfg.payload_len = config->payload_len;
        raw_cfg.payload_mode = PAYLOAD_RANDOM;
        raw_cfg.src_port = config->source_port;
        raw_cfg.dst_port = config->target_port;
        raw_cfg.use_random_src_port = config->use_random_src_port;
        raw_cfg.use_random_src_mac = config->use_random_src_mac;
        raw_cfg.use_random_src_ip = config->use_random_src_ip;
        raw_cfg.use_random_seq = config->use_random_seq;
        
        // 复制地址信息
        parse_ip_str(config->target_ip, raw_cfg.des_ip);
        parse_ip_str(config->source_ip, raw_cfg.src_ip);
        memcpy(raw_cfg.src_mac, config->src_mac, 6);
        memcpy(raw_cfg.random_ip_base, config->random_ip_base, 4);
        memcpy(raw_cfg.random_ip_mask, config->random_ip_mask, 4);

        // 设置目的MAC（此处简化处理：使用FF:FF...或需要ARPLookup）
        memset(raw_cfg.des_mac, 0xFF, 6); 

        unsigned char packet[1500];
        int pkg_len = 0;
        int seq = 0;

        while (g_is_sock_sending) {
            build_package(packet, &pkg_len, seq++, &raw_cfg);
            if (pcap_sendpacket(adhandle, packet, pkg_len) == 0) {
                g_sock_total_sent++;
                g_sock_total_bytes += pkg_len;
            }

            if (config->interval_us > 0) {
                std::this_thread::sleep_for(std::chrono::microseconds(config->interval_us));
            }

            auto now = std::chrono::steady_clock::now();
            static auto last_stats_time = now;
            if (std::chrono::duration_cast<std::chrono::milliseconds>(now - last_stats_time).count() >= 30) {
                if (config->stats_callback) config->stats_callback(g_sock_total_sent, g_sock_total_bytes);
                last_stats_time = now;
            }
        }

        pcap_close(adhandle);
        WSACleanup();
        return;
    }

    // [新增] 专门的 TCP 连接模式处理
    if (!config->is_udp && config->is_connect_only) {
        LOG_SOCK(1, "[SOCK] Mode: TCP Connect Flood (Complete Lifecycle)");
        
        while (g_is_sock_sending) {
            SOCKET sockfd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
            if (sockfd == INVALID_SOCKET) {
                std::this_thread::sleep_for(std::chrono::milliseconds(10));
                continue;
            }

            // [修复] 允许地址/端口重用，解决指定端口时的 TIME_WAIT 问题
            int opt = 1;
            setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, (char*)&opt, sizeof(opt));
            
            // [修复] 设置 LINGER 为 0，强制立即关闭并释放端口 (发送 RST 而非 FIN)
            // 这可以防止端口卡在 TIME_WAIT 状态，从而支持高频指定端口连接
            linger so_linger = {1, 0}; 
            setsockopt(sockfd, SOL_SOCKET, SO_LINGER, (char*)&so_linger, sizeof(so_linger));

            // 设置非阻塞以便快速超时
            u_long mode = 1;
            ioctlsocket(sockfd, FIONBIO, &mode);

            // [新增] 强制绑定到选定网卡的源 IP 和端口
            if (config->source_ip[0] != '\0' && strcmp(config->source_ip, "0.0.0.0") != 0) {
                struct sockaddr_in local_addr;
                memset(&local_addr, 0, sizeof(local_addr));
                local_addr.sin_family = AF_INET;
                local_addr.sin_addr.s_addr = inet_addr(config->source_ip);
                
                // [修复] 如果开启了随机端口，则设为 0 让系统自动分配新的临时端口
                if (config->use_random_src_port) {
                    local_addr.sin_port = 0; 
                } else {
                    local_addr.sin_port = htons(config->source_port); 
                }

                if (bind(sockfd, (struct sockaddr*)&local_addr, sizeof(local_addr)) == SOCKET_ERROR) {
                    int err = WSAGetLastError();
                    if (!config->use_random_src_port && config->source_port != 0 && g_is_sock_sending) {
                        LOG_SOCK(2, "[SOCK] Bind failed on port %d, error: %d", config->source_port, err);
                    }
                }
            }

            // 执行连接（三次握手）
            int connect_ret = connect(sockfd, (struct sockaddr*)&dest_addr, sizeof(dest_addr));
            bool connected = false;

            if (connect_ret == 0) {
                connected = true;
            } else {
                int err = WSAGetLastError();
                if (err == WSAEWOULDBLOCK) {
                    fd_set write_fds;
                    FD_ZERO(&write_fds);
                    FD_SET(sockfd, &write_fds);
                    timeval tv = {0, 500000}; // 增加到 500ms 超时
                    if (select(0, NULL, &write_fds, NULL, &tv) > 0) {
                        connected = true;
                    }
                }
            }

            if (connected) {
                // 连接建立后，发送一次配置的载荷数据
                int data_len = config->payload_len > 0 ? config->payload_len : 1;
                std::vector<char> temp_buf(data_len, 'X');
                send(sockfd, temp_buf.data(), data_len, 0);
                
                g_sock_total_sent++;
                g_sock_total_bytes += data_len;
            }

            // 立即关闭
            closesocket(sockfd);

            // 统计回调
            auto now = std::chrono::steady_clock::now();
            static auto last_stats_time = now;
            if (std::chrono::duration_cast<std::chrono::milliseconds>(now - last_stats_time).count() >= 30) {
                if (config->stats_callback) config->stats_callback(g_sock_total_sent, g_sock_total_bytes);
                last_stats_time = now;
            }

            // 间隔控制
            if (config->interval_us > 0) {
                std::this_thread::sleep_for(std::chrono::microseconds(config->interval_us));
            }
        }
        
        WSACleanup();
        return;
    }

    // --- 以下为原有的数据发送模式 ---
    SOCKET sockfd = INVALID_SOCKET;
    int type = config->is_udp ? SOCK_DGRAM : SOCK_STREAM;
    int proto = config->is_udp ? IPPROTO_UDP : IPPROTO_TCP;

    sockfd = socket(AF_INET, type, proto);
    if (sockfd == INVALID_SOCKET) {
        WSACleanup();
        return;
    }

    // ================== [修复代码开始] ==================
    if (!config->is_udp) { // 仅针对 TCP
        int flag = 1;
        int result = setsockopt(sockfd, IPPROTO_TCP, TCP_NODELAY, (char*)&flag, sizeof(int));
        if (result < 0) {
            std::cerr << "[WARN] Failed to set TCP_NODELAY" << std::endl;
        }
    }
    // ================== [修复代码结束] ==================

    if (config->source_ip[0] != '\0' && strcmp(config->source_ip, "0.0.0.0") != 0 &&
        strcmp(config->source_ip, "") != 0) {
        struct sockaddr_in local_addr;
        memset(&local_addr, 0, sizeof(local_addr));
        local_addr.sin_family = AF_INET;
        local_addr.sin_addr.s_addr = inet_addr(config->source_ip);
        local_addr.sin_port = htons(config->source_port); // [修复] 使用用户设置的源端口
        int bind_result = bind(sockfd, (struct sockaddr*)&local_addr, sizeof(local_addr));
        if (bind_result < 0) {
            std::cerr << "[WARN] Failed to bind to source IP: " << config->source_ip << std::endl;
        }
    }

    if (!config->is_udp) {
        u_long mode = 1;
        ioctlsocket(sockfd, FIONBIO, &mode);
        int connect_ret = connect(sockfd, (struct sockaddr*)&dest_addr, sizeof(dest_addr));
        bool connected = false;

        if (connect_ret == 0)
            connected = true;
        else {
            int err = WSAGetLastError();
            if (err == WSAEWOULDBLOCK) {
                int max_retries = PacketConfig::TCP_CONNECT_MAX_RETRIES;
                for (int i = 0; i < max_retries; ++i) {
                    if (!g_is_sock_sending) break;
                    fd_set write_fds, except_fds;
                    FD_ZERO(&write_fds);
                    FD_SET(sockfd, &write_fds);
                    FD_ZERO(&except_fds);
                    FD_SET(sockfd, &except_fds);
                    timeval tv;
                    tv.tv_sec = 0;
                    tv.tv_usec = 100000;
                    int sel_ret = select(0, NULL, &write_fds, &except_fds, &tv);
                    if (sel_ret > 0) {
                        if (FD_ISSET(sockfd, &write_fds)) {
                            connected = true;
                            break;
                        }
                        if (FD_ISSET(sockfd, &except_fds)) break;
                    }
                }
            }
        }
        mode = 0;
        ioctlsocket(sockfd, FIONBIO, &mode);
        if (!connected) {
            closesocket(sockfd);
            WSACleanup();
            return;
        }
    }

    int data_len = config->payload_len;
    if (data_len <= 0) data_len = 1;
    std::vector<char> send_buffer(data_len, 'X');

    auto last_stats_time = std::chrono::steady_clock::now();
    auto next_send_time = std::chrono::steady_clock::now();
    bool is_burst = (config->interval_us == 0);

    while (g_is_sock_sending) {
        int sent = -1;
        if (config->is_udp) {
            sent = sendto(sockfd, send_buffer.data(), data_len, 0, (struct sockaddr*)&dest_addr, sizeof(dest_addr));
        } else {
            sent = send(sockfd, send_buffer.data(), data_len, 0);
        }

        if (sent > 0) {
            g_sock_total_sent++;
            g_sock_total_bytes += sent;
        } else {
            int err = WSAGetLastError();
            if (err != WSAEWOULDBLOCK) {
                std::this_thread::sleep_for(std::chrono::milliseconds(1));
                if (!config->is_udp && (err == WSAECONNRESET || err == WSAECONNABORTED)) break;
            }
        }

        auto now = std::chrono::steady_clock::now();
        if (config->stats_callback) {
            auto elapsed_ms = std::chrono::duration_cast<std::chrono::milliseconds>(now - last_stats_time).count();
            if (elapsed_ms >= 30) {
                config->stats_callback(g_sock_total_sent, g_sock_total_bytes);
                last_stats_time = now;
            }
        }

        if (!is_burst) {
            next_send_time += std::chrono::microseconds(config->interval_us);
            if (next_send_time > now) {
                auto wait_us = std::chrono::duration_cast<std::chrono::microseconds>(next_send_time - now).count();
                constexpr int LONG_SLEEP_THRESHOLD_US = 100000; // 长睡眠阈值（100ms）
                if (wait_us > LONG_SLEEP_THRESHOLD_US) {
                    while (wait_us > 0 && g_is_sock_sending) {
                        int sleep_slice = (wait_us > LONG_SLEEP_THRESHOLD_US) ? LONG_SLEEP_THRESHOLD_US : wait_us;
                        std::this_thread::sleep_for(std::chrono::microseconds(sleep_slice));
                        wait_us -= sleep_slice;
                        if (!g_is_sock_sending) break;
                    }
                } else {
                    if (wait_us > PacketConfig::MIN_SLEEP_THRESHOLD_US)
                        std::this_thread::sleep_for(std::chrono::microseconds(wait_us));
                    else
                        while (std::chrono::steady_clock::now() < next_send_time) {
                        }
                }
            } else {
                next_send_time = std::chrono::steady_clock::now();
            }
        }
    }

    if (config->stats_callback) config->stats_callback(g_sock_total_sent, g_sock_total_bytes);
    closesocket(sockfd);
    WSACleanup();
}
