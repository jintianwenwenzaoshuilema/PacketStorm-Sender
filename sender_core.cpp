#include "sender_core.h"
#include <stdio.h>
#include <stdlib.h>
#include <iostream>
#include <thread>
#include <string.h>
#include <pcap.h>
#include <chrono>
#include <vector>

#ifndef WIN32
#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>
#else
#include <winsock.h>
#endif



using namespace std;

// === 1. Global Control Flags and Statistics Definitions ===
// These definitions allocate memory for the variables declared as extern in sender_core.h
std::atomic<bool> g_is_sending{false};
std::atomic<uint64_t> g_total_sent{0};   // [FIX] Definition added
std::atomic<uint64_t> g_total_bytes{0};  // [FIX] Definition added

#pragma pack(1)

/* ==========================================================================
   Protocol Header Definitions (Kept as is)
   ========================================================================== */
#define IPTOSBUFFERS    12
static char* iptos(u_long in) {
    static char output[IPTOSBUFFERS][3 * 4 + 3 + 1];
    static short which;
    u_char* p = (u_char*)&in;
    which = (short)((which + 1 == IPTOSBUFFERS) ? 0 : which + 1);
    sprintf(output[which], "%d.%d.%d.%d", p[0], p[1], p[2], p[3]);
    return output[which];
}

struct ip_v4_address { u_char byte1, byte2, byte3, byte4; };
struct mac_address { u_char byte1, byte2, byte3, byte4, byte5, byte6; };

struct ethernet_header {
    mac_address des_mac_addr;
    mac_address src_mac_addr;
    u_short type;
};

struct ip_v4_header {
    u_char  ver_ihl; u_char  tos; u_short tlen; u_short identification;
    u_short flags_fo; u_char  ttl; u_char  proto; u_short checksum;
    ip_v4_address src_ip_addr; ip_v4_address des_ip_addr; u_int   op_pad;
};

struct udp_header { u_short sport; u_short dport; u_short len; u_short checksum; };

struct tcp_header {
    u_short sport; u_short dport; u_int sequence; u_int acknowledgement;
    u_char offset; u_char flags; u_short windows; u_short checksum; u_short urgent_pointer;
};

struct icmp_echo {
    uint8_t type; uint8_t code; uint16_t checksum; uint16_t ident; uint16_t seq;
};

struct psd_header {
    ip_v4_address s_ip; ip_v4_address d_ip; u_char mbz; u_char proto; u_short plen;
};

struct dns_header {
    unsigned short id; unsigned short flags; unsigned short questions;
    unsigned short answer; unsigned short authority; unsigned short additional;
};

struct dns_queries {
    int length; unsigned short qtype; unsigned short qclass; char* name;
};

/* ==========================================================================
   Helper Functions (Checksum, Header Building - Kept as is)
   ========================================================================== */

static u_short checksum(u_short* buffer, int size) {
    unsigned long cksum = 0;
    while (size > 1) { cksum += *buffer++; size -= sizeof(u_short); }
    if (size) { cksum += *(u_short*)buffer; }
    cksum = (cksum >> 16) + (cksum & 0xffff);
    cksum += (cksum >> 16);
    return (u_short)(~cksum);
}

static uint16_t calculate_checksum(unsigned char* buffer, int bytes) {
    uint32_t checksum_val = 0;
    unsigned char* end = buffer + bytes;
    if (bytes % 2 == 1) { end = buffer + bytes - 1; checksum_val += (*end) << 8; }
    while (buffer < end) { checksum_val += buffer[0] << 8; checksum_val += buffer[1]; buffer += 2; }
    uint32_t carry = checksum_val >> 16;
    while (carry) { checksum_val = (checksum_val & 0xffff) + carry; carry = checksum_val >> 16; }
    checksum_val = ~checksum_val;
    return (uint16_t)(checksum_val & 0xffff);
}

static void build_ethernet_header(unsigned char* package, const u_char des_mac[6], const u_char src_mac[6], u_short type) {
    ethernet_header* eh = (ethernet_header*)package;
    memcpy(&eh->des_mac_addr, des_mac, 6);
    memcpy(&eh->src_mac_addr, src_mac, 6);
    eh->type = htons(type);
}

static void build_ip_header(u_char* package, const u_char src_ip[4], const u_char des_ip[4], u_short ip_len, u_char proto_type) {
    ip_v4_header* ih = (ip_v4_header*)(package + 14);
    ih->ver_ihl = 0x45; ih->tos = 0x00; ih->tlen = htons(ip_len);
    ih->identification = 0; ih->flags_fo = htons(0x4000);
    ih->ttl = 0x80; ih->proto = proto_type; ih->checksum = 0;
    memcpy(&ih->src_ip_addr, src_ip, 4);
    memcpy(&ih->des_ip_addr, des_ip, 4);
    ih->checksum = checksum((u_short*)ih, 20);
}

static void build_udp_header(unsigned char* package, u_short s_port, u_short d_port, u_short udp_len) {
    udp_header* uh = (udp_header*)(package + 14 + 20);
    ip_v4_header* ih = (ip_v4_header*)(package + 14);
    uh->sport = htons(s_port); uh->dport = htons(d_port); uh->len = htons(udp_len); uh->checksum = 0;

    psd_header psd;
    psd.s_ip = ih->src_ip_addr; psd.d_ip = ih->des_ip_addr;
    psd.mbz = 0; psd.proto = 0x11; psd.plen = htons(udp_len);

    int pseudo_len = sizeof(psd) + udp_len;
    char* tmp = (char*)calloc(1, pseudo_len);
    if (!tmp) return;
    memcpy(tmp, &psd, sizeof(psd)); memcpy(tmp + sizeof(psd), uh, udp_len);
    uh->checksum = checksum((u_short*)tmp, pseudo_len);
    free(tmp);
}

static void build_tcp_header(unsigned char* package, u_short s_port, u_short d_port, u_int seq, u_int ack, u_char flags, u_short win, u_short tcp_payload_len, const u_char* src_ip, const u_char* dst_ip) {
    tcp_header* th = (tcp_header*)(package + 14 + 20);
    th->sport = htons(s_port); th->dport = htons(d_port);
    th->sequence = htonl(seq); th->acknowledgement = htonl(ack);
    th->offset = (5 << 4); th->flags = flags; th->windows = htons(win);
    th->urgent_pointer = 0; th->checksum = 0;

    int tcp_total_len = 20 + tcp_payload_len;
    psd_header psd;
    memcpy(&psd.s_ip, src_ip, 4); memcpy(&psd.d_ip, dst_ip, 4);
    psd.mbz = 0; psd.proto = 0x06; psd.plen = htons((u_short)tcp_total_len);

    int pseudo_total_len = sizeof(psd) + tcp_total_len;
    char* tmp = (char*)calloc(1, pseudo_total_len);
    if (!tmp) return;
    memcpy(tmp, &psd, sizeof(psd)); memcpy(tmp + sizeof(psd), th, 20);
    if (tcp_payload_len > 0) memcpy(tmp + sizeof(psd) + 20, package + 14 + 20 + 20, tcp_payload_len);
    th->checksum = checksum((u_short*)tmp, pseudo_total_len);
    free(tmp);
}

static void build_icmp_header(unsigned char* package, int seq_num) {
    icmp_echo* icmph = (icmp_echo*)(package + 14 + 20);
    memset(icmph, 0, 13);
    icmph->type = 8; icmph->code = 0; icmph->checksum = 0;
    icmph->ident = htons(0x1234); icmph->seq = htons((uint16_t)seq_num);
    // Payload for ICMP (5 bytes as in original code)
    unsigned char* data = (unsigned char*)(package + 14 + 20 + 8);
    data[0]=0x12; data[1]=0x34; data[2]=0x56; data[3]=0x78; data[4]=0x90;
    icmph->checksum = htons(calculate_checksum((unsigned char*)icmph, 13));
}

// DNS 相关简化保留，实际工程中建议将DNS构建逻辑也优化为不使用malloc
static int dns_create_header(struct dns_header* header) {
    if (!header) return -1;
    memset(header, 0, sizeof(struct dns_header));
    header->id = (unsigned short)(rand() % 65535);
    header->flags = htons(0x0100); header->questions = htons(1);
    return 0;
}
static int dns_create_queries(struct dns_queries* question, const char* hostname) {
    if (!question || !hostname) return -1;
    size_t len = strlen(hostname);
    question->name = (char*)malloc(len + 2);
    if (!question->name) return -2;
    question->length = (int)len + 2;
    question->qtype = htons(1); question->qclass = htons(1);

    char* qname = question->name;
    char* host_dup = strdup(hostname);
    char* token = strtok(host_dup, ".");
    while (token) {
        size_t tlen = strlen(token);
        *qname++ = (char)tlen;
        memcpy(qname, token, tlen); qname += tlen;
        token = strtok(NULL, ".");
    }
    *qname = 0;
    free(host_dup);
    return 0;
}
static void build_dns(unsigned char* package, const char* domain, int dns_package_len) {
    udp_header* uh = (udp_header*)(package + 14 + 20);
    ip_v4_header* ih = (ip_v4_header*)(package + 14);
    int udp_len = 8 + dns_package_len;
    uh->sport = htons(10086); uh->dport = htons(53); uh->len = htons((u_short)udp_len); uh->checksum = 0;

    struct dns_header header; dns_create_header(&header);
    struct dns_queries question; dns_create_queries(&question, domain);

    char* req = (char*)(package + 14 + 20 + 8);
    memcpy(req, &header, sizeof(header));
    memcpy(req + sizeof(header), question.name, question.length);
    u_short qtype = htons(1), qclass = htons(1);
    memcpy(req + sizeof(header) + question.length, &qtype, 2);
    memcpy(req + sizeof(header) + question.length + 2, &qclass, 2);

    psd_header psd; psd.s_ip = ih->src_ip_addr; psd.d_ip = ih->des_ip_addr;
    psd.mbz = 0; psd.proto = 0x11; psd.plen = htons((u_short)udp_len);

    int pseudo_len = sizeof(psd) + udp_len;
    char* tmp = (char*)calloc(1, pseudo_len);
    if (tmp) {
        memcpy(tmp, &psd, sizeof(psd)); memcpy(tmp + sizeof(psd), uh, udp_len);
        uh->checksum = checksum((u_short*)tmp, pseudo_len);
        free(tmp);
    }
    free(question.name);
}

/* ==========================================================================
   功能核心：载荷填充、打包、发送逻辑
   ========================================================================== */

// 填充载荷数据
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
        } else { memset(data_ptr, 0, target_len); }
        break;
    case PAYLOAD_RANDOM:
    default:
        for (int i = 0; i < target_len; ++i) data_ptr[i] = (unsigned char)(rand() % 256);
        break;
    }
}

// 构建完整数据包 (写入 shared_buffer)
static void build_package(unsigned char* package, int* package_len, int seq_num, const SenderConfig* cfg) {
    int udp_len, icmp_len, ip_len;
    unsigned short s_port = (cfg->src_port == 0) ? 10086 : cfg->src_port;
    unsigned short d_port = (cfg->dst_port == 0) ? 10086 : cfg->dst_port;

    switch (cfg->packet_type) {
    case UDP_PACKAGE:
        udp_len = 8 + cfg->payload_len; ip_len = 20 + udp_len; *package_len = 14 + ip_len;
        build_ethernet_header(package, cfg->des_mac, cfg->src_mac, 0x0800);
        build_ip_header(package, cfg->src_ip, cfg->des_ip, (unsigned short)ip_len, 0x11);
        fill_payload_data(package + 14 + 20 + 8, cfg->payload_len, cfg);
        build_udp_header(package, s_port, d_port, (unsigned short)udp_len);
        break;
    case ICMP_PACKAGE:
        icmp_len = 13; ip_len = 20 + icmp_len; *package_len = 14 + ip_len;
        build_ethernet_header(package, cfg->des_mac, cfg->src_mac, 0x0800);
        build_ip_header(package, cfg->src_ip, cfg->des_ip, (unsigned short)ip_len, 0x01);
        build_icmp_header(package, seq_num);
        break;
    case DNS_PACKAGE: {
        const char* domain = (cfg->dns_domain && *cfg->dns_domain) ? cfg->dns_domain : "baidu.com";
        int dlen = (int)strlen(domain);
        int dns_pkg_len = 12 + dlen + 2 + 4;
        *package_len = 14 + 20 + 8 + dns_pkg_len;
        build_ethernet_header(package, cfg->des_mac, cfg->src_mac, 0x0800);
        build_ip_header(package, cfg->src_ip, cfg->des_ip, (unsigned short)(*package_len - 14), 0x11);
        build_dns(package, domain, dns_pkg_len);
    } break;
    case TCP_PACKAGE: {
        int tcp_data_len = cfg->payload_len;
        int tcp_total_len = 20 + tcp_data_len; ip_len = 20 + tcp_total_len; *package_len = 14 + ip_len;
        build_ethernet_header(package, cfg->des_mac, cfg->src_mac, 0x0800);
        build_ip_header(package, cfg->src_ip, cfg->des_ip, (unsigned short)ip_len, 0x06);
        fill_payload_data(package + 14 + 20 + 20, tcp_data_len, cfg);
        build_tcp_header(package, s_port, d_port, seq_num, 0, cfg->tcp_flags, 64240, (u_short)tcp_data_len, cfg->src_ip, cfg->des_ip);
    } break;
    default: *package_len = 0; break;
    }
}

// 时间戳计算
timeval add_stamp(timeval* ptv, unsigned int dus) {
    ptv->tv_usec += dus;
    if (ptv->tv_usec >= 1000000) { ptv->tv_sec++; ptv->tv_usec -= 1000000; }
    return *ptv;
}


/* ==========================================================================
   发包核心函数 (Send Queue - Modified for Burst)
   ========================================================================== */
uint64_t send_queue(pcap_t* fp, unsigned int npacks, const SenderConfig* cfg, unsigned int &seq_counter, pcap_send_queue* squeue, unsigned char* shared_buffer) {
    unsigned int i;
    struct pcap_pkthdr pktheader;
    timeval tv; tv.tv_sec = 0; tv.tv_usec = 0;

    // 重置队列
    squeue->len = 0;
    int package_len = 0;

    // 本批次字节统计变量
    uint64_t batch_bytes = 0;

    // 判断是否为 Burst 模式 (间隔为0)
    bool is_burst = (cfg->send_interval_us == 0);

    for (i = 0; i < npacks; i++) {
        build_package(shared_buffer, &package_len, (int)seq_counter++, cfg);
        if (package_len <= 0) continue;

        pktheader.ts = tv;
        pktheader.caplen = (bpf_u_int32)package_len;
        pktheader.len = (bpf_u_int32)package_len;

        if (pcap_sendqueue_queue(squeue, &pktheader, shared_buffer) == -1) {
            // 队列满，不再添加
            break;
        }

        // 累加准确的包长度
        batch_bytes += package_len;

        // 【修改】只有非 Burst 模式才需要计算时间戳间隔
        // Burst 模式下所有包时间戳由驱动自动处理或忽略，减少CPU计算
        if (!is_burst) {
            add_stamp(&tv, cfg->send_interval_us);
        }
    }

    if (squeue->len > 0) {
        // 【核心修改】
        // sync_flag = 1: 同步发送（按时间戳间隔发，适合定速）
        // sync_flag = 0: 非同步发送（全速发，适合 Burst）
        int sync_flag = is_burst ? 0 : 1;

        pcap_sendqueue_transmit(fp, squeue, sync_flag);
    }

    return batch_bytes;
}

/* ==========================================================================
   对外接口 (DLL Export - Modified for Burst)
   ========================================================================== */
extern "C" void start_send_mode(const SenderConfig* config) {
    char errbuf[PCAP_ERRBUF_SIZE];

    std::cout << "[INFO] Opening adapter: " << config->dev_name << std::endl;

    if (!config || !config->dev_name[0]) {
        std::cerr << "[ERROR] Invalid device name!" << std::endl;
        return;
    }

    // 打开网卡
    // mintime 设置为 1ms，保证此时尽可能快地响应
    pcap_t* handler = pcap_open(config->dev_name, 65535, PCAP_OPENFLAG_PROMISCUOUS, 1, NULL, errbuf);
    if (!handler) {
        std::cerr << "[ERROR] pcap_open failed: " << errbuf << std::endl;
        return;
    }

    SenderConfig cfg = *config;
    bool is_burst_mode = (cfg.send_interval_us == 0);

    if (is_burst_mode) {
        std::cout << "[INFO] Adapter opened. Mode: BURST (Full Speed)." << std::endl;
    } else {
        std::cout << "[INFO] Adapter opened. Mode: Sync Batching (Interval: " << cfg.send_interval_us << "us)." << std::endl;
    }

    // --- 1. 计算批次参数 ---
    unsigned int npacks;

    if (is_burst_mode) {
        // 【修改】Burst 模式：设置较大的固定批次
        // 这决定了单次系统调用发送多少个包。
        // 2048 是一个经验值，既能保证吞吐量，又不会让 pcap_sendqueue_alloc 占用过多内存
        npacks = 2048;
    } else {
        // 定时模式：计算 1秒 内的包量作为缓冲基准
        unsigned int target_batch_time_us = 1000000;
        unsigned int safe_interval = (cfg.send_interval_us == 0) ? 1 : cfg.send_interval_us;
        npacks = target_batch_time_us / safe_interval;
        if (npacks < 1) npacks = 1;
        if (npacks > 5000) npacks = 5000; // 限制最大值
    }

    // 计算这一批包理论上总共需要消耗多少时间 (仅用于定速模式)
    long long batch_duration_us = (long long)npacks * cfg.send_interval_us;

    // --- 2. 内存池预分配 ---
    // 预留足够大的 buffer (假设最大包长 10000 字节，实际通常是 1514)
    std::vector<unsigned char> shared_buffer(10000, 0);

    // 分配队列内存
    unsigned int queue_mem_size = (2000 + sizeof(struct pcap_pkthdr)) * npacks; // 2000 字节足够容纳 MTU
    pcap_send_queue* squeue = pcap_sendqueue_alloc(queue_mem_size);

    if (!squeue) {
        std::cerr << "[ERROR] pcap_sendqueue_alloc failed!" << std::endl;
        pcap_close(handler);
        return;
    }

    unsigned int current_seq_num = 1;

    // --- 3. 初始化时间基准 ---
    auto next_batch_time = std::chrono::steady_clock::now();

    std::cout << "[INFO] Sending loop started." << std::endl;

    while (g_is_sending) {
        // 计算下一轮时间点 (仅定速模式需要)
        if (!is_burst_mode) {
            next_batch_time += std::chrono::microseconds(batch_duration_us);
        }

        // 调用发送
        uint64_t bytes_sent_this_batch = send_queue(handler, npacks, &cfg, current_seq_num, squeue, shared_buffer.data());

        // === 更新全局统计 ===
        g_total_sent += npacks;
        g_total_bytes += bytes_sent_this_batch;

        // 回调通知
        if (cfg.stats_callback) {
            cfg.stats_callback(g_total_sent, g_total_bytes);
        }

        // --- 4. 批次间补时 (Burst 模式自动跳过) ---
        // cfg.send_interval_us 为 0 时，此 if 不成立，循环全速运行
        if (!is_burst_mode) {
            auto now = std::chrono::steady_clock::now();
            if (now < next_batch_time) {
                auto remaining = std::chrono::duration_cast<std::chrono::microseconds>(next_batch_time - now).count();
                if (remaining > 1000) {
                    std::this_thread::sleep_for(std::chrono::microseconds(remaining));
                }
                else if (remaining > 0) {
                    std::this_thread::yield();
                }
            }
            else {
                // 防滞后重置
                next_batch_time = std::chrono::steady_clock::now();
            }
        }
    }

    // --- 5. 清理资源 ---
    pcap_sendqueue_destroy(squeue);
    pcap_close(handler);
    std::cout << "\n[INFO] Sending stopped." << std::endl;
}
#pragma pack()
