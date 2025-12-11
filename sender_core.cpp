#include "sender_core.h"
#include <stdio.h>
#include <stdlib.h>
#include <iostream>
#include <thread>
#include <string.h>
#include <pcap.h>
#include <chrono>
#include <vector>
#include <ws2tcpip.h>

#ifndef WIN32
#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>
#else
#include <winsock.h>
#endif

using namespace std;

// === Global Control Flags ===
std::atomic<bool> g_is_sending{false};
std::atomic<uint64_t> g_total_sent{0};
std::atomic<uint64_t> g_total_bytes{0};

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
        } else { memset(data_ptr, 0, target_len); }
        break;
    case PAYLOAD_RANDOM:
    default:
        for (int i = 0; i < target_len; ++i) data_ptr[i] = (unsigned char)(rand() % 256);
        break;
    }
}

/* ==========================================================================
   Protocol Headers
   ========================================================================== */
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
   Checksum & Builders
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

static void build_icmp_header(unsigned char* package, int seq_num, int payload_len, const SenderConfig* cfg) {
    icmp_echo* icmph = (icmp_echo*)(package + 14 + 20);
    int icmp_total_len = 8 + payload_len;
    memset(icmph, 0, icmp_total_len);
    icmph->type = 8; icmph->code = 0; icmph->checksum = 0;
    icmph->ident = htons(0x1234); icmph->seq = htons((uint16_t)seq_num);

    unsigned char* data_ptr = (unsigned char*)(package + 14 + 20 + 8);
    fill_payload_data(data_ptr, payload_len, cfg);
    icmph->checksum = htons(calculate_checksum((unsigned char*)icmph, icmp_total_len));
}

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
    *qname = 0; free(host_dup);
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

// === Build Package (Single) ===
static void build_package(unsigned char* package, int* package_len, int seq_num, const SenderConfig* cfg) {
    int udp_len, icmp_len, ip_len;
    unsigned short s_port = (cfg->src_port == 0) ? 10086 : cfg->src_port;
    unsigned short d_port = (cfg->dst_port == 0) ? 10086 : cfg->dst_port;

    switch (cfg->packet_type) {
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
        int safe_payload_len = cfg->payload_len;
        if (safe_payload_len < 32) safe_payload_len = 32;
        icmp_len = 8 + safe_payload_len;
        ip_len = 20 + icmp_len;
        *package_len = 14 + ip_len;
        build_ethernet_header(package, cfg->des_mac, cfg->src_mac, 0x0800);
        build_ip_header(package, cfg->src_ip, cfg->des_ip, (unsigned short)ip_len, 0x01);
        build_icmp_header(package, seq_num, safe_payload_len, cfg);
    } break;
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
        int tcp_total_len = 20 + tcp_data_len;
        ip_len = 20 + tcp_total_len;
        *package_len = 14 + ip_len;
        build_ethernet_header(package, cfg->des_mac, cfg->src_mac, 0x0800);
        build_ip_header(package, cfg->src_ip, cfg->des_ip, (unsigned short)ip_len, 0x06);
        fill_payload_data(package + 14 + 20 + 20, tcp_data_len, cfg);
        build_tcp_header(package, s_port, d_port, seq_num, 0, cfg->tcp_flags, 64240, (u_short)tcp_data_len, cfg->src_ip, cfg->des_ip);
    } break;
    default:
        *package_len = 0;
        break;
    }
}

static timeval add_stamp(timeval* ptv, unsigned int dus) {
    ptv->tv_usec += dus;
    if (ptv->tv_usec >= 1000000) { ptv->tv_sec++; ptv->tv_usec -= 1000000; }
    return *ptv;
}

/* ==========================================================================
   Logic Separation: Burst vs Normal
   ========================================================================== */

// --- BURST MODE: Pre-build once, send repeatedly ---
void run_burst_mode(pcap_t* fp, const SenderConfig* cfg) {
    std::cout << "[INFO] Running BURST mode (Pre-built packets)." << std::endl;

    // 1. 预构建一个包 (Pre-build the packet)
    std::vector<unsigned char> raw_packet(10000, 0);
    int packet_len = 0;
    // 使用 seq_num = 1，因为在 burst 模式下内容固定不重要
    build_package(raw_packet.data(), &packet_len, 1, cfg);

    if (packet_len <= 0) {
        std::cerr << "[ERROR] Failed to build packet for burst mode." << std::endl;
        return;
    }

    // 2. 准备发送队列 (Prepare the Queue)
    const unsigned int npacks = 2048; // Batch size
    // 申请足够的内存空间
    unsigned int queue_mem_size = (packet_len + sizeof(struct pcap_pkthdr)) * npacks + 1000;
    pcap_send_queue* squeue = pcap_sendqueue_alloc(queue_mem_size);

    if (!squeue) {
        std::cerr << "[ERROR] Queue alloc failed." << std::endl;
        return;
    }

    // 填充队列
    struct pcap_pkthdr pktheader;
    pktheader.ts.tv_sec = 0;
    pktheader.ts.tv_usec = 0;
    pktheader.caplen = packet_len;
    pktheader.len = packet_len;

    // 将同一个包复制 npacks 次填入队列
    unsigned int actual_queued_packs = 0;
    for (unsigned int i = 0; i < npacks; ++i) {
        if (pcap_sendqueue_queue(squeue, &pktheader, raw_packet.data()) == -1) {
            break;
        }
        actual_queued_packs++;
    }

    // [修正核心] 计算这一批次的真实数据量
    // packet_len: 单个包长度 (e.g. 64)
    // actual_queued_packs: 这一批有多少个包 (e.g. 2048)
    uint64_t bytes_per_batch = (uint64_t)packet_len * actual_queued_packs;

    // 初始化统计计时器
    auto last_stats_time = std::chrono::steady_clock::now();

    // 3. 极速发送循环 (Fast Send Loop)
    while (g_is_sending) {
        // sync = 0 表示忽略时间戳，全力发送
        unsigned int sent_bytes = pcap_sendqueue_transmit(fp, squeue, 0);

        // 如果 sent_bytes < squeue->len，说明发送可能没完全成功，
        // 但在统计上我们通常假设批次发送是原子的，或者简单累加
        // 既然是性能测试，我们按照理论值累加计数

        // [修正核心] 累加的是包的个数，不是 squeue->len
        g_total_sent += actual_queued_packs;

        // [修正核心] 累加的是真实的载荷字节数
        g_total_bytes += bytes_per_batch;

        // 限制回调频率：每 200ms 更新一次 UI
        auto now = std::chrono::steady_clock::now();
        auto elapsed_ms = std::chrono::duration_cast<std::chrono::milliseconds>(now - last_stats_time).count();

        if (elapsed_ms >= 200) {
            if (cfg->stats_callback) {
                cfg->stats_callback(g_total_sent, g_total_bytes);
            }
            last_stats_time = now;
        }
    }

    // 退出时强制更新最后一次统计
    if (cfg->stats_callback) {
        cfg->stats_callback(g_total_sent, g_total_bytes);
    }

    pcap_sendqueue_destroy(squeue);
}

// --- NORMAL MODE: Rebuild per packet, respect intervals ---
void run_normal_mode(pcap_t* fp, const SenderConfig* cfg) {
    std::cout << "[INFO] Running INTERVAL mode (Rebuild packets)." << std::endl;

    // Calculate batch size based on interval to buffer ~1s worth or max 5000
    unsigned int target_batch_time_us = 1000000;
    unsigned int safe_interval = (cfg->send_interval_us == 0) ? 1 : cfg->send_interval_us;
    unsigned int npacks = target_batch_time_us / safe_interval;
    if (npacks < 1) npacks = 1;
    if (npacks > 5000) npacks = 5000;

    long long batch_duration_us = (long long)npacks * cfg->send_interval_us;

    std::vector<unsigned char> shared_buffer(10000, 0);
    unsigned int queue_mem_size = (2000 + sizeof(struct pcap_pkthdr)) * npacks;
    pcap_send_queue* squeue = pcap_sendqueue_alloc(queue_mem_size);

    if (!squeue) return;

    unsigned int seq_counter = 1;
    auto next_batch_time = std::chrono::steady_clock::now();
    struct pcap_pkthdr pktheader;
    timeval tv; tv.tv_sec = 0; tv.tv_usec = 0;

    while (g_is_sending) {
        next_batch_time += std::chrono::microseconds(batch_duration_us);

        // Clear queue for new batch
        squeue->len = 0;
        uint64_t batch_bytes = 0;
        unsigned int actual_sent_packs = 0; // [修正] 新增变量，记录这一批实际放入的包数
        int packet_len = 0;

        // Build batch
        for (unsigned int i = 0; i < npacks; ++i) {
            build_package(shared_buffer.data(), &packet_len, (int)seq_counter++, cfg);
            if (packet_len <= 0) continue;

            pktheader.ts = tv;
            pktheader.caplen = packet_len;
            pktheader.len = packet_len;

            if (pcap_sendqueue_queue(squeue, &pktheader, shared_buffer.data()) == -1) break;

            batch_bytes += packet_len;
            actual_sent_packs++; // [修正] 成功放入队列才 +1
            add_stamp(&tv, cfg->send_interval_us);
        }

        if (squeue->len > 0) {
            // sync = 1 : Respect timestamps
            pcap_sendqueue_transmit(fp, squeue, 1);
        }

        // [修正核心]
        // 错误写法: g_total_sent += squeue->len;
        // 正确写法: 累加实际的包数
        g_total_sent += actual_sent_packs;

        // 累加字节数 (已经在循环里算好了)
        g_total_bytes += batch_bytes;

        if (cfg->stats_callback) {
            cfg->stats_callback(g_total_sent, g_total_bytes);
        }

        // Precision Wait
        auto now = std::chrono::steady_clock::now();
        if (now < next_batch_time) {
            auto remaining = std::chrono::duration_cast<std::chrono::microseconds>(next_batch_time - now).count();
            if (remaining > 1000) std::this_thread::sleep_for(std::chrono::microseconds(remaining));
            else if (remaining > 0) std::this_thread::yield();
        } else {
            next_batch_time = std::chrono::steady_clock::now();
        }
    }

    pcap_sendqueue_destroy(squeue);
}
/* ==========================================================================
   Exported Entry Point
   ========================================================================== */
extern "C" void start_send_mode(const SenderConfig* config) {
    char errbuf[PCAP_ERRBUF_SIZE];
    if (!config || !config->dev_name[0]) return;

    pcap_t* handler = pcap_open(config->dev_name, 65535, PCAP_OPENFLAG_PROMISCUOUS, 1, NULL, errbuf);
    if (!handler) {
        std::cerr << "[ERROR] pcap_open failed: " << errbuf << std::endl;
        return;
    }

    // Branch execution based on interval
    if (config->send_interval_us == 0) {
        run_burst_mode(handler, config);
    } else {
        run_normal_mode(handler, config);
    }

    pcap_close(handler);
    std::cout << "[INFO] Sending stopped." << std::endl;
}

// === Socket Sender (Unchanged) ===
#define LOG_SOCK(level, fmt, ...) do { \
if (config->log_callback) { \
        char buf[512]; \
        snprintf(buf, sizeof(buf), fmt, ##__VA_ARGS__); \
        config->log_callback(buf, level); \
} \
} while(0)

    extern "C" void start_socket_send_mode(const SocketConfig* config) {
        if (!config) return;

        WSADATA wsaData;
        if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) return;

        SOCKET sockfd = INVALID_SOCKET;
        int type = config->is_udp ? SOCK_DGRAM : SOCK_STREAM;
        int proto = config->is_udp ? IPPROTO_UDP : IPPROTO_TCP;

        sockfd = socket(AF_INET, type, proto);
        if (sockfd == INVALID_SOCKET) {
            WSACleanup();
            return;
        }

        if (config->source_ip[0] != '\0' && strcmp(config->source_ip, "0.0.0.0") != 0 && strcmp(config->source_ip, "") != 0) {
            struct sockaddr_in local_addr;
            memset(&local_addr, 0, sizeof(local_addr));
            local_addr.sin_family = AF_INET;
            local_addr.sin_addr.s_addr = inet_addr(config->source_ip);
            local_addr.sin_port = 0;
            bind(sockfd, (struct sockaddr*)&local_addr, sizeof(local_addr));
        }

        struct sockaddr_in dest_addr;
        memset(&dest_addr, 0, sizeof(dest_addr));
        dest_addr.sin_family = AF_INET;
        dest_addr.sin_port = htons(config->target_port);
        dest_addr.sin_addr.s_addr = inet_addr(config->target_ip);

        if (!config->is_udp) {
            u_long mode = 1;
            ioctlsocket(sockfd, FIONBIO, &mode);
            int connect_ret = connect(sockfd, (struct sockaddr*)&dest_addr, sizeof(dest_addr));
            bool connected = false;

            if (connect_ret == 0) connected = true;
            else {
                int err = WSAGetLastError();
                if (err == WSAEWOULDBLOCK) {
                    int max_retries = 30;
                    for (int i = 0; i < max_retries; ++i) {
                        if (!g_is_sock_sending) break;
                        fd_set write_fds, except_fds;
                        FD_ZERO(&write_fds); FD_SET(sockfd, &write_fds);
                        FD_ZERO(&except_fds); FD_SET(sockfd, &except_fds);
                        timeval tv; tv.tv_sec = 0; tv.tv_usec = 100000;
                        int sel_ret = select(0, NULL, &write_fds, &except_fds, &tv);
                        if (sel_ret > 0) {
                            if (FD_ISSET(sockfd, &write_fds)) { connected = true; break; }
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
                    if (wait_us > 100000) {
                        while (wait_us > 0 && g_is_sock_sending) {
                            int sleep_slice = (wait_us > 100000) ? 100000 : wait_us;
                            std::this_thread::sleep_for(std::chrono::microseconds(sleep_slice));
                            wait_us -= sleep_slice;
                            if (!g_is_sock_sending) break;
                        }
                    } else {
                        if (wait_us > 1000) std::this_thread::sleep_for(std::chrono::microseconds(wait_us));
                        else while (std::chrono::steady_clock::now() < next_send_time) {}
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
#pragma pack()
