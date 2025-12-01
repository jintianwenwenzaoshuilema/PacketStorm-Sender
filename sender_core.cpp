#include "sender_core.h"
#include <stdio.h>
#include <stdlib.h>
#include <iostream>
#include <thread>
#include <string.h>
#include <pcap.h>
#include <chrono> // 用于计算时间
#include <thread> // 用于 sleep

// === 1. 定义分离的原子标志 ===
std::atomic<bool> g_is_sending{false};


#ifndef WIN32
#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>
#else
#include <winsock.h>
#endif

#include <pcap.h>

using namespace std;

#pragma pack(1)


/* 工具函数 */

#define IPTOSBUFFERS    12
static char* iptos(u_long in)
{
    static char output[IPTOSBUFFERS][3 * 4 + 3 + 1];
    static short which;
    u_char* p = (u_char*)&in;
    which = (short)((which + 1 == IPTOSBUFFERS) ? 0 : which + 1);
    sprintf(output[which], "%d.%d.%d.%d", p[0], p[1], p[2], p[3]);
    return output[which];
}

/* 协议头结构 */

struct ip_v4_address {
    u_char byte1;
    u_char byte2;
    u_char byte3;
    u_char byte4;
};

struct mac_address {
    u_char byte1;
    u_char byte2;
    u_char byte3;
    u_char byte4;
    u_char byte5;
    u_char byte6;
};

struct ethernet_header {
    mac_address des_mac_addr;
    mac_address src_mac_addr;
    u_short type;
};

struct ip_v4_header {
    u_char  ver_ihl;
    u_char  tos;
    u_short tlen;
    u_short identification;
    u_short flags_fo;
    u_char  ttl;
    u_char  proto;
    u_short checksum;
    ip_v4_address src_ip_addr;
    ip_v4_address des_ip_addr;
    u_int   op_pad;
};

/* 自定义 UDP 头 包含时间戳字段 */

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


/* 校验和相关 */

static u_short checksum(u_short* buffer, int size)
{
    unsigned long cksum = 0;
    while (size > 1)
    {
        cksum += *buffer++;
        size -= sizeof(u_short);
    }
    if (size)
    {
        cksum += *(u_short*)buffer;
    }
    cksum = (cksum >> 16) + (cksum & 0xffff);
    cksum += (cksum >> 16);
    return (u_short)(~cksum);
}

/* 构造以太网头 */

static void build_ethernet_header(unsigned char* package, const u_char des_mac[6], const u_char src_mac[6], u_short type)
{
    ethernet_header* eh = (ethernet_header*)package;

    eh->des_mac_addr.byte1 = des_mac[0];
    eh->des_mac_addr.byte2 = des_mac[1];
    eh->des_mac_addr.byte3 = des_mac[2];
    eh->des_mac_addr.byte4 = des_mac[3];
    eh->des_mac_addr.byte5 = des_mac[4];
    eh->des_mac_addr.byte6 = des_mac[5];

    eh->src_mac_addr.byte1 = src_mac[0];
    eh->src_mac_addr.byte2 = src_mac[1];
    eh->src_mac_addr.byte3 = src_mac[2];
    eh->src_mac_addr.byte4 = src_mac[3];
    eh->src_mac_addr.byte5 = src_mac[4];
    eh->src_mac_addr.byte6 = src_mac[5];

    eh->type = htons(type);
}

/* 构造 IPv4 头 */

static void build_ip_header(u_char* package, const u_char src_ip[4], const u_char des_ip[4], u_short ip_len, u_char proto_type)
{
    ip_v4_header* ih = (ip_v4_header*)(package + 14);

    ih->ver_ihl = 0x45;
    ih->tos = 0x00;
    ih->tlen = htons(ip_len);

    ih->identification = 0;
    ih->flags_fo = htons(0x4000);

    ih->ttl = 0x80;
    ih->proto = proto_type;
    ih->checksum = 0;

    ih->src_ip_addr.byte1 = src_ip[0];
    ih->src_ip_addr.byte2 = src_ip[1];
    ih->src_ip_addr.byte3 = src_ip[2];
    ih->src_ip_addr.byte4 = src_ip[3];

    ih->des_ip_addr.byte1 = des_ip[0];
    ih->des_ip_addr.byte2 = des_ip[1];
    ih->des_ip_addr.byte3 = des_ip[2];
    ih->des_ip_addr.byte4 = des_ip[3];

    ih->checksum = checksum((u_short*)ih, 20);
}

/* 伪首部 */

typedef struct psd_header {
    ip_v4_address s_ip;
    ip_v4_address d_ip;
    u_char mbz;
    u_char proto;
    u_short plen;
} psd_header;

/* 构造 UDP 头 */

static void build_udp_header(unsigned char* package, u_short s_port, u_short d_port, u_short udp_len)
{
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

    int pseudo_len = (int)sizeof(psd) + udp_len;
    char* tmp = (char*)calloc(1, pseudo_len);
    if (!tmp) return;
    memcpy(tmp, &psd, sizeof(psd));
    memcpy(tmp + sizeof(psd), uh, udp_len);

    uh->checksum = checksum((u_short*)tmp, pseudo_len);
    free(tmp);
}

/* 构造 TCP 头 */
static void build_tcp_header(unsigned char* package, u_short s_port, u_short d_port,
                             u_int seq, u_int ack, u_char flags, u_short win, u_short tcp_payload_len,
                             const u_char* src_ip, const u_char* dst_ip)
{
    // 定位 TCP 头位置：以太网(14) + IP(20)
    tcp_header* th = (tcp_header*)(package + 14 + 20);

    // 填充基本字段
    th->sport = htons(s_port);
    th->dport = htons(d_port);
    th->sequence = htonl(seq);
    th->acknowledgement = htonl(ack);

    // Data Offset (头部长度): 通常是 5 (5 * 4 = 20 字节)
    // 高 4 位是 offset，低 4 位是保留位
    th->offset = (5 << 4);

    th->flags = flags;
    th->windows = htons(win);
    th->urgent_pointer = 0;
    th->checksum = 0; // 先置 0

    // 计算校验和需要伪首部
    // TCP 长度 = TCP头(20) + 载荷长度
    int tcp_total_len = 20 + tcp_payload_len;

    psd_header psd;
    // 注意：这里需要从 package 的 IP 头里取，或者通过参数传进来
    // 为方便，我们手动填充 psd 的 IP
    psd.s_ip.byte1 = src_ip[0]; psd.s_ip.byte2 = src_ip[1]; psd.s_ip.byte3 = src_ip[2]; psd.s_ip.byte4 = src_ip[3];
    psd.d_ip.byte1 = dst_ip[0]; psd.d_ip.byte2 = dst_ip[1]; psd.d_ip.byte3 = dst_ip[2]; psd.d_ip.byte4 = dst_ip[3];
    psd.mbz = 0;
    psd.proto = 0x06; // TCP 协议号
    psd.plen = htons((u_short)tcp_total_len);

    // 申请临时内存计算校验和：伪首部 + TCP头 + TCP数据
    int pseudo_total_len = sizeof(psd) + tcp_total_len;
    char* tmp = (char*)calloc(1, pseudo_total_len);
    if (!tmp) return;

    memcpy(tmp, &psd, sizeof(psd));
    // 拷贝 TCP 头
    memcpy(tmp + sizeof(psd), th, 20);
    // 拷贝 TCP 数据 (如果有)
    if (tcp_payload_len > 0) {
        memcpy(tmp + sizeof(psd) + 20, package + 14 + 20 + 20, tcp_payload_len);
    }

    th->checksum = checksum((u_short*)tmp, pseudo_total_len);
    free(tmp);
}

/* ICMP 构造 */

struct icmp_echo {
    uint8_t type;
    uint8_t code;
    uint16_t checksum;
    uint16_t ident;
    uint16_t seq;
};

static uint16_t calculate_checksum(unsigned char* buffer, int bytes)
{
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

static void build_icmp_header(unsigned char* package, int seq_num)
{
    int icmp_total_len = 8 + 5;

    icmp_echo* icmph = (icmp_echo*)(package + 14 + 20);
    unsigned char* icmp_data = (unsigned char*)(package + 14 + 20 + 8);

    memset(icmph, 0, icmp_total_len);

    icmph->type = 8;
    icmph->code = 0;
    icmph->checksum = 0;
    icmph->ident = htons(0x1234);
    icmph->seq = htons((uint16_t)seq_num);

    icmp_data[0] = 0x12;
    icmp_data[1] = 0x34;
    icmp_data[2] = 0x56;
    icmp_data[3] = 0x78;
    icmp_data[4] = 0x90;

    icmph->checksum = htons(calculate_checksum((unsigned char*)icmph, icmp_total_len));
}

/* DNS 相关结构和函数 */

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

static int dns_create_header(struct dns_header* header)
{
    if (header == NULL) return -1;
    memset(header, 0, sizeof(struct dns_header));

    header->id = (unsigned short)(rand() % 65535);
    header->flags = htons(0x0100);
    header->questions = htons(1);
    return 0;
}

static int dns_create_queries(struct dns_queries* question, const char* hostname)
{
    if (question == NULL || hostname == NULL) return -1;
    memset(question, 0, sizeof(struct dns_queries));

    size_t host_len = strlen(hostname);
    question->name = (char*)malloc(host_len + 2);
    if (question->name == NULL) {
        return -2;
    }

    question->length = (int)host_len + 2;
    question->qtype = htons(1);
    question->qclass = htons(1);

    const char delim[2] = ".";
    char* qname = question->name;

    char* hostname_dup = (char*)calloc(1, host_len + 1);
    if (!hostname_dup) {
        free(question->name);
        question->name = NULL;
        return -3;
    }
    memcpy(hostname_dup, hostname, host_len);

    char* token = strtok(hostname_dup, delim);
    while (token != NULL) {
        size_t len = strlen(token);
        *qname = (char)len;
        qname++;
        memcpy(qname, token, len);
        qname += len;
        token = strtok(NULL, delim);
    }

    free(hostname_dup);
    return 0;
}

static int dns_build_request(struct dns_header* header, struct dns_queries* question, char* request)
{
    if (header == NULL || question == NULL || request == NULL) return -1;

    int offset = 0;

    memcpy(request, header, sizeof(struct dns_header));
    offset = (int)sizeof(struct dns_header);

    memcpy(request + offset, question->name, question->length);
    offset += question->length;

    memcpy(request + offset, &question->qtype, sizeof(question->qtype));
    offset += (int)sizeof(question->qtype);

    memcpy(request + offset, &question->qclass, sizeof(question->qclass));
    offset += (int)sizeof(question->qclass);

    return offset;
}

static void build_dns(unsigned char* package, const char* domain, int dns_package_len)
{
    udp_header* uh = (udp_header*)(package + 14 + 20);
    ip_v4_header* ih = (ip_v4_header*)(package + 14);
    int udp_len = 8 + dns_package_len;

    uh->sport = htons(10086);
    uh->dport = htons(53);
    uh->len = htons((u_short)udp_len);
    uh->checksum = 0;

    struct dns_header header;
    if (dns_create_header(&header) != 0) {
        return;
    }

    struct dns_queries question;
    if (dns_create_queries(&question, domain) != 0) {
        return;
    }

    char* request = (char*)(package + 14 + 20 + 8);
    int length = dns_build_request(&header, &question, request);
    (void)length;

    psd_header psd;
    psd.s_ip = ih->src_ip_addr;
    psd.d_ip = ih->des_ip_addr;
    psd.mbz = 0;
    psd.proto = 0x11;
    psd.plen = htons((u_short)udp_len);

    int pseudo_len = sizeof(psd) + udp_len;
    char* tmp = (char*)calloc(1, pseudo_len);
    if (!tmp) {
        free(question.name);
        return;
    }

    memcpy(tmp, &psd, sizeof(psd));
    memcpy(tmp + sizeof(psd), uh, udp_len);

    uh->checksum = checksum((u_short*)tmp, pseudo_len);
    free(tmp);
    free(question.name);
}


/* === 新增：载荷填充函数 === */
static void fill_payload_data(unsigned char* data_ptr, int len, const SenderConfig* cfg) {
    if (len <= 0) return;

    switch (cfg->payload_mode) {
    case PAYLOAD_FIXED:
        // 模式2：使用用户指定的固定字节填充 (例如 memset 0x00 或 0xFF)
        memset(data_ptr, cfg->fixed_byte_val, len);
        break;

    case PAYLOAD_CUSTOM:
        // 模式3：用户自定义数据
        if (cfg->custom_data) {
            // 注意：这里假设 custom_data 长度足够，或者由调用者保证 payload_len 正确
            // 实际工程中可以做更安全的检查，比如循环填充直到填满 len
            int custom_len = strlen(cfg->custom_data);
            if (custom_len >= len) {
                memcpy(data_ptr, cfg->custom_data, len);
            } else {
                // 如果自定义数据比需要的长度短，就循环填充
                int filled = 0;
                while (filled < len) {
                    int chunk = (len - filled > custom_len) ? custom_len : (len - filled);
                    memcpy(data_ptr + filled, cfg->custom_data, chunk);
                    filled += chunk;
                }
            }
        } else {
            memset(data_ptr, 0, len);
        }
        break;

    case PAYLOAD_RANDOM:
    default:
        // 模式1：随机填充 (保留原有逻辑)
        for (int i = 0; i < len; ++i) {
            data_ptr[i] = (unsigned char)(rand() % 256);
        }
        break;
    }
}

// === 修改后的 build_package (完整内容) ===
static void build_package(
    unsigned char* package,
    int* package_len,
    int seq_num,
    const SenderConfig* cfg // 参数改为结构体
    )
{
    int udp_len, icmp_len, ip_len;
    // 端口处理：0则使用默认
    unsigned short s_port = (cfg->src_port == 0) ? 10086 : cfg->src_port;
    unsigned short d_port = (cfg->dst_port == 0) ? 10086 : cfg->dst_port;

    switch (cfg->packet_type)
    {
    case UDP_PACKAGE:
        // UDP 长度 = 头部(8) + 负载
        udp_len = 8 + cfg->payload_len;
        ip_len = 20 + udp_len;
        *package_len = 14 + ip_len;

        build_ethernet_header(package, cfg->des_mac, cfg->src_mac, 0x0800);
        build_ip_header(package, cfg->src_ip, cfg->des_ip, (unsigned short)ip_len, 0x11);

        // --- 核心修改：填充 UDP 载荷 ---
        // 偏移：以太网(14) + IP(20) + UDP头(8)
        fill_payload_data(package + 14 + 20 + 8, cfg->payload_len, cfg);

        // 计算 UDP 校验和 (此时载荷已填充)
        build_udp_header(package, s_port, d_port, (unsigned short)udp_len);
        break;

    case ICMP_PACKAGE:
        // ICMP 保持原样，也可以支持 payload 但通常是固定的
        icmp_len = 8 + 5;
        ip_len = 20 + icmp_len;
        *package_len = 14 + ip_len;

        build_ethernet_header(package, cfg->des_mac, cfg->src_mac, 0x0800);
        build_ip_header(package, cfg->src_ip, cfg->des_ip, (unsigned short)ip_len, 0x01);
        build_icmp_header(package, seq_num);
        break;

    case DNS_PACKAGE:
    {
        const char* target_domain = (cfg->dns_domain && *cfg->dns_domain) ? cfg->dns_domain : "baidu.com";
        int domain_length = (int)strlen(target_domain);
        int dns_package_len = 12 + domain_length + 2 + 4;
        *package_len = 14 + 20 + 8 + dns_package_len;
        unsigned short ip_total_len = (unsigned short)(*package_len - 14);

        build_ethernet_header(package, cfg->des_mac, cfg->src_mac, 0x0800);
        build_ip_header(package, cfg->src_ip, cfg->des_ip, ip_total_len, 0x11);
        build_dns(package, target_domain, dns_package_len);
    }
    break;

    case TCP_PACKAGE:
    {
        int tcp_data_len = cfg->payload_len;
        int tcp_total_len = 20 + tcp_data_len;
        ip_len = 20 + tcp_total_len;
        *package_len = 14 + ip_len;

        build_ethernet_header(package, cfg->des_mac, cfg->src_mac, 0x0800);
        build_ip_header(package, cfg->src_ip, cfg->des_ip, (unsigned short)ip_len, 0x06);

        // --- 核心修改：填充 TCP 载荷 ---
        // 偏移：以太网(14) + IP(20) + TCP头(20)
        fill_payload_data(package + 14 + 20 + 20, tcp_data_len, cfg);

        build_tcp_header(package, s_port, d_port, seq_num, 0,
                         cfg->tcp_flags, 64240, (u_short)tcp_data_len,
                         cfg->src_ip, cfg->des_ip);
    }
    break;

    default:
        *package_len = 0;
        break;
    }
}

/* 发送队列相关 */

timeval add_stamp(timeval* ptv, unsigned int dus)
{
    ptv->tv_usec = ptv->tv_usec + dus;
    if (ptv->tv_usec >= 1000000)
    {
        ptv->tv_sec = ptv->tv_sec + 1;
        ptv->tv_usec = ptv->tv_usec - 1000000;
    }
    return *ptv;
}

// === 修改后的 send_queue (完整内容) ===
// 注意：保留了 seq_counter 的引用传递
void send_queue(pcap_t* fp, unsigned int npacks, const SenderConfig* cfg, unsigned int &seq_counter)
{
    unsigned int i;
    pcap_send_queue* squeue;
    const int MaxPacketLen = 10000;

    struct pcap_pkthdr mpktheader;
    struct pcap_pkthdr* pktheader = &mpktheader;

    timeval tv;
    tv.tv_sec = 0;
    tv.tv_usec = 0;

    squeue = pcap_sendqueue_alloc((unsigned int)((MaxPacketLen + sizeof(struct pcap_pkthdr)) * npacks));
    if (!squeue) {
        printf("pcap_sendqueue_alloc failed\n");
        return;
    }

    unsigned char* package = new unsigned char[10000]();
    int package_len = 0;

    for (i = 0; i < npacks; i++)
    {
        // 调用 build_package，传入结构体指针
        build_package(
            package,
            &package_len,
            (int)seq_counter++, // 序列号自增
            cfg
            );

        if (package_len <= 0) continue;

        pktheader->ts = tv;
        pktheader->caplen = (bpf_u_int32)package_len;
        pktheader->len = (bpf_u_int32)package_len;

        if (pcap_sendqueue_queue(squeue, pktheader, package) == -1)
        {
            printf("packet buffer too small, queue failed.\n");
            delete[] package;
            pcap_sendqueue_destroy(squeue);
            return;
        }

        add_stamp(&tv, cfg->send_interval_us); // 使用 cfg 中的间隔
        pktheader->ts = tv;
    }

    delete[] package;

    int send_num = pcap_sendqueue_transmit(fp, squeue, 1);
    // (日志输出可保留或注释)
    pcap_sendqueue_destroy(squeue);
}


/* 网卡选择函数 */

char* get_interface_name(int interface_idx)
{
    pcap_if_t* allDevs;
    char errbuf[PCAP_ERRBUF_SIZE];

    if (pcap_findalldevs(&allDevs, errbuf) != 0) {
        printf("pcap_findalldevs failed: %s\n", errbuf);
        return NULL;
    }

    int net_num = 0;
    pcap_if_t* d;
    for (d = allDevs; d != NULL; d = d->next) {
        printf("%d : %s \n", ++net_num, d->name);

        if (d->description)
            printf("%s\n", d->description);
        else
            printf("No description available\n");

        pcap_addr_t* a;
        for (a = d->addresses; a; a = a->next) {
            if (a->addr && a->addr->sa_family == AF_INET) {
                printf("\tAddress Family Name: AF_INET\n");
                if (a->addr)
                    printf("\tAddress: %s\n", iptos(((struct sockaddr_in*)a->addr)->sin_addr.s_addr));
                if (a->netmask)
                    printf("\tNetmask: %s\n", iptos(((struct sockaddr_in*)a->netmask)->sin_addr.s_addr));
                if (a->broadaddr)
                    printf("\tBroadcast Address: %s\n", iptos(((struct sockaddr_in*)a->broadaddr)->sin_addr.s_addr));
                if (a->dstaddr)
                    printf("\tDestination Address: %s\n", iptos(((struct sockaddr_in*)a->dstaddr)->sin_addr.s_addr));
            }
        }
        printf("\n");
    }

    if (net_num == 0) {
        printf("No interfaces found\n");
        pcap_freealldevs(allDevs);
        return NULL;
    }

    int inum;
    cout << "Please choose interface " << interface_idx
         << ", enter the interface number (1 - " << net_num << "): ";
    cin >> inum;

    if (inum < 1 || inum > net_num)
    {
        cout << "Interface number out of range." << endl;
        pcap_freealldevs(allDevs);
        return NULL;
    }

    pcap_if_t* dev = allDevs;
    for (int idx = 1; idx < inum; ++idx) {
        dev = dev->next;
    }

    printf("\nOpening: %s\n\n", dev->name);

    size_t name_len = strlen(dev->name);
    char* dev_name_copy = (char*)malloc(name_len + 1);
    if (!dev_name_copy) {
        pcap_freealldevs(allDevs);
        return NULL;
    }
    memcpy(dev_name_copy, dev->name, name_len + 1);

    pcap_freealldevs(allDevs);
    return dev_name_copy;
}






/* 发包模式入口 对外接口 */
// === 修改后的 start_send_mode (完整内容) ===
extern "C" void start_send_mode(const SenderConfig* config)
{
    char errbuf[PCAP_ERRBUF_SIZE];

    if (!config || !config->dev_name[0]) {
        printf("start_send_mode: invalid config\n");
        return;
    }

    pcap_t* handler = pcap_open(config->dev_name,
                                65535,
                                PCAP_OPENFLAG_PROMISCUOUS,
                                3000,
                                NULL,
                                errbuf);
    if (!handler) {
        printf("err in pcap_open (%s): %s\n", config->dev_name, errbuf);
        return;
    }
    std::cout << "Starting send on " << config->dev_name << "..." << std::endl;

    // === 创建本地配置副本 ===
    // 目的：防止多线程下外部修改了 config 指向的内容导致崩溃或数据不一致
    SenderConfig cfg = *config;

    // 计算批次
    unsigned int target_batch_time_us = 1000000; // 1s
    unsigned int safe_interval = (cfg.send_interval_us == 0) ? 1 : cfg.send_interval_us;
    unsigned int npacks = target_batch_time_us / safe_interval;

    if (npacks < 1) npacks = 1;
    if (npacks > 1000) npacks = 1000;

    long long expected_duration_us = (long long)npacks * cfg.send_interval_us;
    unsigned int current_seq_num = 1;

    while (g_is_sending) {
        auto start_time = std::chrono::steady_clock::now();

        // 调用 send_queue，传入结构体指针
        send_queue(handler, npacks, &cfg, current_seq_num);

        auto end_time = std::chrono::steady_clock::now();
        long long elapsed_us = std::chrono::duration_cast<std::chrono::microseconds>(end_time - start_time).count();

        if (elapsed_us < expected_duration_us) {
            long long sleep_us = expected_duration_us - elapsed_us;
            if (sleep_us > 100) {
                std::this_thread::sleep_for(std::chrono::microseconds(sleep_us));
            }
        }
        if (expected_duration_us == 0) std::this_thread::yield();
    }

    pcap_close(handler);
    printf("Sending stopped.\n");
}


#pragma pack()



