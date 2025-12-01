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

/* 构造整包 */
static void build_package(
    unsigned char* package,
    int* package_len,
    unsigned short type,
    int seq_num,
    const unsigned char src_mac[6],
    const unsigned char des_mac[6],
    const unsigned char src_ip[4],
    const unsigned char des_ip[4],
    // === 新增参数 ===
    unsigned short src_port_in,
    unsigned short dst_port_in,
    unsigned short payload_len_in,
    unsigned char tcp_flags_in,
    const char* domain_in
    )
{
    int udp_len;
    int icmp_len;
    int ip_len;

    // 使用传入的端口，如果为0则使用默认
    unsigned short s_port = (src_port_in == 0) ? 10086 : src_port_in;
    unsigned short d_port = (dst_port_in == 0) ? 10086 : dst_port_in;

    switch (type)
    {
    case UDP_PACKAGE:
        // UDP 长度 = 头部(8字节) + 负载长度
        // 如果用户没传 payload_len，默认给 86-8=78 字节负载
        udp_len = 8 + (payload_len_in == 0 ? 78 : payload_len_in);

        ip_len = 20 + udp_len;

        *package_len = 14 + ip_len;
        build_ethernet_header(package, des_mac, src_mac, 0x0800);
        build_ip_header(package, src_ip, des_ip, (unsigned short)ip_len, 0x11);
        build_udp_header(package, s_port, d_port, (unsigned short)udp_len);
        break;

    case ICMP_PACKAGE:
        // ICMP 忽略端口和长度设置，使用标准长度
        icmp_len = 8 + 5;
        ip_len = 20 + icmp_len;
        *package_len = 14 + ip_len;
        build_ethernet_header(package, des_mac, src_mac, 0x0800);
        build_ip_header(package, src_ip, des_ip, (unsigned short)ip_len, 0x01);
        build_icmp_header(package, seq_num);
        break;

    case DNS_PACKAGE:
        // DNS 逻辑保持不变 (暂不使用自定义端口)
        {
            // 使用传入的域名，如果为空则给默认值防止崩溃
            const char* target_domain = (domain_in && *domain_in) ? domain_in : "baidu.com";

            int domain_length = (int)strlen(target_domain);
            int dns_package_len = 12 + domain_length + 2 + 4;

            *package_len = 14 + 20 + 8 + dns_package_len;
            unsigned short ip_total_len = (unsigned short)(*package_len - 14);

            build_ethernet_header(package, des_mac, src_mac, 0x0800);
            build_ip_header(package, src_ip, des_ip, ip_total_len, 0x11);

            // 注意：这里 build_dns 函数需要修改吗？
            // 不需要修改 build_dns 的签名，只需要传参即可。
            build_dns(package, target_domain, dns_package_len);
        }
        break;
    case TCP_PACKAGE:
    {
        // TCP 头固定 20 字节，加上用户指定的 payload_len
        // 如果用户没填长度，默认发 0 长度载荷
        int tcp_data_len = (payload_len_in == 0) ? 0 : payload_len_in;
        int tcp_total_len = 20 + tcp_data_len;
        ip_len = 20 + tcp_total_len;

        *package_len = 14 + ip_len;

        // 1. 构造以太网头
        build_ethernet_header(package, des_mac, src_mac, 0x0800);

        // 2. 构造 IP 头 (Protocol = 0x06 代表 TCP)
        build_ip_header(package, src_ip, des_ip, (unsigned short)ip_len, 0x06);

        // 3. 填充 TCP 载荷数据 (可选：填入一些 dummy data)
        if (tcp_data_len > 0) {
            char* data_ptr = (char*)(package + 14 + 20 + 20);
            memset(data_ptr, 'A', tcp_data_len); // 填充 'A'
        }

        // 4. 构造 TCP 头
        // 这里需要策略：
        // seq_num: 我们使用传入的 seq_num (发包循环的 i) 作为序列号
        // flags: 默认设为 SYN (0x02) 用于测试连接，或者 PSH|ACK (0x18)

        build_tcp_header(package,
                         s_port,
                         d_port,
                         seq_num, // Sequence Number
                         0,
                         tcp_flags_in,
                         64240,   // Window Size
                         (u_short)tcp_data_len,
                         src_ip, des_ip);
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
void send_queue(
    pcap_t* fp,
    unsigned int npacks,
    unsigned int dus,
    unsigned short packet_type,
    const unsigned char src_mac[6],
    const unsigned char des_mac[6],
    const unsigned char src_ip[4],
    const unsigned char des_ip[4],
    // === 新增参数 ===
    unsigned short src_port,
    unsigned short dst_port,
    unsigned short payload_len,
    unsigned char tcp_flags,
    const char* domain_url
    )
{
    unsigned int i;

    pcap_send_queue* squeue;
    const int MaxPacketLen = 10000000;

    struct pcap_pkthdr mpktheader;
    struct pcap_pkthdr* pktheader = &mpktheader;

    timeval tv;
    tv.tv_sec = 0;
    tv.tv_usec = 0;

    squeue = pcap_sendqueue_alloc(
        (unsigned int)((MaxPacketLen + sizeof(struct pcap_pkthdr)) * npacks)
        );
    if (!squeue) {
        printf("pcap_sendqueue_alloc failed\n");
        return;
    }

    unsigned char* package = new unsigned char[10000]();
    int package_len = 0;

    for (i = 0; i < npacks; i++)
    {

        build_package(
            package,
            &package_len,
            packet_type,
            (int)(i + 1),
            src_mac,
            des_mac,
            src_ip,
            des_ip,
            // === 传递新增参数 ===
            src_port,
            dst_port,
            payload_len,
            tcp_flags,
            domain_url
            );

        if (package_len <= 0) {
            continue;
        }

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

        add_stamp(&tv, dus);
        pktheader->ts = tv;
    }

    delete[] package;

    int send_num = pcap_sendqueue_transmit(fp, squeue, 1);
    if ((unsigned int)send_num < squeue->len)
    {
        printf("transmit error %s, only %d bytes sent of %u\n",
               pcap_geterr(fp), send_num, squeue->len);
    }
    else {
        printf("transmit ok, bytes=%d queued=%u\n", send_num, squeue->len);
    }

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
extern "C" void start_send_mode(
    const char* dev_name,
    const unsigned char src_mac[6],
    const unsigned char des_mac[6],
    const unsigned char src_ip[4],
    const unsigned char des_ip[4],
    unsigned int send_interval_us,
    unsigned short packet_type,
    // === 新增参数 ===
    unsigned short src_port,
    unsigned short dst_port,
    unsigned short payload_len,
    unsigned char tcp_flags,
    const char* domain_url
    )
{
    char errbuf[PCAP_ERRBUF_SIZE];

    if (!dev_name || !*dev_name) {
        printf("start_send_mode: invalid dev_name\n");
        return;
    }

    pcap_t* handler = pcap_open(dev_name,
                                65535,
                                PCAP_OPENFLAG_PROMISCUOUS,
                                3000,
                                NULL,
                                errbuf);
    if (!handler) {
        printf("err in pcap_open (%s): %s\n", dev_name, errbuf);
        return;
    }
    cout << "choose " << dev_name << " for send..." << endl;

    // === 修复开始 ===
    // 目标：每批次发包占用约 1s 的时间，这样 UI 点击 Stop 后，最多延迟 0.2秒 就会停止
    unsigned int target_batch_time_us = 1000000; // 1s

    // 计算每批次应该发多少个包
    // 如果间隔是 0，避免除以零错误，强制设为 1
    unsigned int safe_interval = (send_interval_us == 0) ? 1 : send_interval_us;
    unsigned int npacks = target_batch_time_us / safe_interval;

    // 限制边界：至少发1个包，最多发1000个包
    if (npacks < 1) npacks = 1;
    if (npacks > 1000) npacks = 1000;

    // === 修复核心：计算理论耗时 ===
    // 这批包理论上应该消耗的总微秒数
    long long expected_duration_us = (long long)npacks * send_interval_us;

    while (g_is_sending) {
        // 1. 记录开始时间
        auto start_time = std::chrono::steady_clock::now();

        // 2. 发送数据 (如果是 npacks=1，这里会瞬间返回)
        send_queue(handler,
                   npacks,
                   send_interval_us,
                   packet_type,
                   src_mac,
                   des_mac,
                   src_ip,
                   des_ip,
                   src_port,
                   dst_port,
                   payload_len,
                   tcp_flags,
                   domain_url);

        // 3. 记录结束时间
        auto end_time = std::chrono::steady_clock::now();

        // 4. 计算实际花费了多少微秒
        long long elapsed_us = std::chrono::duration_cast<std::chrono::microseconds>(end_time - start_time).count();

        // 5. 如果发得太快（比理论时间短），就通过 Sleep 补足剩余时间
        if (elapsed_us < expected_duration_us) {
            // 需要补足的时间
            long long sleep_us = expected_duration_us - elapsed_us;

            // 只有当需要休眠的时间比较长时才 sleep，避免极短时间的 sleep 精度问题
            if (sleep_us > 100) {
                std::this_thread::sleep_for(std::chrono::microseconds(sleep_us));
            }
        }

        // (可选) 防止 CPU 100% 占用，如果间隔极小，加个极短的 yield
        if (expected_duration_us == 0) std::this_thread::yield();
    }

    pcap_close(handler);
    printf("Sending stopped gracefully.\n");
}



#pragma pack()



