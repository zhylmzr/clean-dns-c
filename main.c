#include <arpa/inet.h>
#include <linux/bpf.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <linux/if_ether.h>
#include <linux/udp.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include "dns.h"

#undef bpf_printk

#ifdef NOPRINTK
#define bpf_printk(fmt, ...)
#else
/**
 * Only limited trace_printk() conversion specifiers allowed:
 * %d %i %u %x %ld %li %lu %lx %lld %lli %llu %llx %p %s
 */
#define bpf_printk(fmt, ...)                                                   \
    ({                                                                         \
        char ____fmt[] = fmt;                                                  \
        bpf_trace_printk(____fmt, sizeof(____fmt), ##__VA_ARGS__);             \
    })
#endif

// for bpf helpers
char _license[] SEC("license") = "GPL";

/* Parse IPv4 packet to get SRC, DST IP and protocol */
static inline int parse_ipv4(void *data, __u64 nh_off, void *data_end,
                             __be32 *src, __be32 *dest, int *proto, int *id,
                             int *flag) {
    struct iphdr *iph = data + nh_off;

    if ((__u64)(iph + 1) > (__u64)data_end)
        return 0;

    int hdsize = iph->ihl * 4;

    if ((__u64)(iph->ihl + hdsize) > (__u64)data_end) {
        return 0;
    }

    *src = iph->saddr;
    *dest = iph->daddr;
    *id = iph->id;
    *proto = iph->protocol;
    *flag = iph->frag_off;
    return hdsize;
}

/* Parse UDP packet to get SRC, DST port */
static inline int parse_udp_port(void *data, __u64 nh_off, void *data_end,
                                 int *src_port, int *dst_port) {
    struct udphdr *uph = data + nh_off;

    if ((__u64)(uph + 1) > (__u64)data_end) {
        return 0;
    }

    *src_port = uph->source;
    *dst_port = uph->dest;
    return uph->len;
}

SEC("xdp")
int xdp_clean_dns(struct xdp_md *ctx) {
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    struct ethhdr *eth = data;
    __u64 nh_off = sizeof(*eth);

    // 排除无效包
    if (data + nh_off > data_end) {
        return XDP_DROP;
    }

    __u16 h_proto = eth->h_proto;

    if (h_proto == htons(ETH_P_IPV6)) {
        return XDP_DROP;
    }

    // 打印以太帧头信息
    // bpf_printk("eth frame src: %llu, dst: %llu, proto: %u\n",
    //            ether_addr_to_u64(eth->h_source),
    //            ether_addr_to_u64(eth->h_dest), bpf_ntohs(eth->h_proto));

    // 非 ip 包直接跳过
    if (h_proto != __constant_htons(ETH_P_IP)) {
        goto pass;
    }

    __be32 src_ip = 0, dest_ip = 0;
    int ip_id = 0, ip_proto = 0, ip_flag;

    int ip_hdsize = parse_ipv4(data, nh_off, data_end, &src_ip, &dest_ip,
                               &ip_proto, &ip_id, &ip_flag);
    // 跳过非UDP包
    if (ip_proto != IPPROTO_UDP) {
        goto pass;
    }

    ip_id = bpf_htonl(ip_id);
    // 跳过非8.8.8.8的包
    if (bpf_htonl(src_ip) != 0x08080808) {
        goto pass;
    }

    if (ip_id == 0) {
        return XDP_DROP;
    } else if (ip_flag == 0x0040) {
        return XDP_DROP;
    }

    bpf_printk("src: %lx, dst: %lx, proto: %d\n", src_ip, dest_ip, ip_proto);
    bpf_printk("id: %x, ip_hdsize: %d\n", ip_id, ip_hdsize);

    nh_off += ip_hdsize;
    int src_port = 0, dst_port = 0;
    parse_udp_port(data, nh_off, data_end, &src_port, &dst_port);
    src_port = bpf_htons(src_port);
    dst_port = bpf_htons(dst_port);

    bpf_printk("src port: %x, dst port: %x\n", src_port, dst_port);

    if (src_port != 53) {
        goto pass;
    }

    nh_off += sizeof(struct udphdr);

    struct dnshdr *dns = data + nh_off;
    if ((__u64)(dns + 1) > (__u64)data_end) {
        goto pass;
    }

    bpf_printk("qr: %d, aa: %d\n", dns->qr, dns->aa);

    // pass dns answer
    if (dns->qr != 1) {
        goto pass;
    }

    // pass authority answer
    if (dns->ad != 0) {
        goto pass;
    }

    // pass multiple answers
    if (dns->ans_count > 1) {
        goto pass;
    }

    // drop has authority flag packet
    if (dns->aa == 1) {
        return XDP_DROP;
    }

pass:
    return XDP_PASS;
}
