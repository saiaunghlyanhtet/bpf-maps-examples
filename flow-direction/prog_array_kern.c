#include <linux/bpf.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

// This is the sample definition of a program array map.
struct {
    __uint(type, BPF_MAP_TYPE_PROG_ARRAY);
    __uint(max_entries, 10); // Maximum number of programs in the array
    __type(key, __u32);      // Key type is a 32-bit unsigned integer
    __type(value, __u32);    // Value type is a 32-bit unsigned integer (program ID)
} prog_array_map SEC(".maps");

// Map to stored banned IPs
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024); 
    __type(key, __u32);        // Source IP
    __type(value, __u8);       // 1 for banned, 0 for not banned
} banned_ips SEC(".maps");

// Map for rate limiting
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024); 
    __type(key, __u32);        // Source IP
    __type(value, __u64);       // Packet count
} rate_limit SEC(".maps");

SEC("xdp")
int xdp_main(struct xdp_md *ctx)
{
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    struct iphdr *iph;

    // Ensure the packet has enough data for IP header
    if (data + sizeof(struct ethhdr) + sizeof(struct iphdr) > data_end)
        return XDP_PASS;

    iph = (struct iphdr *)(data + sizeof(struct ethhdr));

    // Check if the source IP is banned (jump to IP filter program)
    __u8 *banned = bpf_map_lookup_elem(&banned_ips, &iph->saddr);
    if (banned && *banned) {
        bpf_tail_call(ctx, &prog_array_map, 1); // Jump to IP filter program
        return XDP_PASS; // Fallback if tail call fails
    }

    bpf_tail_call(ctx, &prog_array_map, 2); // Jump to rate limiting program
    return XDP_PASS;
}

SEC("xdp/ip_filter")
int xdp_ip_filter(struct xdp_md *ctx)
{
    bpf_printk("Dropping packet from banned IPs\n");
    return XDP_DROP;
}

SEC("xdp/rate_limiter")
int xdp_rate_limiter(struct xdp_md *ctx)
{
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    struct iphdr *iph;

    // Ensure the packet has enough data for IP header
    if (data + sizeof(struct ethhdr) + sizeof(struct iphdr) > data_end)
        return XDP_PASS;

    iph = (struct iphdr *)(data + sizeof(struct ethhdr));
    __u64 *count = bpf_map_lookup_elem(&rate_limit, &iph->saddr);
    __u64 new_count = count ? *count + 1 : 1;

    // Update the packet count in the rate limit map
    bpf_map_update_elem(&rate_limit, &iph->saddr, &new_count, BPF_ANY);

    if (new_count > 100) { // Example rate limit threshold
        bpf_printk("Rate limit exceeded for IP: %u\n", iph->saddr);
        return XDP_DROP; // Drop packet if rate limit exceeded
    }
    return XDP_PASS;
}
