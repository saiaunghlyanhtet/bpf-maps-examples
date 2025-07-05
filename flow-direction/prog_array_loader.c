#include <stdio.h>
#include <stdlib.h>
#include <bpf/libbpf.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <errno.h>

int main(int argc, char **argv) {
    struct bpf_object *obj;
    struct bpf_program *prog_main, *prog_ip_filter, *prog_rate_limiter;
    struct bpf_map *prog_array, *banned_ips;
    int prog_fd_main, prog_fd_ip_filter, prog_fd_rate_limiter, map_fd, banned_ips_fd;
    int ret;

    // Check for network interface argument
    if (argc != 2) {
        fprintf(stderr, "Usage: %s <interface>\n", argv[0]);
        return 1;
    }

    // Open and load eBPF object
    obj = bpf_object__open_file("prog_array_kern.o", NULL);
    if (libbpf_get_error(obj)) {
        fprintf(stderr, "Failed to open BPF object\n");
        return 1;
    }

    ret = bpf_object__load(obj);
    if (ret) {
        fprintf(stderr, "Failed to load BPF object\n");
        return 1;
    }

    // Get program file descriptors
    prog_main = bpf_object__find_program_by_name(obj, "xdp_main");
    prog_ip_filter = bpf_object__find_program_by_name(obj, "xdp_ip_filter");
    prog_rate_limiter = bpf_object__find_program_by_name(obj, "xdp_rate_limiter");
    prog_fd_main = bpf_program__fd(prog_main);
    prog_fd_ip_filter = bpf_program__fd(prog_ip_filter);
    prog_fd_rate_limiter = bpf_program__fd(prog_rate_limiter);

    // Get map file descriptors
    prog_array = bpf_object__find_map_by_name(obj, "prog_array");
    banned_ips = bpf_object__find_map_by_name(obj, "banned_ips");
    map_fd = bpf_map__fd(prog_array);
    banned_ips_fd = bpf_map__fd(banned_ips);

    // Populate prog_array map
    __u32 index_ip_filter = 1;
    __u32 index_rate_limiter = 2;
    ret = bpf_map_update_elem(map_fd, &index_ip_filter, &prog_fd_ip_filter, BPF_ANY);
    if (ret) {
        fprintf(stderr, "Failed to update prog_array for ip_filter\n");
        return 1;
    }
    ret = bpf_map_update_elem(map_fd, &index_rate_limiter, &prog_fd_rate_limiter, BPF_ANY);
    if (ret) {
        fprintf(stderr, "Failed to update prog_array for rate_limiter\n");
        return 1;
    }

    // Add a banned IP (e.g., 192.168.1.100)
    __u32 banned_ip;
    inet_pton(AF_INET, "192.168.1.100", &banned_ip);
    __u8 banned_value = 1;
    ret = bpf_map_update_elem(banned_ips_fd, &banned_ip, &banned_value, BPF_ANY);
    if (ret) {
        fprintf(stderr, "Failed to update banned_ips map\n");
        return 1;
    }

    // Attach main program to network interface
    int ifindex = if_nametoindex(argv[1]);
    if (!ifindex) {
        fprintf(stderr, "Invalid interface: %s\n", argv[1]);
        return 1;
    }
    ret = bpf_set_link_xdp_fd(ifindex, prog_fd_main, 0);
    if (ret < 0) {
        fprintf(stderr, "Failed to attach XDP program: %s\n", strerror(-ret));
        return 1;
    }

    printf("XDP program loaded on %s, banned IP 192.168.1.100\n", argv[1]);
    printf("Press Ctrl+C to exit...\n");
    while (1) sleep(1); // Keep program running

    // Cleanup (unreachable in this example, but for completeness)
    bpf_set_link_xdp_fd(ifindex, -1, 0);
    bpf_object__close(obj);
    return 0;
}
