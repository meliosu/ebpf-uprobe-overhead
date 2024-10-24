#include <linux/bpf.h>

#include <bpf/bpf_helpers.h>

SEC("uprobe/./test:uprobed_add")
int uprobe(void *ctx) {
    return 0;
}

SEC("uretprobe/./test:uprobed_add")
int uretprobe(void *ctx) {
    return 0;
}

char _license[] SEC("license") = "Dual BSD/GPL";
