#include <stdio.h>
#include <time.h>

#include <bpf/libbpf.h>

#include "uprobe.skel.h"

#define panic(fmt, args...)                                                    \
    do {                                                                       \
        printf(fmt "\n", ##args);                                              \
        exit(-1);                                                              \
    } while (0)

__attribute__((noinline)) int uprobed_add(int a, int b) {
    asm volatile("");
    return a + b;
}

int main() {
    int err;
    int iters = 1 * 1000 * 1000;

    struct uprobe_bpf *object = uprobe_bpf__open_and_load();
    if (!object) {
        panic("open_and_load");
    }

    err = uprobe_bpf__attach(object);
    if (err) {
        panic("attach");
    }

    struct timespec beg;
    clock_gettime(CLOCK_MONOTONIC_RAW, &beg);

    for (int i = 0; i < iters; i++) {
        uprobed_add(0, 0);
    }

    struct timespec end;
    clock_gettime(CLOCK_MONOTONIC_RAW, &end);

    long time_ns =
        end.tv_nsec - beg.tv_nsec + (end.tv_sec - beg.tv_sec) * 1000000000;

    printf("ns/call: %ld\n", time_ns / iters);

    uprobe_bpf__destroy(object);
}
