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

static void report_time(struct timespec *beg, struct timespec *end, int iters,
                        char *label) {
    printf("%s: %ld ns/call\n", label,
           ((end->tv_nsec - beg->tv_nsec) +
            (end->tv_sec - beg->tv_sec) * 1000000000) /
               iters);
}

static void bench_uprobed_add(struct timespec *beg, struct timespec *end,
                              int iters) {
    clock_gettime(CLOCK_MONOTONIC_RAW, beg);

    for (int i = 0; i < iters; i++) {
        uprobed_add(0, 0);
    }

    clock_gettime(CLOCK_MONOTONIC_RAW, end);
}

int main() {
    int iters = 1 * 1000 * 1000;

    struct uprobe_bpf *object = uprobe_bpf__open_and_load();
    if (!object) {
        panic("open and load");
    }

    struct timespec beg, end;

    object->links.uprobe = bpf_program__attach(object->progs.uprobe);
    if (!object->links.uprobe) {
        panic("error attaching");
    }

    bench_uprobed_add(&beg, &end, iters);
    report_time(&beg, &end, iters, "uprobe");

    object->links.uretprobe = bpf_program__attach(object->progs.uretprobe);
    if (!object->links.uretprobe) {
        panic("error attaching");
    }

    bench_uprobed_add(&beg, &end, iters);
    report_time(&beg, &end, iters, "uprobe + uretprobe");

    uprobe_bpf__destroy(object);
}
