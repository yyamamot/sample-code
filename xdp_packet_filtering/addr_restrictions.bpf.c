//go:build ignore

#include "bpf_endian.h"
#include "common.h"

char __license[] SEC("license") = "Dual MIT/GPL";

#define KEY_NUM 0xdeadbeef
#define MAX_MAP_ENTRIES 1

struct addr_restrictions {
	__u32 saddr; // source ipv4 address
	unsigned char smac[6]; // source mac address
	__u8 enable_saddr; // enable source ip address restriction
	__u8 enable_smac; // enable source mac address restriction
};

struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, MAX_MAP_ENTRIES);
	__type(key, __u32);
	__type(value, struct addr_restrictions);
} addr_restrictions_map SEC(".maps");

SEC("xdp")
int xdp_addr_restrictions(struct xdp_md *ctx)
{
	void *data_end = (void *)(long)ctx->data_end;
	void *data = (void *)(long)ctx->data;

	// First, parse the ethernet header.
	struct ethhdr *eth = data;
	if ((void *)(eth + 1) > data_end) {
		return XDP_ABORTED;
	}

	int key = KEY_NUM;
	struct addr_restrictions *restrictions = bpf_map_lookup_elem(&addr_restrictions_map, &key);
	if (restrictions == NULL) {
		return XDP_ABORTED;
	}

	if (restrictions->enable_smac) {
		for (int i = 0; i < 6; i++) {
			if (eth->h_source[i] != restrictions->smac[i]) {
				// bpf_printk("MAC addresses: %x != %x\n", eth->h_source[i], restrictions->smac[i]);
				return XDP_DROP;
			}
		}
	}

	if (eth->h_proto != bpf_htons(ETH_P_IP)) {
		// The protocol is not IPv4, so we can't parse an IPv4 source address.
		return XDP_ABORTED;
	}

	// Then parse the IP header.
	struct iphdr *ip = (void *)(eth + 1);
	if ((void *)(ip + 1) > data_end) {
		return XDP_ABORTED;
	}

	if (restrictions->enable_saddr) {
		if (ip->saddr != restrictions->saddr) {
			// bpf_printk("source IP address: %x != %x\n", ip->saddr, restrictions->saddr);
			return XDP_DROP;
		}
	}

	return XDP_PASS;
}
