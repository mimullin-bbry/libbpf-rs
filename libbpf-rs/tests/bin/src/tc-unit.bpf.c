#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

//#include <linux/pkt_cls.h>
#define TC_ACT_UNSPEC	(-1)
#define TC_ACT_OK		0
#define TC_ACT_RECLASSIFY	1
#define TC_ACT_SHOT		2
#define TC_ACT_PIPE		3
#define TC_ACT_STOLEN		4
#define TC_ACT_QUEUED		5
#define TC_ACT_REPEAT		6
#define TC_ACT_REDIRECT		7
#define TC_ACT_TRAP		8

SEC("tc")
int handle_tc(struct __sk_buff *skb)
{
    return TC_ACT_UNSPEC;
}

