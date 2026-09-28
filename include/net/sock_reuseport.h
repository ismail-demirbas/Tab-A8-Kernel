/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _SOCK_REUSEPORT_H
#define _SOCK_REUSEPORT_H

#include <linux/filter.h>
#include <linux/skbuff.h>
#include <linux/types.h>
#include <linux/spinlock.h>
#include <net/sock.h>
#ifndef __GENKSYMS__
#include <net/ipv6.h>
#endif

extern spinlock_t reuseport_lock;

static inline bool inet_rcv_saddr_any(const struct sock *sk)
{
#if IS_ENABLED(CONFIG_IPV6)
	if (sk->sk_family == AF_INET6)
		return ipv6_addr_any(&sk->sk_v6_rcv_saddr);
#endif
	return !sk->sk_rcv_saddr;
}

struct sock_reuseport {
	struct rcu_head		rcu;

	u16			max_socks;	/* length of socks */
	u16			num_socks;	/* elements in socks */
#ifndef __GENKSYMS__
	/* The last synq overflow event timestamp of this
	 * reuse->socks[] group.
	 */
	unsigned int		synq_overflow_ts;
	/* ID stays the same even after the size of socks[] grows. */
	unsigned int		reuseport_id;
	bool			bind_inany;
#endif
	struct bpf_prog __rcu	*prog;		/* optional BPF sock selector */
	struct sock		*socks[0];	/* array of sock pointers */
};

extern int reuseport_alloc(struct sock *sk, bool bind_inany);
extern int reuseport_add_sock(struct sock *sk, struct sock *sk2,
			      bool bind_inany);
extern void reuseport_detach_sock(struct sock *sk);
extern struct sock *reuseport_select_sock(struct sock *sk,
					  u32 hash,
					  struct sk_buff *skb,
					  int hdr_len);
extern int reuseport_attach_prog(struct sock *sk, struct bpf_prog *prog);
int reuseport_get_id(struct sock_reuseport *reuse);

#endif  /* _SOCK_REUSEPORT_H */
