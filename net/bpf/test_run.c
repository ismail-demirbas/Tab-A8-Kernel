/* Copyright (c) 2017 Facebook
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of version 2 of the GNU General Public
 * License as published by the Free Software Foundation.
 */
#include <linux/bpf.h>
#include <net/sch_generic.h>
#include <linux/slab.h>
#include <linux/vmalloc.h>
#include <linux/etherdevice.h>
#include <linux/filter.h>
#include <linux/sched/signal.h>
#include <net/flow_dissector.h>
#include <net/sock.h>
#include <linux/sock_diag.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#define CREATE_TRACE_POINTS
#include <trace/events/bpf_test_run.h>

static __always_inline u32 bpf_test_run_one(struct bpf_prog *prog, void *ctx)
{
	u32 ret;

	preempt_disable();
	rcu_read_lock();
	ret = BPF_PROG_RUN(prog, ctx);
	rcu_read_unlock();
	preempt_enable();

	return ret;
}

static u32 bpf_test_run(struct bpf_prog *prog, void *ctx, u32 repeat, u32 *time)
{
	u64 time_start, time_spent = 0;
	u32 ret = 0, i;

	if (!repeat)
		repeat = 1;
	time_start = ktime_get_ns();
	for (i = 0; i < repeat; i++) {
		ret = bpf_test_run_one(prog, ctx);
		if (need_resched()) {
			if (signal_pending(current))
				break;
			time_spent += ktime_get_ns() - time_start;
			cond_resched();
			time_start = ktime_get_ns();
		}
	}
	time_spent += ktime_get_ns() - time_start;
	do_div(time_spent, repeat);
	*time = time_spent > U32_MAX ? U32_MAX : (u32)time_spent;

	return ret;
}

static int bpf_test_finish(const union bpf_attr *kattr,
			   union bpf_attr __user *uattr, const void *data,
			   u32 size, u32 retval, u32 duration)
{
	void __user *data_out = u64_to_user_ptr(kattr->test.data_out);
	int err = -EFAULT;
	u32 copy_size = size;

	/* Clamp copy if the user has provided a size hint, but copy the full
	 * buffer if not to retain old behaviour.
	 */
	if (kattr->test.data_size_out &&
	    copy_size > kattr->test.data_size_out) {
		copy_size = kattr->test.data_size_out;
		err = -ENOSPC;
	}

	if (data_out && copy_to_user(data_out, data, copy_size))
		goto out;
	if (copy_to_user(&uattr->test.data_size_out, &size, sizeof(size)))
		goto out;
	if (copy_to_user(&uattr->test.retval, &retval, sizeof(retval)))
		goto out;
	if (copy_to_user(&uattr->test.duration, &duration, sizeof(duration)))
		goto out;
	if (err != -ENOSPC)
		err = 0;
out:
	trace_bpf_test_finish(&err);
	return err;
}

static void *bpf_test_init(const union bpf_attr *kattr, u32 size,
			   u32 headroom, u32 tailroom)
{
	void __user *data_in = u64_to_user_ptr(kattr->test.data_in);
	u32 user_size = kattr->test.data_size_in;
	void *data;

	if (size < ETH_HLEN || size > PAGE_SIZE - headroom - tailroom)
		return ERR_PTR(-EINVAL);

	if (user_size > size)
		return ERR_PTR(-EMSGSIZE);

	size = SKB_DATA_ALIGN(size);
	data = kzalloc(size + headroom + tailroom, GFP_USER);
	if (!data)
		return ERR_PTR(-ENOMEM);

	if (copy_from_user(data + headroom, data_in, user_size)) {
		kfree(data);
		return ERR_PTR(-EFAULT);
	}

	return data;
}


int bpf_prog_test_run_xdp(struct bpf_prog *prog, const union bpf_attr *kattr,
			  union bpf_attr __user *uattr)
{
	u32 size = kattr->test.data_size_in;
	u32 repeat = kattr->test.repeat;
	struct xdp_buff xdp = {};
	u32 retval, duration;
	void *data;
	int ret;

	if (kattr->test.ctx_in || kattr->test.ctx_out ||
	    kattr->test.flags || kattr->test.cpu)
		return -EINVAL;

	data = bpf_test_init(kattr, size, XDP_PACKET_HEADROOM + NET_IP_ALIGN, 0);
	if (IS_ERR(data))
		return PTR_ERR(data);

	xdp.data_hard_start = data;
	xdp.data = data + XDP_PACKET_HEADROOM + NET_IP_ALIGN;
	xdp.data_end = xdp.data + size;

	retval = bpf_test_run(prog, &xdp, repeat, &duration);
	if (xdp.data != data + XDP_PACKET_HEADROOM + NET_IP_ALIGN)
		size = xdp.data_end - xdp.data;
	ret = bpf_test_finish(kattr, uattr, xdp.data, size, retval, duration);
	kfree(data);
	return ret;
}

/**
 * range_is_zero - test whether buffer is initialized
 * @buf: buffer to check
 * @from: check from this position
 * @to: check up until (excluding) this position
 *
 * This function returns true if the there is a non-zero byte
 * in the buf in the range [from,to).
 */
static inline bool range_is_zero(void *buf, size_t from, size_t to)
{
	return !memchr_inv((u8 *)buf + from, 0, to - from);
}

static int verify_user_bpf_flow_keys(struct bpf_flow_keys *ctx)
{
	/* make sure the fields we don't use are zeroed */
	if (!range_is_zero(ctx, 0, offsetof(struct bpf_flow_keys, flags)))
		return -EINVAL;

	/* flags is allowed */

	if (!range_is_zero(ctx, offsetofend(struct bpf_flow_keys, flags),
			   sizeof(struct bpf_flow_keys)))
		return -EINVAL;

	return 0;
}

static void *bpf_ctx_init(const union bpf_attr *kattr, u32 max_size)
{
	void __user *data_in = u64_to_user_ptr(kattr->test.ctx_in);
	void __user *data_out = u64_to_user_ptr(kattr->test.ctx_out);
	u32 size = kattr->test.ctx_size_in;
	void *data;
	int err;

	if (!data_in && !data_out)
		return NULL;

	data = kzalloc(max_size, GFP_USER);
	if (!data)
		return ERR_PTR(-ENOMEM);

	if (data_in) {
		err = bpf_check_uarg_tail_zero(data_in, max_size, size);
		if (err) {
			kfree(data);
			return ERR_PTR(err);
		}

		size = min_t(u32, max_size, size);
		if (copy_from_user(data, data_in, size)) {
			kfree(data);
			return ERR_PTR(-EFAULT);
		}
	}
	return data;
}

static int bpf_ctx_finish(const union bpf_attr *kattr,
			  union bpf_attr __user *uattr, const void *data,
			  u32 size)
{
	void __user *data_out = u64_to_user_ptr(kattr->test.ctx_out);
	int err = -EFAULT;
	u32 copy_size = size;

	if (!data || !data_out)
		return 0;

	if (copy_size > kattr->test.ctx_size_out) {
		copy_size = kattr->test.ctx_size_out;
		err = -ENOSPC;
	}

	if (copy_to_user(data_out, data, copy_size))
		goto out;
	if (copy_to_user(&uattr->test.ctx_size_out, &size, sizeof(size)))
		goto out;
	if (err != -ENOSPC)
		err = 0;
out:
	return err;
}

static struct proto bpf_dummy_proto = {
	.name   = "bpf_dummy",
	.owner  = THIS_MODULE,
	.obj_size = sizeof(struct sock),
};

static int convert___skb_to_skb(struct sk_buff *skb, struct __sk_buff *__skb)
{
	struct qdisc_skb_cb *cb = (struct qdisc_skb_cb *)skb->cb;

	if (!__skb)
		return 0;

	/* make sure the fields we don't use are zeroed */
	if (!range_is_zero(__skb, 0, offsetof(struct __sk_buff, mark)))
		return -EINVAL;

	/* mark is allowed */

	if (!range_is_zero(__skb, offsetofend(struct __sk_buff, mark),
			   offsetof(struct __sk_buff, priority)))
		return -EINVAL;

	/* priority is allowed */

	if (!range_is_zero(__skb, offsetofend(struct __sk_buff, priority),
			   offsetof(struct __sk_buff, ifindex)))
		return -EINVAL;

	/* ifindex is allowed */

	if (!range_is_zero(__skb, offsetofend(struct __sk_buff, ifindex),
			   offsetof(struct __sk_buff, cb)))
		return -EINVAL;

	/* cb is allowed */

	if (!range_is_zero(__skb, offsetofend(struct __sk_buff, cb),
			   offsetof(struct __sk_buff, tstamp)))
		return -EINVAL;

	/* tstamp is allowed */
	/* wire_len is allowed */
	/* gso_segs is allowed */

	if (!range_is_zero(__skb, offsetofend(struct __sk_buff, gso_segs),
			   offsetof(struct __sk_buff, gso_size)))
		return -EINVAL;

	/* gso_size is allowed */

	if (!range_is_zero(__skb, offsetofend(struct __sk_buff, gso_size),
			   sizeof(struct __sk_buff)))
		return -EINVAL;

	skb->mark = __skb->mark;
	skb->priority = __skb->priority;
	skb->tstamp = __skb->tstamp;
	memcpy(&cb->data, __skb->cb, QDISC_CB_PRIV_LEN);

	if (__skb->wire_len == 0) {
		cb->pkt_len = skb->len;
	} else {
		if (__skb->wire_len < skb->len ||
		    __skb->wire_len > GSO_MAX_SIZE)
			return -EINVAL;
		cb->pkt_len = __skb->wire_len;
	}

	if (__skb->gso_segs > GSO_MAX_SEGS)
		return -EINVAL;
	skb_shinfo(skb)->gso_segs = __skb->gso_segs;
	skb_shinfo(skb)->gso_size = __skb->gso_size;

	return 0;
}

static void convert_skb_to___skb(struct sk_buff *skb, struct __sk_buff *__skb)
{
	struct qdisc_skb_cb *cb = (struct qdisc_skb_cb *)skb->cb;

	if (!__skb)
		return;

	__skb->mark = skb->mark;
	__skb->priority = skb->priority;
	__skb->ifindex = skb->dev->ifindex;
	__skb->tstamp = skb->tstamp;
	memcpy(__skb->cb, &cb->data, QDISC_CB_PRIV_LEN);
	__skb->wire_len = cb->pkt_len;
	__skb->gso_segs = skb_shinfo(skb)->gso_segs;
}

int bpf_prog_test_run_skb(struct bpf_prog *prog, const union bpf_attr *kattr,
			  union bpf_attr __user *uattr)
{
	bool is_l2 = false, is_direct_pkt_access = false;
	struct net *net = current->nsproxy->net_ns;
	struct net_device *dev = net->loopback_dev;
	u32 size = kattr->test.data_size_in;
	u32 repeat = kattr->test.repeat;
	struct __sk_buff *ctx = NULL;
	u32 retval, duration;
	int hh_len = ETH_HLEN;
	struct sk_buff *skb;
	struct sock *sk;
	void *data;
	int ret;

	if (kattr->test.flags || kattr->test.cpu)
		return -EINVAL;

	data = bpf_test_init(kattr, size, NET_SKB_PAD + NET_IP_ALIGN,
			     SKB_DATA_ALIGN(sizeof(struct skb_shared_info)));
	if (IS_ERR(data))
		return PTR_ERR(data);

	ctx = bpf_ctx_init(kattr, sizeof(struct __sk_buff));
	if (IS_ERR(ctx)) {
		kfree(data);
		return PTR_ERR(ctx);
	}

	switch (prog->type) {
	case BPF_PROG_TYPE_SCHED_CLS:
	case BPF_PROG_TYPE_SCHED_ACT:
		is_l2 = true;
		/* fall through */
	case BPF_PROG_TYPE_LWT_IN:
	case BPF_PROG_TYPE_LWT_OUT:
	case BPF_PROG_TYPE_LWT_XMIT:
		is_direct_pkt_access = true;
		break;
	default:
		break;
	}

	sk = sk_alloc(net, AF_UNSPEC, GFP_USER, &bpf_dummy_proto, 1);
	if (!sk) {
		kfree(data);
		kfree(ctx);
		return -ENOMEM;
	}
	sock_init_data(NULL, sk);

	skb = build_skb(data, 0);
	if (!skb) {
		kfree(data);
		kfree(ctx);
		sk_free(sk);
		return -ENOMEM;
	}
	skb->sk = sk;

	skb_reserve(skb, NET_SKB_PAD + NET_IP_ALIGN);
	__skb_put(skb, size);
	if (ctx && ctx->ifindex > 1) {
		dev = dev_get_by_index(net, ctx->ifindex);
		if (!dev) {
			ret = -ENODEV;
			goto out;
		}
	}
	skb->protocol = eth_type_trans(skb, dev);
	skb_reset_network_header(skb);

	switch (skb->protocol) {
	case htons(ETH_P_IP):
		sk->sk_family = AF_INET;
		if (sizeof(struct iphdr) <= skb_headlen(skb)) {
			sk->sk_rcv_saddr = ip_hdr(skb)->saddr;
			sk->sk_daddr = ip_hdr(skb)->daddr;
		}
		break;
#if IS_ENABLED(CONFIG_IPV6)
	case htons(ETH_P_IPV6):
		sk->sk_family = AF_INET6;
		if (sizeof(struct ipv6hdr) <= skb_headlen(skb)) {
			sk->sk_v6_rcv_saddr = ipv6_hdr(skb)->saddr;
			sk->sk_v6_daddr = ipv6_hdr(skb)->daddr;
		}
		break;
#endif
	default:
		break;
	}

	if (is_l2)
		__skb_push(skb, hh_len);
	if (is_direct_pkt_access)
		bpf_compute_data_end(skb);
	ret = convert___skb_to_skb(skb, ctx);
	if (ret)
		goto out;
	retval = bpf_test_run(prog, skb, repeat, &duration);
	if (!is_l2) {
		if (skb_headroom(skb) < hh_len) {
			int nhead = HH_DATA_ALIGN(hh_len - skb_headroom(skb));

			if (pskb_expand_head(skb, nhead, 0, GFP_USER)) {
				ret = -ENOMEM;
				goto out;
			}
		}
		memset(__skb_push(skb, hh_len), 0, hh_len);
	}
	convert_skb_to___skb(skb, ctx);

	size = skb->len;
	/* bpf program can never convert linear skb to non-linear */
	if (WARN_ON_ONCE(skb_is_nonlinear(skb)))
		size = skb_headlen(skb);
	ret = bpf_test_finish(kattr, uattr, skb->data, size, retval, duration);
	if (!ret)
		ret = bpf_ctx_finish(kattr, uattr, ctx,
				     sizeof(struct __sk_buff));
out:
	if (dev && dev != net->loopback_dev)
		dev_put(dev);
	kfree_skb(skb);
	sk_free(sk);
	kfree(ctx);
	return ret;
}

int bpf_prog_test_run_sk_lookup(struct bpf_prog *prog, const union bpf_attr *kattr,
				union bpf_attr __user *uattr)
{
	struct bpf_prog_array *progs = NULL;
	struct bpf_sk_lookup_kern ctx = {};
	u32 repeat = kattr->test.repeat;
	struct bpf_sk_lookup *user_ctx;
	u64 time_start, time_spent = 0;
	u32 retval = 0, duration, i;
	int ret = -EINVAL;

	if (prog->type != BPF_PROG_TYPE_SK_LOOKUP)
		return -EINVAL;

	if (kattr->test.flags || kattr->test.cpu)
		return -EINVAL;

	if (kattr->test.data_in || kattr->test.data_size_in || kattr->test.data_out ||
	    kattr->test.data_size_out)
		return -EINVAL;

	if (repeat == 0)
		repeat = 1;

	user_ctx = bpf_ctx_init(kattr, sizeof(*user_ctx));
	if (IS_ERR(user_ctx))
		return PTR_ERR(user_ctx);

	if (user_ctx == NULL)
		return -EINVAL;

	if (user_ctx->sk)
		goto out;

	if (range_is_zero(user_ctx, offsetofend(typeof(*user_ctx), local_port),
			  sizeof(*user_ctx)) == false)
		goto out;

	if (user_ctx->local_port > U16_MAX || user_ctx->remote_port > U16_MAX) {
		ret = -ERANGE;
		goto out;
	}

	ctx.family = (u16)user_ctx->family;
	ctx.protocol = (u16)user_ctx->protocol;
	ctx.dport = (u16)user_ctx->local_port;
	ctx.sport = (__force __be16)user_ctx->remote_port;

	switch (ctx.family) {
	case AF_INET:
		ctx.v4.daddr = (__force __be32)user_ctx->local_ip4;
		ctx.v4.saddr = (__force __be32)user_ctx->remote_ip4;
		break;

#if IS_ENABLED(CONFIG_IPV6)
	case AF_INET6:
		ctx.v6.daddr = (struct in6_addr *)user_ctx->local_ip6;
		ctx.v6.saddr = (struct in6_addr *)user_ctx->remote_ip6;
		break;
#endif

	default:
		ret = -EAFNOSUPPORT;
		goto out;
	}

	progs = bpf_prog_array_alloc(1, GFP_KERNEL);
	if (progs == NULL) {
		ret = -ENOMEM;
		goto out;
	}

	progs->items[0].prog = prog;

	time_start = ktime_get_ns();
	for (i = 0; i < repeat; i++) {
		ctx.selected_sk = NULL;
		retval = BPF_PROG_SK_LOOKUP_RUN_ARRAY(progs, ctx, BPF_PROG_RUN);
		if (need_resched()) {
			if (signal_pending(current))
				break;
			time_spent += ktime_get_ns() - time_start;
			cond_resched();
			time_start = ktime_get_ns();
		}
	}
	time_spent += ktime_get_ns() - time_start;
	do_div(time_spent, repeat);
	duration = time_spent > U32_MAX ? U32_MAX : (u32)time_spent;

	user_ctx->cookie = 0;
	if (ctx.selected_sk) {
		if (ctx.selected_sk->sk_reuseport && ctx.no_reuseport == false) {
			ret = -EOPNOTSUPP;
			goto out;
		}

		user_ctx->cookie = sock_gen_cookie(ctx.selected_sk);
	}

	ret = bpf_test_finish(kattr, uattr, NULL, 0, retval, duration);
	if (ret == 0)
		ret = bpf_ctx_finish(kattr, uattr, user_ctx, sizeof(*user_ctx));

out:
	bpf_prog_array_free(progs);
	kfree(user_ctx);
	return ret;
}

int bpf_prog_test_run_flow_dissector(struct bpf_prog *prog,
				     const union bpf_attr *kattr,
				     union bpf_attr __user *uattr)
{
	u32 size = kattr->test.data_size_in;
	struct bpf_flow_dissector ctx = {};
	u32 repeat = kattr->test.repeat;
	struct bpf_flow_keys *user_ctx;
	struct bpf_flow_keys flow_keys;
	unsigned int flags = 0;
	u64 time_start, time_spent = 0;
	const struct ethhdr *eth;
	u32 retval = 0, duration, i;
	void *data;
	int ret;

	if (prog->type != BPF_PROG_TYPE_FLOW_DISSECTOR)
		return -EINVAL;

	if (kattr->test.flags || kattr->test.cpu)
		return -EINVAL;

	if (size < ETH_HLEN)
		return -EINVAL;

	data = bpf_test_init(kattr, size, 0, 0);
	if (IS_ERR(data))
		return PTR_ERR(data);

	eth = (struct ethhdr *)data;

	if (!repeat)
		repeat = 1;

	user_ctx = bpf_ctx_init(kattr, sizeof(struct bpf_flow_keys));
	if (IS_ERR(user_ctx)) {
		kfree(data);
		return PTR_ERR(user_ctx);
	}
	if (user_ctx) {
		ret = verify_user_bpf_flow_keys(user_ctx);
		if (ret)
			goto out;
		/* SAPMA: uapi BPF_FLOW_DISSECTOR_F_* -> 4.14 FLOW_DISSECTOR_F_*
		 * (bit duzenleri farkli; bpf_flow_dissect kernel bayragi bekler)
		 */
		if (user_ctx->flags & BPF_FLOW_DISSECTOR_F_PARSE_1ST_FRAG)
			flags |= FLOW_DISSECTOR_F_PARSE_1ST_FRAG;
		if (user_ctx->flags & BPF_FLOW_DISSECTOR_F_STOP_AT_FLOW_LABEL)
			flags |= FLOW_DISSECTOR_F_STOP_AT_FLOW_LABEL;
		if (user_ctx->flags & BPF_FLOW_DISSECTOR_F_STOP_AT_ENCAP)
			flags |= FLOW_DISSECTOR_F_STOP_AT_ENCAP;
	}

	ctx.flow_keys = &flow_keys;
	ctx.data = data;
	ctx.data_end = (__u8 *)data + size;

	time_start = ktime_get_ns();
	for (i = 0; i < repeat; i++) {
		rcu_read_lock();
		retval = bpf_flow_dissect(prog, &ctx, eth->h_proto, ETH_HLEN,
					  size, flags);
		rcu_read_unlock();
		if (need_resched()) {
			if (signal_pending(current))
				break;
			time_spent += ktime_get_ns() - time_start;
			cond_resched();
			time_start = ktime_get_ns();
		}
	}
	time_spent += ktime_get_ns() - time_start;
	do_div(time_spent, repeat);
	duration = time_spent > U32_MAX ? U32_MAX : (u32)time_spent;

	ret = bpf_test_finish(kattr, uattr, &flow_keys, sizeof(flow_keys),
			      retval, duration);
	if (!ret)
		ret = bpf_ctx_finish(kattr, uattr, user_ctx,
				     sizeof(struct bpf_flow_keys));

out:
	kfree(user_ctx);
	kfree(data);
	return ret;
}
