// SPDX-License-Identifier: GPL-2.0
/*
 * BPF_PROG_TYPE_SK_REUSEPORT support, backported from Linux 4.19
 * net/core/filter.c (tag ASB-2019-04-05_4.19) into a standalone file
 * so that net/core/filter.c (no-touch list) is not modified.
 *
 * ____bpf_skb_load_bytes() / ____bpf_skb_load_bytes_relative() are
 * local helpers derived from the existing bpf_skb_load_bytes() /
 * bpf_skb_load_bytes_relative() logic already present in filter.c,
 * since the ASB-2019-04-05_4.19 tag references but never defines
 * the upstream ____-prefixed helpers (confirmed: no definition
 * anywhere in that tree).
 */

#include <linux/filter.h>
#include <linux/bpf.h>
#include <linux/skbuff.h>
#include <net/sock_reuseport.h>

#ifdef CONFIG_INET

static __always_inline int
____bpf_skb_load_bytes(const struct sk_buff *skb, u32 offset,
		       void *to, u32 len)
{
	void *ptr;

	if (unlikely(offset > 0xffff))
		goto err_clear;

	ptr = skb_header_pointer(skb, offset, len, to);
	if (unlikely(!ptr))
		goto err_clear;
	if (ptr != to)
		memcpy(to, ptr, len);

	return 0;
err_clear:
	memset(to, 0, len);
	return -EFAULT;
}

static __always_inline int
____bpf_skb_load_bytes_relative(const struct sk_buff *skb, u32 offset,
				void *to, u32 len, u32 start_header)
{
	u8 *end = skb_tail_pointer(skb);
	u8 *net = skb_network_header(skb);
	u8 *mac = skb_mac_header(skb);
	u8 *ptr;

	if (unlikely(offset > 0xffff || len > (end - mac)))
		goto err_clear;

	switch (start_header) {
	case BPF_HDR_START_MAC:
		ptr = mac + offset;
		break;
	case BPF_HDR_START_NET:
		ptr = net + offset;
		break;
	default:
		goto err_clear;
	}

	if (likely(ptr >= mac && ptr + len <= end)) {
		memcpy(to, ptr, len);
		return 0;
	}

err_clear:
	memset(to, 0, len);
	return -EFAULT;
}

static void bpf_init_reuseport_kern(struct sk_reuseport_kern *reuse_kern,
				    struct sock_reuseport *reuse,
				    struct sock *sk, struct sk_buff *skb,
				    u32 hash)
{
	reuse_kern->skb = skb;
	reuse_kern->sk = sk;
	reuse_kern->selected_sk = NULL;
	reuse_kern->data_end = skb->data + skb_headlen(skb);
	reuse_kern->hash = hash;
	reuse_kern->reuseport_id = reuse->reuseport_id;
	reuse_kern->bind_inany = reuse->bind_inany;
}

struct sock *bpf_run_sk_reuseport(struct sock_reuseport *reuse, struct sock *sk,
				  struct bpf_prog *prog, struct sk_buff *skb,
				  u32 hash)
{
	struct sk_reuseport_kern reuse_kern;
	enum sk_action action;

	bpf_init_reuseport_kern(&reuse_kern, reuse, sk, skb, hash);
	action = BPF_PROG_RUN(prog, &reuse_kern);

	if (action == SK_PASS)
		return reuse_kern.selected_sk;
	else
		return ERR_PTR(-ECONNREFUSED);
}

BPF_CALL_4(sk_select_reuseport, struct sk_reuseport_kern *, reuse_kern,
	   struct bpf_map *, map, void *, key, u32, flags)
{
	struct sock_reuseport *reuse;
	struct sock *selected_sk;

	selected_sk = map->ops->map_lookup_elem(map, key);
	if (!selected_sk)
		return -ENOENT;

	reuse = rcu_dereference(selected_sk->sk_reuseport_cb);
	if (!reuse)
		return -ENOENT;

	if (unlikely(reuse->reuseport_id != reuse_kern->reuseport_id)) {
		struct sock *sk;

		if (unlikely(!reuse_kern->reuseport_id))
			return -ENOENT;

		sk = reuse_kern->sk;
		if (sk->sk_protocol != selected_sk->sk_protocol)
			return -EPROTOTYPE;
		else if (sk->sk_family != selected_sk->sk_family)
			return -EAFNOSUPPORT;

		return -EBADFD;
	}

	reuse_kern->selected_sk = selected_sk;

	return 0;
}

static const struct bpf_func_proto sk_select_reuseport_proto = {
	.func           = sk_select_reuseport,
	.gpl_only       = false,
	.ret_type       = RET_INTEGER,
	.arg1_type	= ARG_PTR_TO_CTX,
	.arg2_type      = ARG_CONST_MAP_PTR,
	.arg3_type      = ARG_PTR_TO_MAP_KEY,
	.arg4_type	= ARG_ANYTHING,
};

BPF_CALL_4(sk_reuseport_load_bytes,
	   const struct sk_reuseport_kern *, reuse_kern, u32, offset,
	   void *, to, u32, len)
{
	return ____bpf_skb_load_bytes(reuse_kern->skb, offset, to, len);
}

static const struct bpf_func_proto sk_reuseport_load_bytes_proto = {
	.func		= sk_reuseport_load_bytes,
	.gpl_only	= false,
	.ret_type	= RET_INTEGER,
	.arg1_type	= ARG_PTR_TO_CTX,
	.arg2_type	= ARG_ANYTHING,
	.arg3_type	= ARG_PTR_TO_UNINIT_MEM,
	.arg4_type	= ARG_CONST_SIZE,
};

BPF_CALL_5(sk_reuseport_load_bytes_relative,
	   const struct sk_reuseport_kern *, reuse_kern, u32, offset,
	   void *, to, u32, len, u32, start_header)
{
	return ____bpf_skb_load_bytes_relative(reuse_kern->skb, offset, to,
					       len, start_header);
}

static const struct bpf_func_proto sk_reuseport_load_bytes_relative_proto = {
	.func		= sk_reuseport_load_bytes_relative,
	.gpl_only	= false,
	.ret_type	= RET_INTEGER,
	.arg1_type	= ARG_PTR_TO_CTX,
	.arg2_type	= ARG_ANYTHING,
	.arg3_type	= ARG_PTR_TO_UNINIT_MEM,
	.arg4_type	= ARG_CONST_SIZE,
	.arg5_type	= ARG_ANYTHING,
};

static const struct bpf_func_proto *
sk_reuseport_func_proto(enum bpf_func_id func_id,
			const struct bpf_prog *prog)
{
	switch (func_id) {
	case BPF_FUNC_sk_select_reuseport:
		return &sk_select_reuseport_proto;
	case BPF_FUNC_skb_load_bytes:
		return &sk_reuseport_load_bytes_proto;
	case BPF_FUNC_skb_load_bytes_relative:
		return &sk_reuseport_load_bytes_relative_proto;
	default:
		return bpf_base_func_proto(func_id);
	}
}

static bool
sk_reuseport_is_valid_access(int off, int size,
			     enum bpf_access_type type,
			     const struct bpf_prog *prog,
			     struct bpf_insn_access_aux *info)
{
	const u32 size_default = sizeof(__u32);

	if (off < 0 || off >= sizeof(struct sk_reuseport_md) ||
	    off % size || type != BPF_READ)
		return false;

	switch (off) {
	case offsetof(struct sk_reuseport_md, data):
		info->reg_type = PTR_TO_PACKET;
		return size == sizeof(__u64);

	case offsetof(struct sk_reuseport_md, data_end):
		info->reg_type = PTR_TO_PACKET_END;
		return size == sizeof(__u64);

	case offsetof(struct sk_reuseport_md, hash):
		return size == size_default;

	/* Fields that allow narrowing */
	case bpf_ctx_range(struct sk_reuseport_md, eth_protocol):
		if (size < FIELD_SIZEOF(struct sk_buff, protocol))
			return false;
		/* fall through */
	case bpf_ctx_range(struct sk_reuseport_md, ip_protocol):
	case bpf_ctx_range(struct sk_reuseport_md, bind_inany):
	case bpf_ctx_range(struct sk_reuseport_md, len):
		bpf_ctx_record_field_size(info, size_default);
		return bpf_ctx_narrow_access_ok(off, size, size_default);

	default:
		return false;
	}
}

#define SK_REUSEPORT_LOAD_FIELD(F) ({					\
	*insn++ = BPF_LDX_MEM(BPF_FIELD_SIZEOF(struct sk_reuseport_kern, F), \
			      si->dst_reg, si->src_reg,			\
			      bpf_target_off(struct sk_reuseport_kern, F, \
					     FIELD_SIZEOF(struct sk_reuseport_kern, F), \
					     target_size));		\
	})

#define __LOCAL_SOCK_ADDR_LOAD_NESTED_FIELD_SIZE_OFF(S, NS, F, NF, SIZE, OFF) \
	do {								       \
		*insn++ = BPF_LDX_MEM(BPF_FIELD_SIZEOF(S, F), si->dst_reg,     \
				      si->src_reg, offsetof(S, F));	       \
		*insn++ = BPF_LDX_MEM(					       \
			SIZE, si->dst_reg, si->dst_reg,			       \
			bpf_target_off(NS, NF, FIELD_SIZEOF(NS, NF),	       \
				       target_size)			       \
				+ OFF);					       \
	} while (0)

#define __LOCAL_SOCK_ADDR_LOAD_NESTED_FIELD(S, NS, F, NF)		       \
	__LOCAL_SOCK_ADDR_LOAD_NESTED_FIELD_SIZE_OFF(S, NS, F, NF,	       \
					     BPF_FIELD_SIZEOF(NS, NF), 0)

#define SK_REUSEPORT_LOAD_SKB_FIELD(SKB_FIELD)				\
	__LOCAL_SOCK_ADDR_LOAD_NESTED_FIELD(struct sk_reuseport_kern,	\
				    struct sk_buff,			\
				    skb,				\
				    SKB_FIELD)

#define SK_REUSEPORT_LOAD_SK_FIELD_SIZE_OFF(SK_FIELD, BPF_SIZE, EXTRA_OFF) \
	__LOCAL_SOCK_ADDR_LOAD_NESTED_FIELD_SIZE_OFF(struct sk_reuseport_kern,	\
					     struct sock,		\
					     sk,			\
					     SK_FIELD, BPF_SIZE, EXTRA_OFF)

static u32 sk_reuseport_convert_ctx_access(enum bpf_access_type type,
					   const struct bpf_insn *si,
					   struct bpf_insn *insn_buf,
					   struct bpf_prog *prog,
					   u32 *target_size)
{
	struct bpf_insn *insn = insn_buf;

	switch (si->off) {
	case offsetof(struct sk_reuseport_md, data):
		SK_REUSEPORT_LOAD_SKB_FIELD(data);
		break;

	case offsetof(struct sk_reuseport_md, len):
		SK_REUSEPORT_LOAD_SKB_FIELD(len);
		break;

	case offsetof(struct sk_reuseport_md, eth_protocol):
		SK_REUSEPORT_LOAD_SKB_FIELD(protocol);
		break;

	case offsetof(struct sk_reuseport_md, ip_protocol):
		BUILD_BUG_ON(HWEIGHT32(SK_FL_PROTO_MASK) != BITS_PER_BYTE);
		SK_REUSEPORT_LOAD_SK_FIELD_SIZE_OFF(__sk_flags_offset,
						    BPF_W, 0);
		*insn++ = BPF_ALU32_IMM(BPF_AND, si->dst_reg, SK_FL_PROTO_MASK);
		*insn++ = BPF_ALU32_IMM(BPF_RSH, si->dst_reg,
					SK_FL_PROTO_SHIFT);
		*target_size = 1;
		break;

	case offsetof(struct sk_reuseport_md, data_end):
		SK_REUSEPORT_LOAD_FIELD(data_end);
		break;

	case offsetof(struct sk_reuseport_md, hash):
		SK_REUSEPORT_LOAD_FIELD(hash);
		break;

	case offsetof(struct sk_reuseport_md, bind_inany):
		SK_REUSEPORT_LOAD_FIELD(bind_inany);
		break;
	}

	return insn - insn_buf;
}

const struct bpf_verifier_ops sk_reuseport_verifier_ops = {
	.get_func_proto		= sk_reuseport_func_proto,
	.is_valid_access	= sk_reuseport_is_valid_access,
	.convert_ctx_access	= sk_reuseport_convert_ctx_access,
};

const struct bpf_prog_ops sk_reuseport_prog_ops = {
};

#endif /* CONFIG_INET */
