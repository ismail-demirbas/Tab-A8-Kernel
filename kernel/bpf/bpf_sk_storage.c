// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2019 Facebook  */
#include <linux/rculist.h>
#include <linux/list.h>
#include <linux/hash.h>
#include <linux/types.h>
#include <linux/spinlock.h>
#include <linux/bpf.h>
#include <linux/bpf_local_storage.h>
#include <linux/bpf_sk_storage.h>
#include <net/sock.h>
#include <uapi/linux/btf.h>

DEFINE_BPF_STORAGE_CACHE(sk_cache);

static struct bpf_local_storage_data *
sk_storage_lookup(struct sock *sk, struct bpf_map *map, bool cacheit_lockit)
{
	struct bpf_local_storage *sk_storage;
	struct bpf_local_storage_map *smap;

	sk_storage = rcu_dereference(sk->sk_bpf_storage);
	if (!sk_storage)
		return NULL;

	smap = (struct bpf_local_storage_map *)map;
	return bpf_local_storage_lookup(sk_storage, smap, cacheit_lockit);
}

static int sk_storage_delete(struct sock *sk, struct bpf_map *map)
{
	struct bpf_local_storage_data *sdata;

	sdata = sk_storage_lookup(sk, map, false);
	if (!sdata)
		return -ENOENT;

	bpf_selem_unlink(SELEM(sdata));

	return 0;
}

void bpf_sk_storage_free(struct sock *sk)
{
	struct bpf_local_storage_elem *selem;
	struct bpf_local_storage *sk_storage;
	bool free_sk_storage = false;
	struct hlist_node *n;

	rcu_read_lock();
	sk_storage = rcu_dereference(sk->sk_bpf_storage);
	if (!sk_storage) {
		rcu_read_unlock();
		return;
	}

	raw_spin_lock_bh(&sk_storage->lock);
	hlist_for_each_entry_safe(selem, n, &sk_storage->list, snode) {
		bpf_selem_unlink_map(selem);
		free_sk_storage = bpf_selem_unlink_storage_nolock(sk_storage,
								  selem, true);
	}
	raw_spin_unlock_bh(&sk_storage->lock);
	rcu_read_unlock();

	if (free_sk_storage)
		kfree_rcu(sk_storage, rcu);
}

static void sk_storage_map_free(struct bpf_map *map)
{
	struct bpf_local_storage_map *smap;

	smap = (struct bpf_local_storage_map *)map;
	bpf_local_storage_cache_idx_free(&sk_cache, smap->cache_idx);
	bpf_local_storage_map_free(smap);
}

static struct bpf_map *sk_storage_map_alloc(union bpf_attr *attr)
{
	struct bpf_local_storage_map *smap;

	smap = bpf_local_storage_map_alloc(attr);
	if (IS_ERR(smap))
		return ERR_CAST(smap);

	smap->cache_idx = bpf_local_storage_cache_idx_get(&sk_cache);
	return &smap->map;
}

static int notsupp_get_next_key(struct bpf_map *map, void *key,
				void *next_key)
{
	return -ENOTSUPP;
}

static void *bpf_fd_sk_storage_lookup_elem(struct bpf_map *map, void *key)
{
	struct bpf_local_storage_data *sdata;
	struct socket *sock;
	int fd, err;

	fd = *(int *)key;
	sock = sockfd_lookup(fd, &err);
	if (sock) {
		sdata = sk_storage_lookup(sock->sk, map, true);
		sockfd_put(sock);
		return sdata ? sdata->data : NULL;
	}

	return ERR_PTR(err);
}

static int bpf_fd_sk_storage_update_elem(struct bpf_map *map, void *key,
					 void *value, u64 map_flags)
{
	struct bpf_local_storage_data *sdata;
	struct socket *sock;
	int fd, err;

	fd = *(int *)key;
	sock = sockfd_lookup(fd, &err);
	if (sock) {
		sdata = bpf_local_storage_update(
			sock->sk, (struct bpf_local_storage_map *)map, value,
			map_flags);
		sockfd_put(sock);
		return PTR_ERR_OR_ZERO(sdata);
	}

	return err;
}

static int bpf_fd_sk_storage_delete_elem(struct bpf_map *map, void *key)
{
	struct socket *sock;
	int fd, err;

	fd = *(int *)key;
	sock = sockfd_lookup(fd, &err);
	if (sock) {
		err = sk_storage_delete(sock->sk, map);
		sockfd_put(sock);
		return err;
	}

	return err;
}

BPF_CALL_4(bpf_sk_storage_get, struct bpf_map *, map, struct sock *, sk,
	   void *, value, u64, flags)
{
	struct bpf_local_storage_data *sdata;

	if (!sk || !sk_fullsock(sk) || flags > BPF_SK_STORAGE_GET_F_CREATE)
		return (unsigned long)NULL;

	sdata = sk_storage_lookup(sk, map, true);
	if (sdata)
		return (unsigned long)sdata->data;

	if (flags == BPF_SK_STORAGE_GET_F_CREATE &&
	    refcount_inc_not_zero(&sk->sk_refcnt)) {
		sdata = bpf_local_storage_update(
			sk, (struct bpf_local_storage_map *)map, value,
			BPF_NOEXIST);
		sock_put(sk);
		return IS_ERR(sdata) ?
			(unsigned long)NULL : (unsigned long)sdata->data;
	}

	return (unsigned long)NULL;
}

BPF_CALL_2(bpf_sk_storage_delete, struct bpf_map *, map, struct sock *, sk)
{
	if (!sk || !sk_fullsock(sk))
		return -EINVAL;

	if (refcount_inc_not_zero(&sk->sk_refcnt)) {
		int err;

		err = sk_storage_delete(sk, map);
		sock_put(sk);
		return err;
	}

	return -ENOENT;
}

static int sk_storage_charge(struct bpf_local_storage_map *smap,
			     void *owner, u32 size)
{
	int optmem_max = READ_ONCE(sysctl_optmem_max);
	struct sock *sk = (struct sock *)owner;

	if (size <= optmem_max &&
	    atomic_read(&sk->sk_omem_alloc) + size < optmem_max) {
		atomic_add(size, &sk->sk_omem_alloc);
		return 0;
	}

	return -ENOMEM;
}

static void sk_storage_uncharge(struct bpf_local_storage_map *smap,
				void *owner, u32 size)
{
	struct sock *sk = owner;

	atomic_sub(size, &sk->sk_omem_alloc);
}

static struct bpf_local_storage __rcu **
sk_storage_ptr(void *owner)
{
	struct sock *sk = owner;

	return &sk->sk_bpf_storage;
}

const struct bpf_map_ops sk_storage_map_ops = {
	.map_alloc_check = bpf_local_storage_map_alloc_check,
	.map_alloc = sk_storage_map_alloc,
	.map_free = sk_storage_map_free,
	.map_get_next_key = notsupp_get_next_key,
	.map_lookup_elem = bpf_fd_sk_storage_lookup_elem,
	.map_update_elem = bpf_fd_sk_storage_update_elem,
	.map_delete_elem = bpf_fd_sk_storage_delete_elem,
	.map_check_btf = bpf_local_storage_map_check_btf,
	.map_local_storage_charge = sk_storage_charge,
	.map_local_storage_uncharge = sk_storage_uncharge,
	.map_owner_storage_ptr = sk_storage_ptr,
};

const struct bpf_func_proto bpf_sk_storage_get_cg_sock_proto = {
	.func		= bpf_sk_storage_get,
	.gpl_only	= false,
	.ret_type	= RET_PTR_TO_MAP_VALUE_OR_NULL,
	.arg1_type	= ARG_CONST_MAP_PTR,
	.arg2_type	= ARG_PTR_TO_CTX,
	.arg3_type	= ARG_PTR_TO_MAP_VALUE,
	.arg4_type	= ARG_ANYTHING,
};

const struct bpf_func_proto bpf_sk_storage_delete_proto = {
	.func		= bpf_sk_storage_delete,
	.gpl_only	= false,
	.ret_type	= RET_INTEGER,
	.arg1_type	= ARG_CONST_MAP_PTR,
	.arg2_type	= ARG_PTR_TO_CTX,
};

const struct bpf_func_proto bpf_sk_storage_get_cg_sockopt_proto = {
	.func		= bpf_sk_storage_get,
	.gpl_only	= false,
	.ret_type	= RET_PTR_TO_MAP_VALUE_OR_NULL,
	.arg1_type	= ARG_CONST_MAP_PTR,
	.arg2_type	= ARG_PTR_TO_SOCK_COMMON,
	.arg3_type	= ARG_PTR_TO_MAP_VALUE,
	.arg4_type	= ARG_ANYTHING,
};

const struct bpf_func_proto bpf_sk_storage_delete_cg_sockopt_proto = {
	.func		= bpf_sk_storage_delete,
	.gpl_only	= false,
	.ret_type	= RET_INTEGER,
	.arg1_type	= ARG_CONST_MAP_PTR,
	.arg2_type	= ARG_PTR_TO_SOCK_COMMON,
};
