// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2019 Facebook  */
#include <linux/rculist.h>
#include <linux/list.h>
#include <linux/hash.h>
#include <linux/types.h>
#include <linux/spinlock.h>
#include <linux/bpf.h>
#include <linux/bpf_local_storage.h>
#include <net/sock.h>
#include <uapi/linux/sock_diag.h>
#include <uapi/linux/btf.h>

#define BPF_LOCAL_STORAGE_CREATE_FLAG_MASK (BPF_F_NO_PREALLOC | BPF_F_CLONE)

static struct bpf_local_storage_map_bucket *
select_bucket(struct bpf_local_storage_map *smap,
	      struct bpf_local_storage_elem *selem)
{
	return &smap->buckets[hash_ptr(selem, smap->bucket_log)];
}

static int mem_charge(struct bpf_local_storage_map *smap, void *owner, u32 size)
{
	struct bpf_map *map = &smap->map;

	if (!map->ops->map_local_storage_charge)
		return 0;

	return map->ops->map_local_storage_charge(smap, owner, size);
}

static void mem_uncharge(struct bpf_local_storage_map *smap, void *owner,
			 u32 size)
{
	struct bpf_map *map = &smap->map;

	if (map->ops->map_local_storage_uncharge)
		map->ops->map_local_storage_uncharge(smap, owner, size);
}

static struct bpf_local_storage __rcu **
owner_storage(struct bpf_local_storage_map *smap, void *owner)
{
	struct bpf_map *map = &smap->map;

	return map->ops->map_owner_storage_ptr(owner);
}

static bool selem_linked_to_storage_lockless(const struct bpf_local_storage_elem *selem)
{
	return !hlist_unhashed(&selem->snode);
}

static bool selem_linked_to_storage(const struct bpf_local_storage_elem *selem)
{
	return !hlist_unhashed(&selem->snode);
}

static bool selem_linked_to_map_lockless(const struct bpf_local_storage_elem *selem)
{
	return !hlist_unhashed(&selem->map_node);
}

static bool selem_linked_to_map(const struct bpf_local_storage_elem *selem)
{
	return !hlist_unhashed(&selem->map_node);
}

struct bpf_local_storage_elem *
bpf_selem_alloc(struct bpf_local_storage_map *smap, void *owner,
		void *value, bool charge_mem)
{
	struct bpf_local_storage_elem *selem;

	if (charge_mem && mem_charge(smap, owner, smap->elem_size))
		return NULL;

	selem = kzalloc(smap->elem_size, GFP_ATOMIC | __GFP_NOWARN);
	if (selem) {
		if (value)
			copy_map_value(&smap->map, SDATA(selem)->data, value);
		return selem;
	}

	if (charge_mem)
		mem_uncharge(smap, owner, smap->elem_size);

	return NULL;
}

bool bpf_selem_unlink_storage_nolock(struct bpf_local_storage *local_storage,
				     struct bpf_local_storage_elem *selem,
				     bool uncharge_mem)
{
	struct bpf_local_storage_map *smap;
	bool free_local_storage;
	void *owner;

	smap = rcu_dereference(SDATA(selem)->smap);
	owner = local_storage->owner;

	if (uncharge_mem)
		mem_uncharge(smap, owner, smap->elem_size);

	free_local_storage = hlist_is_singular_node(&selem->snode,
						    &local_storage->list);
	if (free_local_storage) {
		mem_uncharge(smap, owner, sizeof(struct bpf_local_storage));
		local_storage->owner = NULL;

		RCU_INIT_POINTER(*owner_storage(smap, owner), NULL);
	}
	hlist_del_init_rcu(&selem->snode);
	if (rcu_access_pointer(local_storage->cache[smap->cache_idx]) ==
	    SDATA(selem))
		RCU_INIT_POINTER(local_storage->cache[smap->cache_idx], NULL);

	kfree_rcu(selem, rcu);

	return free_local_storage;
}

static void __bpf_selem_unlink_storage(struct bpf_local_storage_elem *selem)
{
	struct bpf_local_storage *local_storage;
	bool free_local_storage = false;

	if (unlikely(!selem_linked_to_storage_lockless(selem)))
		return;

	local_storage = rcu_dereference(selem->local_storage);
	raw_spin_lock_bh(&local_storage->lock);
	if (likely(selem_linked_to_storage(selem)))
		free_local_storage = bpf_selem_unlink_storage_nolock(
			local_storage, selem, true);
	raw_spin_unlock_bh(&local_storage->lock);

	if (free_local_storage)
		kfree_rcu(local_storage, rcu);
}

void bpf_selem_link_storage_nolock(struct bpf_local_storage *local_storage,
				   struct bpf_local_storage_elem *selem)
{
	RCU_INIT_POINTER(selem->local_storage, local_storage);
	hlist_add_head_rcu(&selem->snode, &local_storage->list);
}

void bpf_selem_unlink_map(struct bpf_local_storage_elem *selem)
{
	struct bpf_local_storage_map *smap;
	struct bpf_local_storage_map_bucket *b;

	if (unlikely(!selem_linked_to_map_lockless(selem)))
		return;

	smap = rcu_dereference(SDATA(selem)->smap);
	b = select_bucket(smap, selem);
	raw_spin_lock_bh(&b->lock);
	if (likely(selem_linked_to_map(selem)))
		hlist_del_init_rcu(&selem->map_node);
	raw_spin_unlock_bh(&b->lock);
}

void bpf_selem_link_map(struct bpf_local_storage_map *smap,
			struct bpf_local_storage_elem *selem)
{
	struct bpf_local_storage_map_bucket *b = select_bucket(smap, selem);

	raw_spin_lock_bh(&b->lock);
	RCU_INIT_POINTER(SDATA(selem)->smap, smap);
	hlist_add_head_rcu(&selem->map_node, &b->list);
	raw_spin_unlock_bh(&b->lock);
}

void bpf_selem_unlink(struct bpf_local_storage_elem *selem)
{
	bpf_selem_unlink_map(selem);
	__bpf_selem_unlink_storage(selem);
}

struct bpf_local_storage_data *
bpf_local_storage_lookup(struct bpf_local_storage *local_storage,
			 struct bpf_local_storage_map *smap,
			 bool cacheit_lockit)
{
	struct bpf_local_storage_data *sdata;
	struct bpf_local_storage_elem *selem;

	sdata = rcu_dereference(local_storage->cache[smap->cache_idx]);
	if (sdata && rcu_access_pointer(sdata->smap) == smap)
		return sdata;

	hlist_for_each_entry_rcu(selem, &local_storage->list, snode)
		if (rcu_access_pointer(SDATA(selem)->smap) == smap)
			break;

	if (!selem)
		return NULL;

	sdata = SDATA(selem);
	if (cacheit_lockit) {
		raw_spin_lock_bh(&local_storage->lock);
		if (selem_linked_to_storage(selem))
			rcu_assign_pointer(local_storage->cache[smap->cache_idx],
					   sdata);
		raw_spin_unlock_bh(&local_storage->lock);
	}

	return sdata;
}

static int check_flags(const struct bpf_local_storage_data *old_sdata,
		       u64 map_flags)
{
	if (old_sdata && (map_flags & ~BPF_F_LOCK) == BPF_NOEXIST)
		return -EEXIST;

	if (!old_sdata && (map_flags & ~BPF_F_LOCK) == BPF_EXIST)
		return -ENOENT;

	return 0;
}

int bpf_local_storage_alloc(void *owner,
			    struct bpf_local_storage_map *smap,
			    struct bpf_local_storage_elem *first_selem)
{
	struct bpf_local_storage *prev_storage, *storage;
	struct bpf_local_storage **owner_storage_ptr;
	int err;

	err = mem_charge(smap, owner, sizeof(*storage));
	if (err)
		return err;

	storage = kzalloc(sizeof(*storage), GFP_ATOMIC | __GFP_NOWARN);
	if (!storage) {
		err = -ENOMEM;
		goto uncharge;
	}

	INIT_HLIST_HEAD(&storage->list);
	raw_spin_lock_init(&storage->lock);
	storage->owner = owner;

	bpf_selem_link_storage_nolock(storage, first_selem);
	bpf_selem_link_map(smap, first_selem);

	owner_storage_ptr =
		(struct bpf_local_storage **)owner_storage(smap, owner);
	prev_storage = cmpxchg(owner_storage_ptr, NULL, storage);
	if (unlikely(prev_storage)) {
		bpf_selem_unlink_map(first_selem);
		err = -EAGAIN;
		goto uncharge;
	}

	return 0;

uncharge:
	kfree(storage);
	mem_uncharge(smap, owner, sizeof(*storage));
	return err;
}

struct bpf_local_storage_data *
bpf_local_storage_update(void *owner, struct bpf_local_storage_map *smap,
			 void *value, u64 map_flags)
{
	struct bpf_local_storage_data *old_sdata = NULL;
	struct bpf_local_storage_elem *selem;
	struct bpf_local_storage *local_storage;
	int err;

	if (unlikely((map_flags & ~BPF_F_LOCK) > BPF_EXIST) ||
	    unlikely((map_flags & BPF_F_LOCK) &&
		     !map_value_has_spin_lock(&smap->map)))
		return ERR_PTR(-EINVAL);

	local_storage = rcu_dereference(*owner_storage(smap, owner));
	if (!local_storage || hlist_empty(&local_storage->list)) {
		err = check_flags(NULL, map_flags);
		if (err)
			return ERR_PTR(err);

		selem = bpf_selem_alloc(smap, owner, value, true);
		if (!selem)
			return ERR_PTR(-ENOMEM);

		err = bpf_local_storage_alloc(owner, smap, selem);
		if (err) {
			kfree(selem);
			mem_uncharge(smap, owner, smap->elem_size);
			return ERR_PTR(err);
		}

		return SDATA(selem);
	}

	if ((map_flags & BPF_F_LOCK) && !(map_flags & BPF_NOEXIST)) {
		old_sdata =
			bpf_local_storage_lookup(local_storage, smap, false);
		err = check_flags(old_sdata, map_flags);
		if (err)
			return ERR_PTR(err);
		if (old_sdata && selem_linked_to_storage_lockless(SELEM(old_sdata))) {
			copy_map_value_locked(&smap->map, old_sdata->data,
					      value, false);
			return old_sdata;
		}
	}

	raw_spin_lock_bh(&local_storage->lock);

	if (unlikely(hlist_empty(&local_storage->list))) {
		err = -EAGAIN;
		goto unlock_err;
	}

	old_sdata = bpf_local_storage_lookup(local_storage, smap, false);
	err = check_flags(old_sdata, map_flags);
	if (err)
		goto unlock_err;

	if (old_sdata && (map_flags & BPF_F_LOCK)) {
		copy_map_value_locked(&smap->map, old_sdata->data, value,
				      false);
		selem = SELEM(old_sdata);
		goto unlock;
	}

	selem = bpf_selem_alloc(smap, owner, value, !old_sdata);
	if (!selem) {
		err = -ENOMEM;
		goto unlock_err;
	}

	bpf_selem_link_map(smap, selem);
	bpf_selem_link_storage_nolock(local_storage, selem);

	if (old_sdata) {
		bpf_selem_unlink_map(SELEM(old_sdata));
		bpf_selem_unlink_storage_nolock(local_storage, SELEM(old_sdata),
						false);
	}

unlock:
	raw_spin_unlock_bh(&local_storage->lock);
	return SDATA(selem);

unlock_err:
	raw_spin_unlock_bh(&local_storage->lock);
	return ERR_PTR(err);
}

u16 bpf_local_storage_cache_idx_get(struct bpf_local_storage_cache *cache)
{
	u64 min_usage = U64_MAX;
	u16 i, res = 0;

	spin_lock(&cache->idx_lock);

	for (i = 0; i < BPF_LOCAL_STORAGE_CACHE_SIZE; i++) {
		if (cache->idx_usage_counts[i] < min_usage) {
			min_usage = cache->idx_usage_counts[i];
			res = i;

			if (!min_usage)
				break;
		}
	}
	cache->idx_usage_counts[res]++;

	spin_unlock(&cache->idx_lock);

	return res;
}

void bpf_local_storage_cache_idx_free(struct bpf_local_storage_cache *cache,
				      u16 idx)
{
	spin_lock(&cache->idx_lock);
	cache->idx_usage_counts[idx]--;
	spin_unlock(&cache->idx_lock);
}

void bpf_local_storage_map_free(struct bpf_local_storage_map *smap)
{
	struct bpf_local_storage_elem *selem;
	struct bpf_local_storage_map_bucket *b;
	unsigned int i;

	synchronize_rcu();

	for (i = 0; i < (1U << smap->bucket_log); i++) {
		b = &smap->buckets[i];

		rcu_read_lock();
		while ((selem = hlist_entry_safe(
				rcu_dereference_raw(hlist_first_rcu(&b->list)),
				struct bpf_local_storage_elem, map_node))) {
			bpf_selem_unlink(selem);
			cond_resched_rcu();
		}
		rcu_read_unlock();
	}

	synchronize_rcu();

	kvfree(smap->buckets);
	kfree(smap);
}

int bpf_local_storage_map_alloc_check(union bpf_attr *attr)
{
	if (attr->map_flags & ~BPF_LOCAL_STORAGE_CREATE_FLAG_MASK ||
	    !(attr->map_flags & BPF_F_NO_PREALLOC) ||
	    attr->max_entries ||
	    attr->key_size != sizeof(int) || !attr->value_size ||
	    !attr->btf_key_type_id || !attr->btf_value_type_id)
		return -EINVAL;

	if (!bpf_capable())
		return -EPERM;

	if (attr->value_size > BPF_LOCAL_STORAGE_MAX_VALUE_SIZE)
		return -E2BIG;

	return 0;
}

struct bpf_local_storage_map *bpf_local_storage_map_alloc(union bpf_attr *attr)
{
	struct bpf_local_storage_map *smap;
	unsigned int i;
	u32 nbuckets;
	u64 cost;
	int ret;

	smap = kzalloc(sizeof(*smap), GFP_USER | __GFP_NOWARN);
	if (!smap)
		return ERR_PTR(-ENOMEM);
	bpf_map_init_from_attr(&smap->map, attr);

	nbuckets = roundup_pow_of_two(num_possible_cpus());
	nbuckets = max_t(u32, 2, nbuckets);
	smap->bucket_log = ilog2(nbuckets);
	cost = sizeof(*smap->buckets) * nbuckets + sizeof(*smap);

	/* 4.14: bpf_map_charge_init/finish yok (5.10 govdesinden farkli,
	 * queue_stack_maps.c/ringbuf.c ile ayni uyarlama), precharge_memlock
	 * + map.pages kullanilir.
	 */
	ret = bpf_map_precharge_memlock(cost >> PAGE_SHIFT);
	if (ret < 0) {
		kfree(smap);
		return ERR_PTR(ret);
	}

	smap->buckets = kvmalloc_array(nbuckets, sizeof(*smap->buckets),
					GFP_USER | __GFP_NOWARN | __GFP_ZERO);
	if (!smap->buckets) {
		kfree(smap);
		return ERR_PTR(-ENOMEM);
	}

	smap->map.pages = cost >> PAGE_SHIFT;

	for (i = 0; i < nbuckets; i++) {
		INIT_HLIST_HEAD(&smap->buckets[i].list);
		raw_spin_lock_init(&smap->buckets[i].lock);
	}

	smap->elem_size =
		sizeof(struct bpf_local_storage_elem) + attr->value_size;

	return smap;
}

int bpf_local_storage_map_check_btf(const struct bpf_map *map,
				    const struct btf_type *key_type,
				    const struct btf_type *value_type)
{
	u32 int_data;

	if (BTF_INFO_KIND(key_type->info) != BTF_KIND_INT)
		return -EINVAL;

	int_data = *(u32 *)(key_type + 1);
	if (BTF_INT_BITS(int_data) != 32 || BTF_INT_OFFSET(int_data))
		return -EINVAL;

	return 0;
}
