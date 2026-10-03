/* Copyright (c) 2011-2014 PLUMgrid, http://plumgrid.com
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of version 2 of the GNU General Public
 * License as published by the Free Software Foundation.
 */
#ifndef _LINUX_BPF_H
#define _LINUX_BPF_H 1

#include <uapi/linux/bpf.h>
#include <linux/bpf-cgroup.h>

#include <linux/workqueue.h>
#include <linux/mutex.h>
#include <linux/file.h>
#include <linux/percpu.h>
#include <linux/err.h>
#include <linux/rbtree_latch.h>
#include <linux/numa.h>

struct perf_event;
struct bpf_prog;
struct bpf_verifier_log;
struct bpf_map;
struct btf;
struct btf_type;
struct seq_file;
struct poll_table_struct;
struct bpf_local_storage_map;
struct bpf_local_storage;

struct seq_operations;
struct bpf_iter_aux_info;

typedef int (*bpf_iter_init_seq_priv_t)(void *private_data,
					struct bpf_iter_aux_info *aux);
typedef void (*bpf_iter_fini_seq_priv_t)(void *private_data);
struct bpf_iter_seq_info {
	const struct seq_operations *seq_ops;
	bpf_iter_init_seq_priv_t init_seq_private;
	bpf_iter_fini_seq_priv_t fini_seq_private;
	u32 seq_priv_size;
};

/* map is generic key/value storage optionally accesible by eBPF programs */
struct bpf_map_ops {
	/* funcs callable from userspace (via syscall) */
#ifndef __GENKSYMS__
	int (*map_alloc_check)(union bpf_attr *attr);
#endif
	struct bpf_map *(*map_alloc)(union bpf_attr *attr);
	void (*map_release)(struct bpf_map *map, struct file *map_file);
	void (*map_free)(struct bpf_map *map);
	int (*map_get_next_key)(struct bpf_map *map, void *key, void *next_key);
	void (*map_release_uref)(struct bpf_map *map);
	void *(*map_lookup_elem_sys_only)(struct bpf_map *map, void *key);

	/* funcs callable from userspace and from eBPF programs */
	void *(*map_lookup_elem)(struct bpf_map *map, void *key);
	int (*map_update_elem)(struct bpf_map *map, void *key, void *value, u64 flags);
	int (*map_delete_elem)(struct bpf_map *map, void *key);

	/* funcs called by prog_array and perf_event_array map */
	void *(*map_fd_get_ptr)(struct bpf_map *map, struct file *map_file,
				int fd);
	void (*map_fd_put_ptr)(void *ptr);
	u32 (*map_gen_lookup)(struct bpf_map *map, struct bpf_insn *insn_buf);
	u32 (*map_fd_sys_lookup_elem)(void *ptr);
#ifndef __GENKSYMS__
	int (*map_check_btf)(const struct bpf_map *map,
			     const struct btf *btf,
			     const struct btf_type *key_type,
			     const struct btf_type *value_type);

	/* funcs called by prog_array and perf_event_array map */
	void (*map_seq_show_elem)(struct bpf_map *map, void *key,
				  struct seq_file *m);
	int (*map_direct_value_addr)(const struct bpf_map *map,
				     u64 *imm, u32 off);

	int (*map_push_elem)(struct bpf_map *map, void *value, u64 flags);
	int (*map_pop_elem)(struct bpf_map *map, void *value);
	int (*map_peek_elem)(struct bpf_map *map, void *value);

	int (*map_mmap)(struct bpf_map *map, struct vm_area_struct *vma);
	unsigned int (*map_poll)(struct bpf_map *map, struct file *filp,
				 struct poll_table_struct *pts);

	int (*map_local_storage_charge)(struct bpf_local_storage_map *smap,
					void *owner, u32 size);
	void (*map_local_storage_uncharge)(struct bpf_local_storage_map *smap,
					   void *owner, u32 size);
	struct bpf_local_storage __rcu **(*map_owner_storage_ptr)(void *owner);

	/* BTF name and id of struct allocated by map_alloc */
	const char * const map_btf_name;
	int *map_btf_id;

	/* bpf_iter info used to open a seq_file */
	const struct bpf_iter_seq_info *iter_seq_info;

	/* I6: 5.10 batch ops + map_meta_equal (sonda, GENKSYMS korumali) */
	int (*map_lookup_batch)(struct bpf_map *map, const union bpf_attr *attr,
				union bpf_attr __user *uattr);
	int (*map_lookup_and_delete_batch)(struct bpf_map *map,
					   const union bpf_attr *attr,
					   union bpf_attr __user *uattr);
	int (*map_update_batch)(struct bpf_map *map, const union bpf_attr *attr,
				union bpf_attr __user *uattr);
	int (*map_delete_batch)(struct bpf_map *map, const union bpf_attr *attr,
				union bpf_attr __user *uattr);
	bool (*map_meta_equal)(const struct bpf_map *meta0,
			       const struct bpf_map *meta1);
#endif
};

struct bpf_map {
	/* 1st cacheline with read-mostly members of which some
	 * are also accessed in fast-path (e.g. ops, max_entries).
	 */
	const struct bpf_map_ops *ops ____cacheline_aligned;
	struct bpf_map *inner_map_meta;
#ifdef CONFIG_SECURITY
	void *security;
#endif
	enum bpf_map_type map_type;
	u32 key_size;
	u32 value_size;
	u32 max_entries;
	u32 map_flags;
	u32 pages;
	u32 id;
	int numa_node;
#ifndef __GENKSYMS__
	u32 btf_key_type_id;
	u32 btf_value_type_id;
	u32 btf_vmlinux_value_type_id;
	struct btf *btf;
	char name[BPF_OBJ_NAME_LEN];
	int spin_lock_off; /* >=0 valid offset, <0 error */
#endif
	bool unpriv_array;
#ifndef __GENKSYMS__
	bool frozen; /* write-once; write-protected by freeze_mutex */
#endif
	/* 6 bytes hole */

	/* 2nd cacheline with misc members to avoid false sharing
	 * particularly with refcounting.
	 */
	struct user_struct *user ____cacheline_aligned;
	atomic_t refcnt;
	atomic_t usercnt;
	struct work_struct work;
#ifndef __GENKSYMS__
	struct mutex freeze_mutex;
	atomic64_t writecnt;
#endif
};

static inline bool map_value_has_spin_lock(const struct bpf_map *map)
{
	return map->spin_lock_off >= 0;
}

static inline void check_and_init_map_lock(struct bpf_map *map, void *dst)
{
		return;
	*(struct bpf_spin_lock *)(dst + map->spin_lock_off) =
		(struct bpf_spin_lock){};
}

/* copy everything but bpf_spin_lock */
static inline void copy_map_value(struct bpf_map *map, void *dst, void *src)
{
	if (unlikely(map_value_has_spin_lock(map))) {
		u32 off = map->spin_lock_off;

		memcpy(dst, src, off);
		memcpy(dst + off + sizeof(struct bpf_spin_lock),
		       src + off + sizeof(struct bpf_spin_lock),
		       map->value_size - off - sizeof(struct bpf_spin_lock));
	} else {
		memcpy(dst, src, map->value_size);
	}
}
void copy_map_value_locked(struct bpf_map *map, void *dst, void *src,
			   bool lock_src);

/* function argument constraints */
enum bpf_arg_type {
	ARG_DONTCARE = 0,	/* unused argument in helper function */

	/* the following constraints used to prototype
	 * bpf_map_lookup/update/delete_elem() functions
	 */
	ARG_CONST_MAP_PTR,	/* const argument used as pointer to bpf_map */
	ARG_PTR_TO_MAP_KEY,	/* pointer to stack used as map key */
	ARG_PTR_TO_MAP_VALUE,	/* pointer to stack used as map value */

	/* the following constraints used to prototype bpf_memcmp() and other
	 * functions that access data on eBPF program stack
	 */
	ARG_PTR_TO_MEM,		/* pointer to valid memory (stack, packet, map value) */
#ifndef __GENKSYMS__
	ARG_PTR_TO_MEM_OR_NULL, /* pointer to valid memory or NULL */
#endif
	ARG_PTR_TO_UNINIT_MEM,	/* pointer to memory does not need to be initialized,
				 * helper function must fill all bytes or clear
				 * them in error case.
				 */

	ARG_CONST_SIZE,		/* number of bytes accessed from memory */
	ARG_CONST_SIZE_OR_ZERO,	/* number of bytes accessed from memory or 0 */
#ifndef __GENKSYMS__
	ARG_CONST_ALLOC_SIZE_OR_ZERO,	/* number of allocated bytes requested */
#endif

	ARG_PTR_TO_CTX,		/* pointer to context */
	ARG_ANYTHING,		/* any (initialized) argument is ok */
#ifndef __GENKSYMS__
	ARG_PTR_TO_SOCK_COMMON,	/* pointer to sock_common */
	ARG_PTR_TO_SPIN_LOCK,	/* pointer to bpf_spin_lock */
	ARG_PTR_TO_ALLOC_MEM,	/* pointer to dynamically allocated memory */
	ARG_PTR_TO_LONG,	/* pointer to long */
	ARG_PTR_TO_SOCKET,	/* pointer to bpf_sock (fullsock) */
	ARG_PTR_TO_SOCKET_OR_NULL,	/* pointer to bpf_sock (fullsock) or NULL */
	ARG_PTR_TO_BTF_ID,	/* pointer to in-kernel struct */
	ARG_PTR_TO_BTF_ID_SOCK_COMMON,	/* pointer to in-kernel sock_common or bpf-mirrored bpf_sock */
	ARG_PTR_TO_MAP_VALUE_OR_NULL,	/* pointer to stack used as map value or NULL */
	ARG_PTR_TO_UNINIT_MAP_VALUE,	/* pointer to valid memory used to store a map value */
	ARG_PTR_TO_PERCPU_BTF_ID,
#endif
};

/* type of values returned from helper functions */
enum bpf_return_type {
	RET_INTEGER,			/* function returns integer */
	RET_VOID,			/* function doesn't return anything */
#ifndef __GENKSYMS__
	RET_PTR_TO_MAP_VALUE,		/* returns a pointer to map elem value */
#endif
	RET_PTR_TO_MAP_VALUE_OR_NULL,	/* returns a pointer to map elem value or NULL */
#ifndef __GENKSYMS__
	RET_PTR_TO_SOCKET_OR_NULL,	/* returns a pointer to a socket or NULL */
	RET_PTR_TO_TCP_SOCK_OR_NULL,	/* returns a pointer to a tcp_sock or NULL */
	RET_PTR_TO_SOCK_COMMON_OR_NULL,	/* returns a pointer to a sock_common or NULL */
	RET_PTR_TO_ALLOC_MEM_OR_NULL,	/* returns a pointer to dynamically allocated memory or NULL */
	RET_PTR_TO_BTF_ID_OR_NULL,	/* returns a pointer to a btf_id or NULL */
	RET_PTR_TO_MEM_OR_BTF_ID_OR_NULL,
	RET_PTR_TO_MEM_OR_BTF_ID,
#endif
};

/* eBPF function prototype used by verifier to allow BPF_CALLs from eBPF programs
 * to in-kernel helper functions and for adjusting imm32 field in BPF_CALL
 * instructions after verifying
 */
struct bpf_func_proto {
	u64 (*func)(u64 r1, u64 r2, u64 r3, u64 r4, u64 r5);
	bool gpl_only;
	bool pkt_access;
	enum bpf_return_type ret_type;
	enum bpf_arg_type arg1_type;
	enum bpf_arg_type arg2_type;
	enum bpf_arg_type arg3_type;
	enum bpf_arg_type arg4_type;
	enum bpf_arg_type arg5_type;
#ifndef __GENKSYMS__
	union {
		struct {
			u32 *arg1_btf_id;
			u32 *arg2_btf_id;
			u32 *arg3_btf_id;
			u32 *arg4_btf_id;
			u32 *arg5_btf_id;
		};
		u32 *arg_btf_id[5];
	};
	int *ret_btf_id; /* return value btf_id */
	bool (*allowed)(const struct bpf_prog *prog);
#endif
};

/* bpf_context is intentionally undefined structure. Pointer to bpf_context is
 * the first argument to eBPF programs.
 * For socket filters: 'struct bpf_context *' == 'struct sk_buff *'
 */
struct bpf_context;

enum bpf_access_type {
	BPF_READ = 1,
	BPF_WRITE = 2
};

/* types of values stored in eBPF registers */
/* Pointer types represent:
 * pointer
 * pointer + imm
 * pointer + (u16) var
 * pointer + (u16) var + imm
 * if (range > 0) then [ptr, ptr + range - off) is safe to access
 * if (id > 0) means that some 'var' was added
 * if (off > 0) means that 'imm' was added
 */
enum bpf_reg_type {
	NOT_INIT = 0,		 /* nothing was written into register */
	SCALAR_VALUE,		 /* reg doesn't contain a valid pointer */
	PTR_TO_CTX,		 /* reg points to bpf_context */
	CONST_PTR_TO_MAP,	 /* reg points to struct bpf_map */
	PTR_TO_MAP_VALUE,	 /* reg points to map element value */
	PTR_TO_MAP_VALUE_OR_NULL,/* points to map elem value or NULL */
	PTR_TO_STACK,		 /* reg == frame_pointer + offset */
	PTR_TO_PACKET,		 /* reg points to skb->data */
	PTR_TO_PACKET_END,	 /* skb->data + headlen */
#ifndef __GENKSYMS__
	PTR_TO_SOCKET,		 /* reg points to struct bpf_sock */
	PTR_TO_SOCKET_OR_NULL,	 /* reg points to struct bpf_sock or NULL */
	PTR_TO_SOCK_COMMON,	 /* reg points to sock_common */
	PTR_TO_SOCK_COMMON_OR_NULL, /* reg points to sock_common or NULL */
	PTR_TO_TCP_SOCK,	 /* reg points to struct tcp_sock */
	PTR_TO_TCP_SOCK_OR_NULL, /* reg points to struct tcp_sock or NULL */
	PTR_TO_MEM,		 /* reg points to valid memory region */
	PTR_TO_MEM_OR_NULL,	 /* reg points to valid memory region or NULL */
	PTR_TO_BTF_ID,		 /* reg points to kernel struct */
	PTR_TO_BTF_ID_OR_NULL,	 /* reg points to kernel struct or NULL */
	PTR_TO_RDONLY_BUF,	 /* reg points to a readonly buffer */
	PTR_TO_RDONLY_BUF_OR_NULL, /* reg points to a readonly buffer or NULL */
	PTR_TO_RDWR_BUF,	 /* reg points to a read/write buffer */
	PTR_TO_RDWR_BUF_OR_NULL, /* reg points to a read/write buffer or NULL */
	PTR_TO_FLOW_KEYS,	 /* reg points to bpf_flow_keys */
	PTR_TO_XDP_SOCK,	 /* reg points to struct xdp_sock */
	PTR_TO_PACKET_META,	 /* skb->data - meta_len */
	PTR_TO_TP_BUFFER,
	PTR_TO_PERCPU_BTF_ID,
#endif
};

/* The information passed from prog-specific *_is_valid_access
 * back to the verifier.
 */
struct bpf_insn_access_aux {
	enum bpf_reg_type reg_type;
	int ctx_field_size;
#ifndef __GENKSYMS__
	u32 btf_id;
#endif
};

static inline void
bpf_ctx_record_field_size(struct bpf_insn_access_aux *aux, u32 size)
{
	aux->ctx_field_size = size;
}

bool bpf_sock_common_is_valid_access(int off, int size,
					 enum bpf_access_type type,
					 struct bpf_insn_access_aux *info);
bool bpf_sock_is_valid_access(int off, int size, enum bpf_access_type type,
				  struct bpf_insn_access_aux *info);
u32 bpf_sock_convert_ctx_access(enum bpf_access_type type,
				const struct bpf_insn *si,
				struct bpf_insn *insn_buf,
				struct bpf_prog *prog, u32 *target_size);
u32 bpf_tcp_sock_convert_ctx_access(enum bpf_access_type type,
					const struct bpf_insn *si,
					struct bpf_insn *insn_buf,
					struct bpf_prog *prog, u32 *target_size);
bool bpf_tcp_sock_is_valid_access(int off, int size, enum bpf_access_type type,
				  struct bpf_insn_access_aux *info);
bool bpf_xdp_sock_is_valid_access(int off, int size, enum bpf_access_type type,
				  struct bpf_insn_access_aux *info);
u32 bpf_xdp_sock_convert_ctx_access(enum bpf_access_type type,
				    const struct bpf_insn *si,
				    struct bpf_insn *insn_buf,
				    struct bpf_prog *prog, u32 *target_size);

struct bpf_prog_ops {
	int (*test_run)(struct bpf_prog *prog, const union bpf_attr *kattr,
			union bpf_attr __user *uattr);
};

struct bpf_verifier_ops {
	/* return eBPF function prototype for verification */
#ifdef __GENKSYMS__
	const struct bpf_func_proto *(*get_func_proto)(enum bpf_func_id func_id);
#else
	const struct bpf_func_proto *(*get_func_proto)(enum bpf_func_id func_id,
							const struct bpf_prog *prog);
#endif

	/* return true if 'size' wide access at offset 'off' within bpf_context
	 * with 'type' (read or write) is allowed
	 */
#ifdef __GENKSYMS__
	bool (*is_valid_access)(int off, int size, enum bpf_access_type type,
				struct bpf_insn_access_aux *info);
#else
	bool (*is_valid_access)(int off, int size, enum bpf_access_type type,
				const struct bpf_prog *prog,
				struct bpf_insn_access_aux *info);
#endif
	int (*gen_prologue)(struct bpf_insn *insn, bool direct_write,
			    const struct bpf_prog *prog);
	u32 (*convert_ctx_access)(enum bpf_access_type type,
				  const struct bpf_insn *src,
				  struct bpf_insn *dst,
				  struct bpf_prog *prog, u32 *target_size);
#ifdef __GENKSYMS__
	int (*test_run)(struct bpf_prog *prog, const union bpf_attr *kattr,
			union bpf_attr __user *uattr);
#endif
#ifndef __GENKSYMS__
	int (*btf_struct_access)(struct bpf_verifier_log *log,
				 const struct btf_type *t, int off, int size,
				 enum bpf_access_type atype,
				 u32 *next_btf_id);
#endif
};

struct btf;

struct bpf_link {
	atomic64_t refcnt;
	u32 id;
	enum bpf_link_type type;
	const struct bpf_link_ops *ops;
	struct bpf_prog *prog;
	struct work_struct work;
};

struct bpf_link_ops {
	void (*release)(struct bpf_link *link);
	void (*dealloc)(struct bpf_link *link);
	int (*detach)(struct bpf_link *link);
	int (*update_prog)(struct bpf_link *link, struct bpf_prog *new_prog,
			   struct bpf_prog *old_prog);
	void (*show_fdinfo)(const struct bpf_link *link, struct seq_file *seq);
#ifndef __GENKSYMS__
	int (*fill_link_info)(const struct bpf_link *link,
				  struct bpf_link_info *info);
#endif
};

struct bpf_cgroup_link {
	struct bpf_link link;
	struct cgroup *cgroup;
	enum bpf_attach_type type;
};

struct bpf_link_primer {
	struct bpf_link *link;
	struct file *file;
	int fd;
	u32 id;
};

void bpf_link_init(struct bpf_link *link, enum bpf_link_type type,
		   const struct bpf_link_ops *ops, struct bpf_prog *prog);
int bpf_link_prime(struct bpf_link *link, struct bpf_link_primer *primer);
int bpf_link_settle(struct bpf_link_primer *primer);
void bpf_link_cleanup(struct bpf_link_primer *primer);
void bpf_link_inc(struct bpf_link *link);
void bpf_link_put(struct bpf_link *link);
int bpf_link_new_fd(struct bpf_link *link);
struct bpf_link *bpf_link_get_from_fd(u32 ufd);
int bpf_xdp_link_attach(const union bpf_attr *attr, struct bpf_prog *prog);
struct bpf_link *bpf_link_by_id(u32 id);

#define MAX_BPF_FUNC_ARGS 12

struct bpf_func_info_aux {
	u16 linkage;
	bool unreliable;
};

struct exception_table_entry;

/* reg_type info for ctx arguments */
struct bpf_ctx_arg_aux {
	u32 offset;
	enum bpf_reg_type reg_type;
	u32 btf_id;
};

extern const struct file_operations bpf_iter_fops;

#define BPF_ITER_FUNC_PREFIX "bpf_iter_"
#define DEFINE_BPF_ITER_FUNC(target, args...)			\
	extern int bpf_iter_ ## target(args);			\
	int __init bpf_iter_ ## target(args) { return 0; }

struct bpf_iter_aux_info {
	struct bpf_map *map;
};

typedef int (*bpf_iter_attach_target_t)(struct bpf_prog *prog,
					union bpf_iter_link_info *linfo,
					struct bpf_iter_aux_info *aux);
typedef void (*bpf_iter_detach_target_t)(struct bpf_iter_aux_info *aux);
typedef void (*bpf_iter_show_fdinfo_t) (const struct bpf_iter_aux_info *aux,
					struct seq_file *seq);
typedef int (*bpf_iter_fill_link_info_t)(const struct bpf_iter_aux_info *aux,
					 struct bpf_link_info *info);

#define BPF_ITER_CTX_ARG_MAX 2
struct bpf_iter_reg {
	const char *target;
	bpf_iter_attach_target_t attach_target;
	bpf_iter_detach_target_t detach_target;
	bpf_iter_show_fdinfo_t show_fdinfo;
	bpf_iter_fill_link_info_t fill_link_info;
	u32 ctx_arg_info_size;
	struct bpf_ctx_arg_aux ctx_arg_info[BPF_ITER_CTX_ARG_MAX];
	const struct bpf_iter_seq_info *seq_info;
};

struct bpf_iter_meta {
	__bpf_md_ptr(struct seq_file *, seq);
	u64 session_id;
	u64 seq_num;
};

struct bpf_iter__bpf_map_elem {
	__bpf_md_ptr(struct bpf_iter_meta *, meta);
	__bpf_md_ptr(struct bpf_map *, map);
	__bpf_md_ptr(void *, key);
	__bpf_md_ptr(void *, value);
};

int bpf_iter_reg_target(const struct bpf_iter_reg *reg_info);
void bpf_iter_unreg_target(const struct bpf_iter_reg *reg_info);
bool bpf_iter_prog_supported(struct bpf_prog *prog);
int bpf_iter_link_attach(const union bpf_attr *attr, struct bpf_prog *prog);
int bpf_iter_new_fd(struct bpf_link *link);
bool bpf_link_is_iter(struct bpf_link *link);
struct bpf_prog *bpf_iter_get_info(struct bpf_iter_meta *meta, bool in_stop);
int bpf_iter_run_prog(struct bpf_prog *prog, void *ctx);
void bpf_iter_map_show_fdinfo(const struct bpf_iter_aux_info *aux,
				  struct seq_file *seq);
int bpf_iter_map_fill_link_info(const struct bpf_iter_aux_info *aux,
				struct bpf_link_info *info);

int  generic_map_lookup_batch(struct bpf_map *map,
			      const union bpf_attr *attr,
			      union bpf_attr __user *uattr);
int  generic_map_update_batch(struct bpf_map *map,
			      const union bpf_attr *attr,
			      union bpf_attr __user *uattr);
int  generic_map_delete_batch(struct bpf_map *map,
			      const union bpf_attr *attr,
			      union bpf_attr __user *uattr);
bool bpf_map_meta_equal(const struct bpf_map *meta0,
			const struct bpf_map *meta1);
struct bpf_map *bpf_map_get_curr_or_next(u32 *id);
struct bpf_prog *bpf_prog_get_curr_or_next(u32 *id);

struct bpf_prog_aux {
	atomic_t refcnt;
	u32 used_map_cnt;
	u32 max_ctx_offset;
	u32 stack_depth;
	u32 id;
#ifndef __GENKSYMS__
	u32 func_cnt;
	struct bpf_prog **func;
	void *jit_data; /* JIT specific data. arch dependent */
	char name[16];
	u64 load_time; /* ns since boottime */
#endif
	struct latch_tree_node ksym_tnode;
	struct list_head ksym_lnode;
#ifdef __GENKSYMS__
	const struct bpf_verifier_ops *ops;
#else
	const struct bpf_prog_ops *ops;
#endif
	struct bpf_map **used_maps;
	struct bpf_prog *prog;
	struct user_struct *user;
#ifndef __GENKSYMS__
	struct bpf_map *cgroup_storage[MAX_BPF_CGROUP_STORAGE_TYPE];
#endif
#ifndef __GENKSYMS__
	struct btf *btf;
	struct bpf_prog *dst_prog;
	u32 attach_btf_id;
	bool attach_btf_trace;
	const struct btf_type *attach_func_proto;
	const char *attach_func_name;
	u32 ctx_arg_info_size;
	u32 max_rdonly_access;
	u32 max_rdwr_access;
	u32 max_tp_access;
	const struct bpf_ctx_arg_aux *ctx_arg_info;
	struct bpf_func_info *func_info;
#ifndef __GENKSYMS__
	struct bpf_func_info_aux *func_info_aux;
#endif
	struct bpf_line_info *linfo;
	struct exception_table_entry *extable;
	u32 num_exentries;
	u32 func_info_cnt;
	u32 nr_linfo;
	void **jited_linfo;
	u32 linfo_idx;
#endif
#ifdef CONFIG_SECURITY
	void *security;
#endif
	union {
		struct work_struct work;
		struct rcu_head	rcu;
	};
};

struct bpf_array {
	struct bpf_map map;
	u32 elem_size;
	u32 index_mask;
	/* 'ownership' of prog_array is claimed by the first program that
	 * is going to use this map or by the first program which FD is stored
	 * in the map to make sure that all callers and callees have the same
	 * prog_type and JITed flag
	 */
	enum bpf_prog_type owner_prog_type;
	bool owner_jited;
	union {
		char value[0] __aligned(8);
		void *ptrs[0] __aligned(8);
		void __percpu *pptrs[0] __aligned(8);
	};
};

struct bpf_attach_target_info {
	long tgt_addr;
	const char *tgt_name;
	const struct btf_type *tgt_type;
};

int bpf_check_attach_target(struct bpf_verifier_log *log,
			    const struct bpf_prog *prog,
			    const struct bpf_prog *tgt_prog,
			    u32 btf_id,
			    struct bpf_attach_target_info *tgt_info);

#define MAX_TAIL_CALL_CNT 32

#define BPF_F_ACCESS_MASK	(BPF_F_RDONLY |		\
				 BPF_F_RDONLY_PROG |	\
				 BPF_F_WRONLY |		\
				 BPF_F_WRONLY_PROG)

#define BPF_MAP_CAN_READ	(1U << 0)
#define BPF_MAP_CAN_WRITE	(1U << 1)

static inline u32 bpf_map_flags_to_cap(struct bpf_map *map)
{
	u32 access_flags = map->map_flags & (BPF_F_RDONLY_PROG | BPF_F_WRONLY_PROG);

	/* Combination of BPF_F_RDONLY_PROG | BPF_F_WRONLY_PROG is
	 * not possible.
	 */
	if (access_flags & BPF_F_RDONLY_PROG)
		return BPF_MAP_CAN_READ;
	else if (access_flags & BPF_F_WRONLY_PROG)
		return BPF_MAP_CAN_WRITE;
	else
		return BPF_MAP_CAN_READ | BPF_MAP_CAN_WRITE;
}

static inline bool bpf_map_flags_access_ok(u32 access_flags)
{
	return (access_flags & (BPF_F_RDONLY_PROG | BPF_F_WRONLY_PROG)) !=
	       (BPF_F_RDONLY_PROG | BPF_F_WRONLY_PROG);
}

struct bpf_event_entry {
	struct perf_event *event;
	struct file *perf_file;
	struct file *map_file;
	struct rcu_head rcu;
};

u64 bpf_tail_call(u64 ctx, u64 r2, u64 index, u64 r4, u64 r5);
u64 bpf_get_stackid(u64 r1, u64 r2, u64 r3, u64 r4, u64 r5);
u64 bpf_get_stack(u64 r1, u64 r2, u64 r3, u64 r4, u64 r5);

bool bpf_prog_array_compatible(struct bpf_array *array, const struct bpf_prog *fp);
int bpf_prog_calc_tag(struct bpf_prog *fp);
int bpf_check_uarg_tail_zero(void __user *uaddr, size_t expected_size,
			     size_t actual_size);

const struct bpf_func_proto *bpf_get_trace_printk_proto(void);

typedef unsigned long (*bpf_ctx_copy_t)(void *dst, const void *src,
					unsigned long off, unsigned long len);

extern const struct bpf_func_proto bpf_event_output_data_proto;

u64 bpf_event_output(struct bpf_map *map, u64 flags, void *meta, u64 meta_size,
		     void *ctx, u64 ctx_size, bpf_ctx_copy_t ctx_copy);

int bpf_prog_test_run_xdp(struct bpf_prog *prog, const union bpf_attr *kattr,
			  union bpf_attr __user *uattr);
int bpf_prog_test_run_flow_dissector(struct bpf_prog *prog,
				     const union bpf_attr *kattr,
				     union bpf_attr __user *uattr);
int bpf_prog_test_run_sk_lookup(struct bpf_prog *prog,
				const union bpf_attr *kattr,
				union bpf_attr __user *uattr);
int bpf_prog_test_run_skb(struct bpf_prog *prog, const union bpf_attr *kattr,
			  union bpf_attr __user *uattr);

/* an array of programs to be executed under rcu_lock.
 *
 * Typical usage:
 * ret = BPF_PROG_RUN_ARRAY(&bpf_prog_array, ctx, BPF_PROG_RUN);
 *
 * the structure returned by bpf_prog_array_alloc() should be populated
 * with program pointers and the last pointer must be NULL.
 * The user has to keep refcnt on the program and make sure the program
 * is removed from the array before bpf_prog_put().
 * The 'struct bpf_prog_array *' should only be replaced with xchg()
 * since other cpus are walking the array of pointers in parallel.
 */
struct bpf_cgroup_storage;

struct bpf_prog_array_item {
	struct bpf_prog *prog;
#ifndef __GENKSYMS__
	struct bpf_cgroup_storage *cgroup_storage[MAX_BPF_CGROUP_STORAGE_TYPE];
#endif
};

struct bpf_prog_array {
	struct rcu_head rcu;
#ifdef __GENKSYMS__
	struct bpf_prog *progs[0];
#else
	struct bpf_prog_array_item items[0];
#endif
};

struct bpf_prog_array __rcu *bpf_prog_array_alloc(u32 prog_cnt, gfp_t flags);
void bpf_prog_array_free(struct bpf_prog_array __rcu *progs);

int bpf_prog_array_update_at(struct bpf_prog_array *array, int index,
			     struct bpf_prog *prog);
int bpf_prog_array_delete_safe_at(struct bpf_prog_array *array, int index);
int bpf_prog_array_length(struct bpf_prog_array *progs);
int bpf_prog_array_copy_to_user(struct bpf_prog_array *progs,
				__u32 __user *prog_ids, u32 cnt);

void bpf_prog_array_delete_safe(struct bpf_prog_array __rcu *progs,
				struct bpf_prog *old_prog);
int bpf_prog_array_copy(struct bpf_prog_array __rcu *old_array,
			struct bpf_prog *exclude_prog,
			struct bpf_prog *include_prog,
			struct bpf_prog_array **new_array);

#define __BPF_PROG_RUN_ARRAY(array, ctx, func, check_non_null)	\
	({						\
		struct bpf_prog_array_item *_item;	\
		struct bpf_prog *_prog;		\
		struct bpf_prog_array *_array;	\
		u32 _ret = 1;				\
		preempt_disable();			\
		rcu_read_lock();			\
		_array = rcu_dereference(array);	\
		if (unlikely(check_non_null && !_array))\
			goto _out;			\
		_item = &_array->items[0];		\
		while ((_prog = READ_ONCE(_item->prog))) {		\
			bpf_cgroup_storage_set(_item->cgroup_storage);	\
			_ret &= func(_prog, ctx);	\
			_item++;			\
		}					\
_out:							\
		rcu_read_unlock();			\
		preempt_enable_no_resched();		\
		_ret;					\
	 })

#define BPF_PROG_RUN_ARRAY(array, ctx, func)		\
	__BPF_PROG_RUN_ARRAY(array, ctx, func, false)

#define BPF_PROG_RUN_ARRAY_CHECK(array, ctx, func)	\
	__BPF_PROG_RUN_ARRAY(array, ctx, func, true)

#define BPF_COMPLEXITY_LIMIT_INSNS	1000000 /* yes. 1M insns */

#ifdef CONFIG_BPF_SYSCALL
DECLARE_PER_CPU(int, bpf_prog_active);

extern const struct file_operations bpf_map_fops;
extern const struct file_operations bpf_prog_fops;

#define BPF_PROG_TYPE(_id, _name, prog_ctx_type, kern_ctx_type) \
	extern const struct bpf_prog_ops _name ## _prog_ops; \
	extern const struct bpf_verifier_ops _name ## _verifier_ops;
#define BPF_MAP_TYPE(_id, _ops) \
	extern const struct bpf_map_ops _ops;
#define BPF_LINK_TYPE(_id, _name)
#include <linux/bpf_types.h>
#undef BPF_PROG_TYPE
#undef BPF_MAP_TYPE
#undef BPF_LINK_TYPE

struct bpf_prog *bpf_prog_get(u32 ufd);
struct bpf_prog *bpf_prog_get_type(u32 ufd, enum bpf_prog_type type);
struct bpf_prog *bpf_prog_get_type_dev(u32 ufd, enum bpf_prog_type type,
				       bool attach_drv);
struct bpf_prog * __must_check bpf_prog_add(struct bpf_prog *prog, int i);
void bpf_prog_sub(struct bpf_prog *prog, int i);
struct bpf_prog * __must_check bpf_prog_inc(struct bpf_prog *prog);
struct bpf_prog * __must_check bpf_prog_inc_not_zero(struct bpf_prog *prog);
void bpf_prog_put(struct bpf_prog *prog);
int __bpf_prog_charge(struct user_struct *user, u32 pages);
void __bpf_prog_uncharge(struct user_struct *user, u32 pages);

struct bpf_map *bpf_map_get(u32 ufd);
struct bpf_map *bpf_map_get_with_uref(u32 ufd);
struct bpf_map *__bpf_map_get(struct fd f);
struct bpf_map * __must_check bpf_map_inc(struct bpf_map *map, bool uref);
void bpf_map_inc_with_uref(struct bpf_map *map);
void bpf_map_put_with_uref(struct bpf_map *map);
bool bpf_map_write_active(const struct bpf_map *map);
void bpf_map_put(struct bpf_map *map);
struct bpf_map *bpf_map_inc_not_zero_noref(struct bpf_map *map);
int bpf_map_precharge_memlock(u32 pages);
int bpf_map_charge_memlock(struct bpf_map *map, u32 pages);
void bpf_map_uncharge_memlock(struct bpf_map *map, u32 pages);
void bpf_map_init_from_attr(struct bpf_map *map, union bpf_attr *attr);
int array_map_alloc_check(union bpf_attr *attr);
void *bpf_map_area_alloc(size_t size, int numa_node);
void bpf_map_area_free(void *base);

extern int sysctl_unprivileged_bpf_disabled;

int bpf_map_new_fd(struct bpf_map *map, int flags);
int bpf_prog_new_fd(struct bpf_prog *prog);

int bpf_obj_pin_user(u32 ufd, const char __user *pathname);
int bpf_obj_get_user(const char __user *pathname, int flags);

int bpf_percpu_hash_copy(struct bpf_map *map, void *key, void *value);
int bpf_percpu_array_copy(struct bpf_map *map, void *key, void *value);
int bpf_percpu_hash_update(struct bpf_map *map, void *key, void *value,
			   u64 flags);
int bpf_percpu_array_update(struct bpf_map *map, void *key, void *value,
			    u64 flags);

int bpf_stackmap_copy(struct bpf_map *map, void *key, void *value);

int bpf_fd_array_map_update_elem(struct bpf_map *map, struct file *map_file,
				 void *key, void *value, u64 map_flags);
int bpf_fd_array_map_lookup_elem(struct bpf_map *map, void *key, u32 *value);
int bpf_fd_htab_map_update_elem(struct bpf_map *map, struct file *map_file,
				void *key, void *value, u64 map_flags);
int bpf_fd_htab_map_lookup_elem(struct bpf_map *map, void *key, u32 *value);

int bpf_get_file_flag(int flags);

int map_check_no_btf(const struct bpf_map *map,
		     const struct btf *btf,
		     const struct btf_type *key_type,
		     const struct btf_type *value_type);

/* memcpy that is used with 8-byte aligned pointers, power-of-8 size and
 * forced to use 'long' read/writes to try to atomically copy long counters.
 * Best-effort only.  No barriers here, since it _will_ race with concurrent
 * updates from BPF programs. Called from bpf syscall and mostly used with
 * size 8 or 16 bytes, so ask compiler to inline it.
 */
static inline void bpf_long_memcpy(void *dst, const void *src, u32 size)
{
	const long *lsrc = src;
	long *ldst = dst;

	size /= sizeof(long);
	while (size--)
		*ldst++ = *lsrc++;
}

/* verify correctness of eBPF program */
int bpf_check(struct bpf_prog **fp, union bpf_attr *attr,
	      union bpf_attr __user *uattr);

struct bpf_prog *bpf_prog_get_type_path(const char *name, enum bpf_prog_type type);

/* Map specifics */
struct net_device;
struct bpf_dtab_netdev;
struct xdp_buff;
struct sk_buff;

struct bpf_dtab_netdev *__dev_map_lookup_elem(struct bpf_map *map, u32 key);
struct bpf_dtab_netdev *__dev_map_hash_lookup_elem(struct bpf_map *map, u32 key);
void __dev_flush(void);
int dev_xdp_enqueue(struct net_device *dev, struct xdp_buff *xdp,
		    struct net_device *dev_rx);
int dev_map_enqueue(struct bpf_dtab_netdev *dst, struct xdp_buff *xdp,
		    struct net_device *dev_rx);
int dev_map_generic_redirect(struct bpf_dtab_netdev *dst, struct sk_buff *skb,
			     struct bpf_prog *xdp_prog);
bool dev_map_can_have_prog(struct bpf_map *map);

struct bpf_cpu_map_entry;
struct bpf_cpu_map_entry *__cpu_map_lookup_elem(struct bpf_map *map, u32 key);
void __cpu_map_flush(void);
int cpu_map_enqueue(struct bpf_cpu_map_entry *rcpu, struct xdp_buff *xdp,
		    struct net_device *dev_rx);

/* Return map's numa specified by userspace */
static inline int bpf_map_attr_numa_node(const union bpf_attr *attr)
{
	return (attr->map_flags & BPF_F_NUMA_NODE) ?
		attr->numa_node : NUMA_NO_NODE;
}

#else
static inline struct bpf_prog *bpf_prog_get(u32 ufd)
{
	return ERR_PTR(-EOPNOTSUPP);
}

static inline struct bpf_prog *bpf_prog_get_type(u32 ufd,
						 enum bpf_prog_type type)
{
	return ERR_PTR(-EOPNOTSUPP);
}
static inline struct bpf_prog * __must_check bpf_prog_add(struct bpf_prog *prog,
							  int i)
{
	return ERR_PTR(-EOPNOTSUPP);
}

static inline void bpf_prog_sub(struct bpf_prog *prog, int i)
{
}

static inline void bpf_prog_put(struct bpf_prog *prog)
{
}

static inline struct bpf_prog * __must_check bpf_prog_inc(struct bpf_prog *prog)
{
	return ERR_PTR(-EOPNOTSUPP);
}

static inline struct bpf_prog *__must_check
bpf_prog_inc_not_zero(struct bpf_prog *prog)
{
	return ERR_PTR(-EOPNOTSUPP);
}

static inline int __bpf_prog_charge(struct user_struct *user, u32 pages)
{
	return 0;
}

static inline void __bpf_prog_uncharge(struct user_struct *user, u32 pages)
{
}

static inline int bpf_obj_get_user(const char __user *pathname, int flags)
{
	return -EOPNOTSUPP;
}

static inline struct bpf_prog *bpf_prog_get_type_path(const char *name,
				enum bpf_prog_type type)
{
	return ERR_PTR(-EOPNOTSUPP);
}

struct net_device;
struct bpf_dtab_netdev;
struct xdp_buff;
struct sk_buff;

static inline struct bpf_dtab_netdev *__dev_map_lookup_elem(struct bpf_map *map, u32 key)
{
	return NULL;
}

static inline struct bpf_dtab_netdev *__dev_map_hash_lookup_elem(struct bpf_map *map, u32 key)
{
	return NULL;
}

static inline void __dev_flush(void)
{
}

static inline int dev_xdp_enqueue(struct net_device *dev, struct xdp_buff *xdp,
				  struct net_device *dev_rx)
{
	return 0;
}

static inline int dev_map_enqueue(struct bpf_dtab_netdev *dst, struct xdp_buff *xdp,
				  struct net_device *dev_rx)
{
	return 0;
}

static inline int dev_map_generic_redirect(struct bpf_dtab_netdev *dst,
					   struct sk_buff *skb,
					   struct bpf_prog *xdp_prog)
{
	return 0;
}

static inline bool dev_map_can_have_prog(struct bpf_map *map)
{
	return false;
}

struct bpf_cpu_map_entry;
static inline struct bpf_cpu_map_entry *__cpu_map_lookup_elem(struct bpf_map *map, u32 key)
{
	return NULL;
}

static inline void __cpu_map_flush(void)
{
}

static inline int cpu_map_enqueue(struct bpf_cpu_map_entry *rcpu, struct xdp_buff *xdp,
				  struct net_device *dev_rx)
{
	return 0;
}

#endif /* CONFIG_BPF_SYSCALL */

#if defined(CONFIG_INET) && defined(CONFIG_BPF_SYSCALL)
int sock_map_prog_update(struct bpf_map *map, struct bpf_prog *prog,
			 struct bpf_prog *old, u32 which);
int sock_map_get_from_fd(const union bpf_attr *attr, struct bpf_prog *prog);
int sock_map_prog_detach(const union bpf_attr *attr, enum bpf_prog_type ptype);
int sock_map_update_elem_sys(struct bpf_map *map, void *key, void *value, u64 flags);
void sock_map_unhash(struct sock *sk);
void sock_map_destroy(struct sock *sk);
void sock_map_close(struct sock *sk, long timeout);
#else
#ifdef CONFIG_BPF_SYSCALL
static inline int sock_map_prog_update(struct bpf_map *map,
				       struct bpf_prog *prog,
				       struct bpf_prog *old, u32 which)
{
	return -EOPNOTSUPP;
}

static inline int sock_map_get_from_fd(const union bpf_attr *attr,
				       struct bpf_prog *prog)
{
	return -EINVAL;
}

static inline int sock_map_prog_detach(const union bpf_attr *attr,
				       enum bpf_prog_type ptype)
{
	return -EOPNOTSUPP;
}

static inline int sock_map_update_elem_sys(struct bpf_map *map, void *key, void *value,
					   u64 flags)
{
	return -EOPNOTSUPP;
}
#endif /* CONFIG_BPF_SYSCALL */
#endif /* CONFIG_INET && CONFIG_BPF_SYSCALL */

/* verifier prototypes for helper functions called from eBPF programs */
extern const struct bpf_func_proto bpf_map_lookup_elem_proto;
extern const struct bpf_func_proto bpf_map_update_elem_proto;
extern const struct bpf_func_proto bpf_map_delete_elem_proto;

extern const struct bpf_func_proto bpf_get_prandom_u32_proto;
extern const struct bpf_func_proto bpf_spin_lock_proto;
extern const struct bpf_func_proto bpf_spin_unlock_proto;
extern const struct bpf_func_proto bpf_get_smp_processor_id_proto;
extern const struct bpf_func_proto bpf_get_numa_node_id_proto;
extern const struct bpf_func_proto bpf_per_cpu_ptr_proto;
extern const struct bpf_func_proto bpf_this_cpu_ptr_proto;
extern const struct bpf_func_proto bpf_tail_call_proto;
extern const struct bpf_func_proto bpf_ktime_get_ns_proto;
extern const struct bpf_func_proto bpf_ktime_get_boot_ns_proto;
extern const struct bpf_func_proto bpf_ringbuf_output_proto;
extern const struct bpf_func_proto bpf_ringbuf_reserve_proto;
extern const struct bpf_func_proto bpf_ringbuf_submit_proto;
extern const struct bpf_func_proto bpf_ringbuf_discard_proto;
extern const struct bpf_func_proto bpf_ringbuf_query_proto;
extern const struct bpf_func_proto bpf_get_current_pid_tgid_proto;
extern const struct bpf_func_proto bpf_get_current_uid_gid_proto;
extern const struct bpf_func_proto bpf_get_current_comm_proto;
extern const struct bpf_func_proto bpf_get_local_storage_proto;
extern const struct bpf_func_proto bpf_get_current_cgroup_id_proto;
extern const struct bpf_func_proto bpf_map_push_elem_proto;
extern const struct bpf_func_proto bpf_map_pop_elem_proto;
extern const struct bpf_func_proto bpf_map_peek_elem_proto;
extern const struct bpf_func_proto bpf_jiffies64_proto;
extern const struct bpf_func_proto bpf_get_ns_current_pid_tgid_proto;
extern const struct bpf_func_proto bpf_get_task_stack_proto;
extern const struct bpf_func_proto bpf_strtol_proto;
extern const struct bpf_func_proto bpf_strtoul_proto;
extern const struct bpf_func_proto bpf_get_current_ancestor_cgroup_id_proto;
extern const struct bpf_func_proto bpf_skb_vlan_push_proto;
extern const struct bpf_func_proto bpf_skb_vlan_pop_proto;
extern const struct bpf_func_proto bpf_get_stackid_proto;
extern const struct bpf_func_proto bpf_get_stack_proto;
extern const struct bpf_func_proto bpf_sock_map_update_proto;
extern const struct bpf_func_proto bpf_sock_hash_update_proto;
extern const struct bpf_func_proto bpf_sk_redirect_map_proto;
extern const struct bpf_func_proto bpf_sk_redirect_hash_proto;
extern const struct bpf_func_proto bpf_msg_redirect_map_proto;
extern const struct bpf_func_proto bpf_msg_redirect_hash_proto;

/* Shared helpers among cBPF and eBPF. */
void bpf_user_rnd_init_once(void);
u64 bpf_user_rnd_u32(u64 r1, u64 r2, u64 r3, u64 r4, u64 r5);

void bpf_sk_reuseport_detach(struct sock *sk);
int bpf_fd_reuseport_array_lookup_elem(struct bpf_map *map, void *key,
				       void *value);
int bpf_fd_reuseport_array_update_elem(struct bpf_map *map, void *key,
				       void *value, u64 map_flags);

#endif /* _LINUX_BPF_H */
