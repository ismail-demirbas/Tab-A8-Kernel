/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright (c) 2019 Facebook */
#ifndef _BPF_SK_STORAGE_H
#define _BPF_SK_STORAGE_H

struct sock;

#ifdef CONFIG_BPF_SYSCALL
void bpf_sk_storage_free(struct sock *sk);
extern const struct bpf_func_proto bpf_sk_storage_get_cg_sock_proto;
extern const struct bpf_func_proto bpf_sk_storage_delete_proto;
extern const struct bpf_func_proto bpf_sk_storage_get_cg_sockopt_proto;
extern const struct bpf_func_proto bpf_sk_storage_delete_cg_sockopt_proto;
#else
static inline void bpf_sk_storage_free(struct sock *sk) { }
#endif

#endif /* _BPF_SK_STORAGE_H */
