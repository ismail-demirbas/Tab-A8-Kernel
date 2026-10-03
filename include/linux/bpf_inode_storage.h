/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _LINUX_BPF_INODE_STORAGE_H
#define _LINUX_BPF_INODE_STORAGE_H

struct inode;
struct bpf_func_proto;

#ifdef CONFIG_BPF_SYSCALL
extern const struct bpf_func_proto bpf_inode_storage_get_proto;
extern const struct bpf_func_proto bpf_inode_storage_delete_proto;
void bpf_inode_storage_free(struct inode *inode);
#else
static inline void bpf_inode_storage_free(struct inode *inode)
{
}
#endif

#endif /* _LINUX_BPF_INODE_STORAGE_H */
