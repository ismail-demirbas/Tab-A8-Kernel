# SPDX-License-Identifier: GPL-2.0
obj-y := core.o
CFLAGS_core.o += $(call cc-disable-warning, override-init)

obj-$(CONFIG_BPF_SYSCALL) += syscall.o verifier.o inode.o helpers.o tnum.o bpf_iter.o map_iter.o prog_iter.o task_iter.o
obj-$(CONFIG_BPF_SYSCALL) += hashtab.o arraymap.o percpu_freelist.o bpf_lru_list.o lpm_trie.o map_in_map.o
obj-$(CONFIG_BPF_SYSCALL) += queue_stack_maps.o ringbuf.o
ifeq ($(CONFIG_NET),y)
obj-$(CONFIG_BPF_SYSCALL) += devmap.o
obj-$(CONFIG_BPF_SYSCALL) += cpumap.o
obj-$(CONFIG_BPF_SYSCALL) += reuseport_array.o
obj-$(CONFIG_BPF_SYSCALL) += btf.o disasm.o
obj-$(CONFIG_BPF_SYSCALL) += bpf_local_storage.o bpf_sk_storage.o
obj-$(CONFIG_BPF_SYSCALL) += bpf_inode_storage.o
ifeq ($(CONFIG_NET),y)
obj-$(CONFIG_BPF_SYSCALL) += net_namespace.o
endif
endif
ifeq ($(CONFIG_PERF_EVENTS),y)
obj-$(CONFIG_BPF_SYSCALL) += stackmap.o
endif
obj-$(CONFIG_CGROUP_BPF) += cgroup.o
obj-$(CONFIG_BPF_SYSCALL) += local_storage.o
obj-$(CONFIG_DEBUG_INFO_BTF) += sysfs_btf.o
