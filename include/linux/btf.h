/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright (c) 2018 Facebook */

#ifndef _LINUX_BTF_H
#define _LINUX_BTF_H 1

#include <linux/types.h>

struct btf;
struct btf_type;
union bpf_attr;
struct bpf_prog;
struct bpf_insn_access_aux;

extern const struct file_operations btf_fops;

void btf_put(struct btf *btf);
int btf_new_fd(const union bpf_attr *attr);
struct btf *btf_parse_vmlinux(void);
struct btf *bpf_get_btf_vmlinux(void);
s32 btf_find_by_name_kind(const struct btf *btf, const char *name, u8 kind);
const struct btf_type *btf_type_skip_modifiers(const struct btf *btf,
					       u32 id, u32 *res_id);
const struct btf_type *btf_type_resolve_ptr(const struct btf *btf,
					    u32 id, u32 *res_id);
const struct btf_type *
btf_resolve_size(const struct btf *btf, const struct btf_type *type,
		 u32 *type_size);
struct btf *btf_get_by_fd(int fd);
int btf_check_func_info_type(const struct btf *btf, u32 type_id);
bool btf_str_offset_valid(const struct btf *btf, u32 offset);
int btf_get_info_by_fd(const struct btf *btf,
		       const union bpf_attr *attr,
		       union bpf_attr __user *uattr);
/* Figure out the size of a type_id.  If type_id is a modifier
 * (e.g. const), it will be resolved to find out the type with size.
 *
 * For example:
 * In describing "const void *",  type_id is "const" and "const"
 * refers to "void *".  The return type will be "void *".
 *
 * If type_id is a simple "int", then return type will be "int".
 *
 * @btf: struct btf object
 * @type_id: Find out the size of type_id. The type_id of the return
 *           type is set to *type_id.
 * @ret_size: It can be NULL.  If not NULL, the size of the return
 *            type is set to *ret_size.
 * Return: The btf_type (resolved to another type with size info if needed).
 *         NULL is returned if type_id itself does not have size info
 *         (e.g. void) or it cannot be resolved to another type that
 *         has size info.
 *         *type_id and *ret_size will not be changed in the
 *         NULL return case.
 */
const struct btf_type *btf_type_id_size(const struct btf *btf,
					u32 *type_id,
					u32 *ret_size);
const struct btf_type *btf_type_by_id(const struct btf *btf, u32 type_id);
void btf_type_seq_show(const struct btf *btf, u32 type_id, void *obj,
		       struct seq_file *m);
int btf_get_fd_by_id(u32 id);
u32 btf_id(const struct btf *btf);
int btf_find_spin_lock(const struct btf *btf, const struct btf_type *t);
const char *btf_name_by_offset(const struct btf *btf, u32 offset);
bool btf_type_is_ptr(const struct btf_type *t);
bool btf_type_is_func_proto(const struct btf_type *t);
bool btf_type_is_typedef(const struct btf_type *t);
int btf_struct_access(struct bpf_verifier_log *log,
		      const struct btf_type *t, int off, int size,
		      enum bpf_access_type atype,
		      u32 *next_btf_id);
bool btf_struct_ids_match(struct bpf_verifier_log *log,
			  int off, u32 id, u32 need_type_id);
bool btf_ctx_access(int off, int size, enum bpf_access_type type,
		    const struct bpf_prog *prog,
		    struct bpf_insn_access_aux *info);

#endif
