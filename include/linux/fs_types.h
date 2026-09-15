/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _LINUX_FS_TYPES_H
#define _LINUX_FS_TYPES_H

#include <linux/types.h>

#include <linux/types.h>

/*
 * struct dirent file types
 * (ie "(i_mode >> 12) & 15")
 */
#define S_DT_SHIFT	12
#define S_DT(mode)	(((mode) & S_IFMT) >> S_DT_SHIFT)
#define S_DT_MASK	(S_IFMT >> S_DT_SHIFT)

#define DT_MAX		(S_DT_MASK + 1)

#define DT_MAX		(S_DT_MASK + 1)

/*
 * fs on-disk file types.
 * DT_* values already defined in include/linux/fs.h for this tree.
 */
#define FT_UNKNOWN	0
#define FT_REG_FILE	1
#define FT_DIR		2
#define FT_CHRDEV	3
#define FT_BLKDEV	4
#define FT_FIFO		5
#define FT_SOCK		6
#define FT_SYMLINK	7

#define FT_MAX		8

extern unsigned char fs_ftype_to_dtype(unsigned int filetype);
extern unsigned char fs_umode_to_ftype(umode_t mode);
extern unsigned char fs_umode_to_dtype(umode_t mode);

#endif
