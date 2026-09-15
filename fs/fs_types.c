// SPDX-License-Identifier: GPL-2.0
#include <linux/fs.h>
#include <linux/fs_types.h>
#include <linux/export.h>

static const unsigned char fs_dtype_by_ftype[FT_MAX] = {
	[FT_UNKNOWN]	= DT_UNKNOWN,
	[FT_REG_FILE]	= DT_REG,
	[FT_DIR]	= DT_DIR,
	[FT_CHRDEV]	= DT_CHR,
	[FT_BLKDEV]	= DT_BLK,
	[FT_FIFO]	= DT_FIFO,
	[FT_SOCK]	= DT_SOCK,
	[FT_SYMLINK]	= DT_LNK
};

unsigned char fs_ftype_to_dtype(unsigned int filetype)
{
	if (filetype >= FT_MAX)
		return DT_UNKNOWN;

	return fs_dtype_by_ftype[filetype];
}
EXPORT_SYMBOL_GPL(fs_ftype_to_dtype);

static const unsigned char fs_ftype_by_dtype[DT_MAX] = {
	[DT_REG]	= FT_REG_FILE,
	[DT_DIR]	= FT_DIR,
	[DT_LNK]	= FT_SYMLINK,
	[DT_CHR]	= FT_CHRDEV,
	[DT_BLK]	= FT_BLKDEV,
	[DT_FIFO]	= FT_FIFO,
	[DT_SOCK]	= FT_SOCK,
};

unsigned char fs_umode_to_ftype(umode_t mode)
{
	return fs_ftype_by_dtype[S_DT(mode)];
}
EXPORT_SYMBOL_GPL(fs_umode_to_ftype);

unsigned char fs_umode_to_dtype(umode_t mode)
{
	return fs_ftype_to_dtype(fs_umode_to_ftype(mode));
}
EXPORT_SYMBOL_GPL(fs_umode_to_dtype);
