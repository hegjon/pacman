/*
 *  btrpkg.h
 *
 *  Reader for btrpkg format version 0 indexes (https://github.com/hegjon/btrpkg) and their
 *  signify-format Ed25519 signatures.
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */
#ifndef ALPM_BTRPKG_H
#define ALPM_BTRPKG_H

#include <stddef.h>
#include <stdint.h>

/* Self-contained (libcrypto, libzstd and base64.c only), so it can be tested without a handle.
 * Every function that can fail returns 0 on success and -1 on failure, with a message in err
 * (BTR_ERRLEN bytes). */

#define BTR_VERSION 0 /* format version (0: unstable, changes without a bump) */
#define BTR_HDR 256
#define BTR_ENT 88
#define BTR_BLOCK 4096
#define BTR_MAX_EXTENT (128 * 1024)
#define BTR_ERRLEN 256

#define BTR_COMP_NONE 0
#define BTR_COMP_ZSTD 2

#define BTR_K_FILE 0
#define BTR_K_DIR 1
#define BTR_K_SYMLINK 2
#define BTR_K_HARDLINK 3

typedef struct {
	uint64_t nchunks, image_len;
	uint64_t entries_len, entries_raw_len;
	uint64_t blob_len, blob_raw_len;
	unsigned char table_hash[32], entries_hash[32], blob_hash[32];
	/* the header hash (bytes 224..256): what identifies the package and what is signed */
	unsigned char id[32];
} btr_header_t;

typedef struct {
	uint64_t image_off;
	uint32_t unencoded_len, encoded_len;
	uint8_t compression;
	unsigned char stored[32]; /* SHA-256 of the bytes as stored */
	unsigned char raw[32];    /* SHA-256 of the unencoded bytes */
} btr_chunk_t;

typedef struct {
	unsigned char *name, *value; /* name NUL-terminated; value binary */
	size_t name_len, value_len;
} btr_xattr_t;

typedef struct {
	uint8_t kind;
	uint32_t mode, uid, gid;
	int64_t mtime;
	uint64_t size;
	uint64_t data_off; /* image offset (large file) or offset into the small-file blob */
	uint8_t small;
	char *path;   /* NUL-terminated (checked to contain no NUL) */
	size_t path_len;
	char *target; /* symlink target or hardlink path, NUL-terminated */
	size_t target_len;
	uint32_t nxattrs;
	btr_xattr_t *xattrs;
} btr_entry_t;

typedef struct {
	btr_header_t hdr;
	btr_chunk_t *chunks;
	btr_entry_t *entries;
	size_t nentries;
	unsigned char *small;
	size_t small_len;
} btr_index_t;

uint64_t btr_index_len(const btr_header_t *h);
uint64_t btr_image_base(const btr_header_t *h);
uint64_t btr_cache_len(const btr_header_t *h);

/* Decode and check a 256-byte header (magic, version, checksum, reserved bytes, size caps). */
int btr_header_decode(const unsigned char *b, size_t len, btr_header_t *h, char *err);

/* Parse and check a whole index from the start of buf (an index, transport or cache file; bytes
 * after the index are ignored). If expected_id is not NULL the header hash must equal it, checked
 * before anything after the header is looked at. */
int btr_index_parse(const unsigned char *buf, size_t len, const unsigned char *expected_id,
		btr_index_t **out, char *err);
void btr_index_free(btr_index_t *idx);

/* Check a signify signature (the text of a .sig file) over the 256-byte header, against every
 * *.pub in keydirs (NULL-terminated; missing directories are skipped) minus the key numbers in
 * any "revoked" file there. On success, the key's path goes to keypath (PATH_MAX) if not NULL. */
int btr_sig_verify(const unsigned char *hdr, const char *sigtext, size_t siglen,
		const char *const *keydirs, char *keypath, char *err);

/* Check a chunk's stored bytes before writing them: length, stored hash, and for zstd the frame
 * header btrfs relies on (one frame, no dictionary ID or checksum, content size = unencoded
 * length). The unencoded hash is not checked (see btrpkg's format.rs, check_chunk). */
int btr_check_chunk(size_t i, const btr_chunk_t *c, const unsigned char *d, size_t len, char *err);

void btr_sha256(const unsigned char *d, size_t len, unsigned char out[32]);
void btr_hex(const unsigned char *b, size_t len, char *out); /* out: 2*len+1 */

#endif /* ALPM_BTRPKG_H */
