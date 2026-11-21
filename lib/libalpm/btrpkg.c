/*
 *  btrpkg.c
 *
 *  Reader for btrpkg format version 0 indexes and their signify-format Ed25519 signatures. The
 *  format and every check here follow btrpkg's src/format.rs and src/sign.rs; `btrpkg dump` and
 *  test/btrpkg/btrdump print the same text for the same index.
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

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <openssl/evp.h>
#include <zstd.h>

#include "base64.h"
#include "btrpkg.h"

static const unsigned char MAGIC[8] = { 'B', 'T', 'R', 'P', 'K', 'G', 0, 0 };

/* Caps on lengths a header may announce, checked before anything is allocated (format.rs). */
#define MAX_SECTION ((uint64_t)1 << 32)
#define MAX_ENTRIES_RAW ((uint64_t)256 << 20)
#define MAX_BLOB_RAW ((uint64_t)1 << 30)
/* smallest possible encoded entry: kind, mode, uid, gid, mtime, size, data_off, small, three
 * u32 lengths */
#define MIN_ENTRY 50

static int fail(char *err, const char *fmt, ...)
{
	if(err) {
		va_list ap;
		va_start(ap, fmt);
		vsnprintf(err, BTR_ERRLEN, fmt, ap);
		va_end(ap);
	}
	return -1;
}

static uint32_t u32_at(const unsigned char *b)
{
	return (uint32_t)b[0] | (uint32_t)b[1] << 8 | (uint32_t)b[2] << 16 | (uint32_t)b[3] << 24;
}

static uint64_t u64_at(const unsigned char *b)
{
	return (uint64_t)u32_at(b) | (uint64_t)u32_at(b + 4) << 32;
}

static int all_zero(const unsigned char *b, size_t n)
{
	for(size_t i = 0; i < n; i++) {
		if(b[i]) {
			return 0;
		}
	}
	return 1;
}

void btr_sha256(const unsigned char *d, size_t len, unsigned char out[32])
{
	unsigned int n = 32;
	if(EVP_Digest(d, len, out, &n, EVP_sha256(), NULL) != 1 || n != 32) {
		/* only on allocation failure inside OpenSSL; make every comparison fail */
		memset(out, 0, 32);
		out[0] = 1;
		out[31] = 0xff;
	}
}

void btr_hex(const unsigned char *b, size_t len, char *out)
{
	static const char x[] = "0123456789abcdef";
	for(size_t i = 0; i < len; i++) {
		out[2 * i] = x[b[i] >> 4];
		out[2 * i + 1] = x[b[i] & 15];
	}
	out[2 * len] = '\0';
}

static int checked_align(uint64_t x, uint64_t *out)
{
	if(x > UINT64_MAX - (BTR_BLOCK - 1)) {
		return 0;
	}
	*out = (x + BTR_BLOCK - 1) & ~(uint64_t)(BTR_BLOCK - 1);
	return 1;
}

uint64_t btr_index_len(const btr_header_t *h)
{
	/* no overflow: the caps in btr_header_decode keep this below 2^34 */
	return BTR_HDR + h->nchunks * BTR_ENT + h->entries_len + h->blob_len;
}

uint64_t btr_image_base(const btr_header_t *h)
{
	uint64_t a = 0;
	checked_align(btr_index_len(h), &a);
	return a;
}

uint64_t btr_cache_len(const btr_header_t *h)
{
	return btr_image_base(h) + h->image_len;
}

int btr_header_decode(const unsigned char *b, size_t len, btr_header_t *h, char *err)
{
	unsigned char sum[32];
	if(len < BTR_HDR) {
		return fail(err, "truncated header");
	}
	if(memcmp(b, MAGIC, 8) != 0) {
		return fail(err, "not a btrpkg file");
	}
	if(u32_at(b + 8) != BTR_VERSION) {
		return fail(err, "btrpkg format version %u, this reader reads version %u", u32_at(b + 8), BTR_VERSION);
	}
	if(b[12] != 1) {
		return fail(err, "unknown hash algorithm %u", b[12]);
	}
	btr_sha256(b, 224, sum);
	if(memcmp(sum, b + 224, 32) != 0) {
		return fail(err, "header checksum mismatch: corrupt or tampered header");
	}
	if(!all_zero(b + 13, 3) || !all_zero(b + 160, 64)) {
		return fail(err, "reserved header bytes are set");
	}
	h->nchunks = u64_at(b + 16);
	h->image_len = u64_at(b + 24);
	h->entries_len = u64_at(b + 32);
	h->entries_raw_len = u64_at(b + 40);
	h->blob_len = u64_at(b + 48);
	h->blob_raw_len = u64_at(b + 56);
	memcpy(h->table_hash, b + 64, 32);
	memcpy(h->entries_hash, b + 96, 32);
	memcpy(h->blob_hash, b + 128, 32);
	memcpy(h->id, b + 224, 32);
	if(h->nchunks > MAX_SECTION / BTR_ENT) {
		return fail(err, "too many chunks");
	}
	if(h->image_len > h->nchunks * BTR_MAX_EXTENT) {
		return fail(err, "image longer than its chunks");
	}
	if(h->entries_len >= MAX_SECTION || h->blob_len >= MAX_SECTION) {
		return fail(err, "section too large");
	}
	if(h->entries_raw_len > MAX_ENTRIES_RAW || h->blob_raw_len > MAX_BLOB_RAW) {
		return fail(err, "section too large");
	}
	return 0;
}

static int decode_table(const unsigned char *b, const btr_header_t *h, btr_chunk_t *out, char *err)
{
	uint64_t next = 0;
	for(uint64_t i = 0; i < h->nchunks; i++) {
		const unsigned char *e = b + i * BTR_ENT;
		btr_chunk_t *c = &out[i];
		c->image_off = u64_at(e);
		c->unencoded_len = u32_at(e + 8);
		c->encoded_len = u32_at(e + 12);
		c->compression = e[16];
		memcpy(c->stored, e + 24, 32);
		memcpy(c->raw, e + 56, 32);
		if(!all_zero(e + 17, 7)) {
			return fail(err, "chunk %llu: reserved bytes are set", (unsigned long long)i);
		}
		if(c->image_off != next) {
			return fail(err, "chunk %llu: not where the previous chunk ends", (unsigned long long)i);
		}
		if(c->unencoded_len == 0 || c->unencoded_len > BTR_MAX_EXTENT || c->unencoded_len % BTR_BLOCK) {
			return fail(err, "chunk %llu: bad length", (unsigned long long)i);
		}
		switch(c->compression) {
			case BTR_COMP_NONE:
				if(c->encoded_len != c->unencoded_len || memcmp(c->stored, c->raw, 32) != 0) {
					return fail(err, "chunk %llu: bad raw chunk", (unsigned long long)i);
				}
				break;
			case BTR_COMP_ZSTD:
				/* btrfs only takes a compressed extent that is smaller than its data */
				if(c->encoded_len == 0 || c->encoded_len >= c->unencoded_len) {
					return fail(err, "chunk %llu: bad zstd chunk", (unsigned long long)i);
				}
				break;
			default:
				return fail(err, "chunk %llu: unknown compression %u", (unsigned long long)i, c->compression);
		}
		next += c->unencoded_len;
	}
	if(next != h->image_len) {
		return fail(err, "chunks don't cover the image");
	}
	return 0;
}

/* One zstd frame that decodes to exactly raw_len bytes. */
static unsigned char *decompress_exact(const unsigned char *z, size_t zlen, uint64_t raw_len,
		const char *what, char *err)
{
	size_t fs = ZSTD_findFrameCompressedSize(z, zlen);
	if(ZSTD_isError(fs) || fs != zlen) {
		fail(err, "%s: not exactly one zstd frame", what);
		return NULL;
	}
	unsigned char *out = malloc(raw_len ? raw_len : 1);
	if(!out) {
		fail(err, "%s: out of memory", what);
		return NULL;
	}
	ZSTD_DCtx *d = ZSTD_createDCtx();
	if(!d) {
		free(out);
		fail(err, "%s: out of memory", what);
		return NULL;
	}
	size_t n = ZSTD_decompressDCtx(d, out, raw_len, z, zlen);
	ZSTD_freeDCtx(d);
	if(ZSTD_isError(n) || n != raw_len) {
		free(out);
		fail(err, "%s decompressed to the wrong length", what);
		return NULL;
	}
	return out;
}

typedef struct {
	const unsigned char *b;
	size_t len, pos;
} reader_t;

static int take(reader_t *r, size_t n, const unsigned char **out)
{
	if(n > r->len - r->pos) {
		return -1;
	}
	*out = r->b + r->pos;
	r->pos += n;
	return 0;
}

static int rd_u8(reader_t *r, uint8_t *v)
{
	const unsigned char *p;
	if(take(r, 1, &p)) {
		return -1;
	}
	*v = p[0];
	return 0;
}

static int rd_u32(reader_t *r, uint32_t *v)
{
	const unsigned char *p;
	if(take(r, 4, &p)) {
		return -1;
	}
	*v = u32_at(p);
	return 0;
}

static int rd_u64(reader_t *r, uint64_t *v)
{
	const unsigned char *p;
	if(take(r, 8, &p)) {
		return -1;
	}
	*v = u64_at(p);
	return 0;
}

/* length-prefixed bytes, copied with a NUL after them */
static int rd_bytes(reader_t *r, unsigned char **out, size_t *len)
{
	uint32_t n;
	const unsigned char *p;
	if(rd_u32(r, &n) || take(r, n, &p)) {
		return -1;
	}
	unsigned char *s = malloc((size_t)n + 1);
	if(!s) {
		return -1;
	}
	memcpy(s, p, n);
	s[n] = '\0';
	*out = s;
	*len = n;
	return 0;
}

static void free_entries(btr_entry_t *e, size_t n)
{
	if(!e) {
		return;
	}
	for(size_t i = 0; i < n; i++) {
		free(e[i].path);
		free(e[i].target);
		for(uint32_t k = 0; e[i].xattrs && k < e[i].nxattrs; k++) {
			free(e[i].xattrs[k].name);
			free(e[i].xattrs[k].value);
		}
		free(e[i].xattrs);
	}
	free(e);
}

static int decode_entries(const unsigned char *b, size_t len, btr_entry_t **out, size_t *count, char *err)
{
	reader_t r = { b, len, 0 };
	uint32_t n;
	if(rd_u32(&r, &n)) {
		return fail(err, "truncated entries");
	}
	/* a bogus count can't make us allocate much: every entry takes at least MIN_ENTRY bytes */
	if(n > (len - 4) / MIN_ENTRY) {
		return fail(err, "truncated entries");
	}
	btr_entry_t *v = calloc(n ? n : 1, sizeof(*v));
	if(!v) {
		return fail(err, "out of memory");
	}
	size_t done = 0;
	for(; done < n; done++) {
		btr_entry_t *e = &v[done];
		uint64_t mtime;
		if(rd_u8(&r, &e->kind) || rd_u32(&r, &e->mode) || rd_u32(&r, &e->uid) || rd_u32(&r, &e->gid)
				|| rd_u64(&r, &mtime) || rd_u64(&r, &e->size) || rd_u64(&r, &e->data_off)
				|| rd_u8(&r, &e->small)) {
			goto truncated;
		}
		e->mtime = (int64_t)mtime;
		if(e->small > 1) {
			unsigned bad = e->small;
			free_entries(v, done + 1);
			return fail(err, "bad small flag %u", bad);
		}
		if(rd_bytes(&r, (unsigned char **)&e->path, &e->path_len)
				|| rd_bytes(&r, (unsigned char **)&e->target, &e->target_len)
				|| rd_u32(&r, &e->nxattrs)) {
			goto truncated;
		}
		if(e->nxattrs > (r.len - r.pos) / 8) {
			e->nxattrs = 0;
			goto truncated;
		}
		if(e->nxattrs) {
			e->xattrs = calloc(e->nxattrs, sizeof(*e->xattrs));
			if(!e->xattrs) {
				e->nxattrs = 0;
				goto truncated;
			}
			for(uint32_t k = 0; k < e->nxattrs; k++) {
				if(rd_bytes(&r, &e->xattrs[k].name, &e->xattrs[k].name_len)
						|| rd_bytes(&r, &e->xattrs[k].value, &e->xattrs[k].value_len)) {
					goto truncated;
				}
			}
		}
	}
	if(r.pos != len) {
		free_entries(v, n);
		return fail(err, "trailing bytes after the entries");
	}
	*out = v;
	*count = n;
	return 0;
truncated:
	free_entries(v, done + 1);
	return fail(err, "truncated entries");
}

/* A set of byte strings (pointers into the entries, which outlive it). */
typedef struct {
	const char **key;
	size_t *klen;
	size_t mask;
} strset_t;

static int set_init(strset_t *s, size_t n)
{
	size_t cap = 16;
	while(cap < 2 * n + 2) {
		cap <<= 1;
	}
	s->key = calloc(cap, sizeof(*s->key));
	s->klen = calloc(cap, sizeof(*s->klen));
	s->mask = cap - 1;
	return s->key && s->klen ? 0 : -1;
}

static void set_free(strset_t *s)
{
	free(s->key);
	free(s->klen);
}

static size_t hash_bytes(const char *p, size_t n)
{
	uint64_t h = 1469598103934665603ULL;
	for(size_t i = 0; i < n; i++) {
		h = (h ^ (unsigned char)p[i]) * 1099511628211ULL;
	}
	return (size_t)h;
}

static int set_has(const strset_t *s, const char *p, size_t n)
{
	for(size_t i = hash_bytes(p, n) & s->mask; s->key[i]; i = (i + 1) & s->mask) {
		if(s->klen[i] == n && memcmp(s->key[i], p, n) == 0) {
			return 1;
		}
	}
	return 0;
}

static void set_add(strset_t *s, const char *p, size_t n)
{
	size_t i = hash_bytes(p, n) & s->mask;
	for(; s->key[i]; i = (i + 1) & s->mask) {
		if(s->klen[i] == n && memcmp(s->key[i], p, n) == 0) {
			return;
		}
	}
	s->key[i] = p;
	s->klen[i] = n;
}

static int safe_path(const char *p, size_t n)
{
	if(n == 0 || p[0] == '/' || memchr(p, 0, n)) {
		return 0;
	}
	size_t start = 0;
	for(size_t i = 0; i <= n; i++) {
		if(i == n || p[i] == '/') {
			size_t len = i - start;
			if(len == 0 || (len == 1 && p[start] == '.') || (len == 2 && p[start] == '.' && p[start + 1] == '.')) {
				return 0;
			}
			start = i + 1;
		}
	}
	return 1;
}

/* Everything an installer relies on: safe paths, known kinds, data inside the image or blob, no
 * path that leads through a symlink or file of the same package, and hardlinks only to files the
 * package placed before. */
static int check_entries(const btr_entry_t *v, size_t n, uint64_t image_len, uint64_t blob_len, char *err)
{
	strset_t files = { 0 }, not_dirs = { 0 };
	int ret = -1;
	if(set_init(&files, n) || set_init(&not_dirs, n)) {
		fail(err, "out of memory");
		goto out;
	}
	for(size_t i = 0; i < n; i++) {
		const btr_entry_t *e = &v[i];
		const char *name = e->path;
		if(!safe_path(e->path, e->path_len)) {
			fail(err, "unsafe path \"%.200s\"", name);
			goto out;
		}
		for(size_t k = 0; k < e->path_len; k++) {
			if(e->path[k] == '/' && set_has(&not_dirs, e->path, k)) {
				fail(err, "%.200s: leads through a symlink or file of the package", name);
				goto out;
			}
		}
		if(memchr(e->target, 0, e->target_len)) {
			fail(err, "%.200s: NUL in link target", name);
			goto out;
		}
		for(uint32_t k = 0; k < e->nxattrs; k++) {
			if(e->xattrs[k].name_len == 0 || memchr(e->xattrs[k].name, 0, e->xattrs[k].name_len)) {
				fail(err, "%.200s: bad xattr name", name);
				goto out;
			}
		}
		uint64_t a, end;
		switch(e->kind) {
			case BTR_K_DIR:
				break;
			case BTR_K_SYMLINK:
				if(e->target_len == 0) {
					fail(err, "%.200s: symlink without target", name);
					goto out;
				}
				break;
			case BTR_K_HARDLINK:
				if(!safe_path(e->target, e->target_len) || !set_has(&files, e->target, e->target_len)) {
					fail(err, "%.200s: hardlink to something other than an earlier file of the package", name);
					goto out;
				}
				break;
			case BTR_K_FILE:
				if(e->small) {
					if(e->data_off > UINT64_MAX - e->size || e->data_off + e->size > blob_len) {
						fail(err, "%.200s: small file outside the blob", name);
						goto out;
					}
				} else if(e->size == 0 || e->data_off % BTR_BLOCK || !checked_align(e->size, &a)
						|| e->data_off > UINT64_MAX - a || (end = e->data_off + a) > image_len) {
					fail(err, "%.200s: file outside the image", name);
					goto out;
				}
				break;
			default:
				fail(err, "%.200s: unknown entry kind %u", name, e->kind);
				goto out;
		}
		switch(e->kind) {
			case BTR_K_FILE:
				set_add(&files, e->path, e->path_len);
				set_add(&not_dirs, e->path, e->path_len);
				break;
			case BTR_K_SYMLINK:
			case BTR_K_HARDLINK:
				set_add(&not_dirs, e->path, e->path_len);
				break;
			default:
				if(set_has(&not_dirs, e->path, e->path_len)) {
					fail(err, "%.200s: a directory where the package has a file or symlink", name);
					goto out;
				}
		}
	}
	ret = 0;
out:
	set_free(&files);
	set_free(&not_dirs);
	return ret;
}

void btr_index_free(btr_index_t *idx)
{
	if(!idx) {
		return;
	}
	free(idx->chunks);
	free_entries(idx->entries, idx->nentries);
	free(idx->small);
	free(idx);
}

int btr_index_parse(const unsigned char *buf, size_t len, const unsigned char *expected_id,
		btr_index_t **out, char *err)
{
	unsigned char sum[32];
	btr_index_t *idx = calloc(1, sizeof(*idx));
	unsigned char *raw = NULL;
	if(!idx) {
		return fail(err, "out of memory");
	}
	btr_header_t *h = &idx->hdr;
	if(btr_header_decode(buf, len, h, err)) {
		goto bad;
	}
	if(expected_id && memcmp(h->id, expected_id, 32) != 0) {
		char a[65], b[65];
		btr_hex(h->id, 32, a);
		btr_hex(expected_id, 32, b);
		fail(err, "index %s is not the expected %s", a, b);
		goto bad;
	}
	if(btr_index_len(h) > len) {
		fail(err, "truncated index");
		goto bad;
	}
	const unsigned char *table = buf + BTR_HDR;
	const unsigned char *ez = table + h->nchunks * BTR_ENT;
	const unsigned char *bz = ez + h->entries_len;

	btr_sha256(table, h->nchunks * BTR_ENT, sum);
	if(memcmp(sum, h->table_hash, 32) != 0) {
		fail(err, "chunk table checksum mismatch");
		goto bad;
	}
	idx->chunks = calloc(h->nchunks ? h->nchunks : 1, sizeof(*idx->chunks));
	if(!idx->chunks) {
		fail(err, "out of memory");
		goto bad;
	}
	if(decode_table(table, h, idx->chunks, err)) {
		goto bad;
	}

	btr_sha256(ez, h->entries_len, sum);
	if(memcmp(sum, h->entries_hash, 32) != 0) {
		fail(err, "entries checksum mismatch");
		goto bad;
	}
	if(!(raw = decompress_exact(ez, h->entries_len, h->entries_raw_len, "entries", err))) {
		goto bad;
	}
	if(decode_entries(raw, h->entries_raw_len, &idx->entries, &idx->nentries, err)) {
		goto bad;
	}
	free(raw);
	raw = NULL;

	btr_sha256(bz, h->blob_len, sum);
	if(memcmp(sum, h->blob_hash, 32) != 0) {
		fail(err, "small-file blob checksum mismatch");
		goto bad;
	}
	if(!(idx->small = decompress_exact(bz, h->blob_len, h->blob_raw_len, "small-file blob", err))) {
		goto bad;
	}
	idx->small_len = h->blob_raw_len;
	if(check_entries(idx->entries, idx->nentries, h->image_len, idx->small_len, err)) {
		goto bad;
	}
	*out = idx;
	return 0;
bad:
	free(raw);
	btr_index_free(idx);
	return -1;
}

int btr_check_chunk(size_t i, const btr_chunk_t *c, const unsigned char *d, size_t len, char *err)
{
	unsigned char sum[32];
	if(len != c->encoded_len) {
		return fail(err, "chunk %zu is corrupt", i);
	}
	btr_sha256(d, len, sum);
	if(memcmp(sum, c->stored, 32) != 0) {
		return fail(err, "chunk %zu is corrupt", i);
	}
	switch(c->compression) {
		case BTR_COMP_ZSTD: {
			static const unsigned char zmagic[4] = { 0x28, 0xb5, 0x2f, 0xfd };
			if(len < 5 || memcmp(d, zmagic, 4) != 0 || (d[4] & 0x07)) {
				return fail(err, "chunk %zu: not a plain zstd frame", i);
			}
			size_t fs = ZSTD_findFrameCompressedSize(d, len);
			if(ZSTD_isError(fs) || fs != len) {
				return fail(err, "chunk %zu: not exactly one zstd frame", i);
			}
			unsigned long long cs = ZSTD_getFrameContentSize(d, len);
			if(cs == ZSTD_CONTENTSIZE_UNKNOWN || cs == ZSTD_CONTENTSIZE_ERROR || cs != c->unencoded_len) {
				return fail(err, "chunk %zu: wrong content size", i);
			}
			return 0;
		}
		case BTR_COMP_NONE:
			if(memcmp(c->stored, c->raw, 32) != 0 || len != c->unencoded_len) {
				return fail(err, "chunk %zu: its data doesn't match the unencoded hash", i);
			}
			return 0;
		default:
			return fail(err, "chunk %zu: unknown compression %u", i, c->compression);
	}
}

/* ---- signatures (sign.rs) ---- */

/* At most this much of a .pub, .sig or revoked file is read. */
#define MAX_TEXT 65536

/* The decoded payload of a signify file: the base64 line after "untrusted comment: ...". */
static int read_blob(const char *text, size_t len, const char *what, unsigned char *out, size_t *outlen, char *err)
{
	static const char prefix[] = "untrusted comment: ";
	const char *nl = memchr(text, '\n', len);
	if(len < sizeof(prefix) - 1 || memcmp(text, prefix, sizeof(prefix) - 1) != 0 || !nl) {
		return fail(err, "%s: no comment line", what);
	}
	const char *line = nl + 1;
	const char *end = memchr(line, '\n', len - (size_t)(line - text));
	if(!end) {
		end = text + len;
	}
	/* trim like Rust's str::trim (ASCII whitespace is all that can occur in base64 text) */
	while(line < end && (*line == ' ' || *line == '\t' || *line == '\r')) {
		line++;
	}
	while(end > line && (end[-1] == ' ' || end[-1] == '\t' || end[-1] == '\r')) {
		end--;
	}
	if(line == end) {
		return fail(err, "%s: no key line", what);
	}
	size_t dl = *outlen;
	if(base64_decode(out, &dl, (const unsigned char *)line, (size_t)(end - line)) != 0) {
		return fail(err, "%s: bad base64", what);
	}
	if(dl < 2 || out[0] != 'E' || out[1] != 'd') {
		return fail(err, "%s: not an Ed25519 signify file", what);
	}
	*outlen = dl;
	return 0;
}

static ssize_t read_text(const char *path, char *buf, size_t cap)
{
	int fd = open(path, O_RDONLY | O_CLOEXEC);
	if(fd < 0) {
		return -1;
	}
	size_t n = 0;
	while(n < cap) {
		ssize_t r = read(fd, buf + n, cap - n);
		if(r < 0 && errno == EINTR) {
			continue;
		}
		if(r <= 0) {
			break;
		}
		n += (size_t)r;
	}
	close(fd);
	return (ssize_t)n;
}

static int unhex8(const char *s, size_t n, unsigned char out[8])
{
	if(n != 16) {
		return -1;
	}
	for(size_t i = 0; i < 16; i++) {
		char c = s[i];
		int v = c >= '0' && c <= '9' ? c - '0' : c >= 'a' && c <= 'f' ? c - 'a' + 10
			: c >= 'A' && c <= 'F' ? c - 'A' + 10 : -1;
		if(v < 0) {
			return -1;
		}
		if(i % 2 == 0) {
			out[i / 2] = (unsigned char)(v << 4);
		} else {
			out[i / 2] |= (unsigned char)v;
		}
	}
	return 0;
}

static int cmp_names(const struct dirent **a, const struct dirent **b)
{
	return strcmp((*a)->d_name, (*b)->d_name);
}

static int ed25519_verify(const unsigned char pk[32], const unsigned char *msg, size_t len, const unsigned char sig[64])
{
	int ok = 0;
	EVP_PKEY *key = EVP_PKEY_new_raw_public_key(EVP_PKEY_ED25519, NULL, pk, 32);
	EVP_MD_CTX *ctx = EVP_MD_CTX_new();
	if(key && ctx && EVP_DigestVerifyInit(ctx, NULL, NULL, NULL, key) == 1) {
		ok = EVP_DigestVerify(ctx, sig, 64, msg, len) == 1;
	}
	EVP_MD_CTX_free(ctx);
	EVP_PKEY_free(key);
	return ok;
}

int btr_sig_verify(const unsigned char *hdr, const char *sigtext, size_t siglen,
		const char *const *keydirs, char *keypath, char *err)
{
	unsigned char sig[128];
	size_t sl = sizeof(sig);
	char *text = NULL;
	int ret = -1, found = 0, revoked = 0;
	unsigned char pk[32];
	char path[PATH_MAX];
	char kn[17];

	if(read_blob(sigtext, siglen, "signature", sig, &sl, err)) {
		return -1;
	}
	if(sl != 74) {
		return fail(err, "not a signify signature");
	}
	btr_hex(sig + 2, 8, kn);
	if(!(text = malloc(MAX_TEXT))) {
		return fail(err, "out of memory");
	}
	/* The keyring: every *.pub (first one wins per key number, directories in order, names
	 * sorted bytewise within one) minus the key numbers in any "revoked" file. A malformed key
	 * or revoked file is an error, as in sign.rs. */
	for(const char *const *d = keydirs; d && *d; d++) {
		struct dirent **names = NULL;
		int n = scandir(*d, &names, NULL, cmp_names);
		if(n < 0) {
			continue;
		}
		for(int i = 0; i < n; i++) {
			const char *nm = names[i]->d_name;
			size_t nl = strlen(nm);
			int is_rev = strcmp(nm, "revoked") == 0;
			int is_pub = nl > 4 && strcmp(nm + nl - 4, ".pub") == 0;
			if((!is_rev && !is_pub) || ret == -2) {
				continue;
			}
			snprintf(path, sizeof(path), "%s/%s", *d, nm);
			ssize_t tl = read_text(path, text, MAX_TEXT);
			if(tl < 0) {
				fail(err, "%s: %s", path, strerror(errno));
				ret = -2;
				continue;
			}
			if(is_rev) {
				for(ssize_t p = 0; p < tl;) {
					const char *ln = text + p;
					const char *e = memchr(ln, '\n', (size_t)(tl - p));
					size_t ll = e ? (size_t)(e - ln) : (size_t)(tl - p);
					p += (ssize_t)ll + 1;
					const char *hash = memchr(ln, '#', ll);
					if(hash) {
						ll = (size_t)(hash - ln);
					}
					while(ll && (*ln == ' ' || *ln == '\t' || *ln == '\r')) {
						ln++;
						ll--;
					}
					while(ll && (ln[ll - 1] == ' ' || ln[ll - 1] == '\t' || ln[ll - 1] == '\r')) {
						ll--;
					}
					if(!ll) {
						continue;
					}
					unsigned char k[8];
					if(unhex8(ln, ll, k)) {
						fail(err, "%s: bad key number \"%.*s\"", path, (int)(ll > 40 ? 40 : ll), ln);
						ret = -2;
						break;
					}
					if(memcmp(k, sig + 2, 8) == 0) {
						revoked = 1;
					}
				}
			} else {
				unsigned char kd[128];
				size_t kl = sizeof(kd);
				if(read_blob(text, (size_t)tl, path, kd, &kl, err)) {
					ret = -2;
					continue;
				}
				if(kl != 42) {
					fail(err, "%s: not a signify public key", path);
					ret = -2;
					continue;
				}
				if(!found && memcmp(kd + 2, sig + 2, 8) == 0) {
					memcpy(pk, kd + 10, 32);
					if(keypath) {
						snprintf(keypath, PATH_MAX, "%s", path);
					}
					found = 1;
				}
			}
		}
		for(int i = 0; i < n; i++) {
			free(names[i]);
		}
		free(names);
	}
	free(text);
	if(ret == -2) {
		return -1;
	}
	if(revoked) {
		return fail(err, "signed with revoked key %s", kn);
	}
	if(!found) {
		return fail(err, "signed with unknown key %s", kn);
	}
	if(!ed25519_verify(pk, hdr, BTR_HDR, sig + 10)) {
		return fail(err, "bad signature (key %s)", kn);
	}
	return 0;
}
