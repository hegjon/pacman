/*
 *  btrstream.c
 *
 *  A btrpkg cache file (index | padding | image, see btrpkg.h) read as a tar archive, so every
 *  libalpm path that reads packages through libarchive (loading, file lists, .INSTALL, mtree,
 *  changelog, extraction with backup files and .pacnew) works unchanged. The stream is made from
 *  the index: a pax header per entry (path, link, size, mtime, owner, xattrs), file data from
 *  the small-file blob or read from the image. Large files' data can be skipped without being
 *  read; add.c reflinks those from the image instead (_alpm_btr_large_file).
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

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <archive.h>

#include "btrpkg.h"
#include "btrstream.h"

#define BUFSZ (256 * 1024)
#define BLK 512

enum phase { P_HEADER, P_DATA, P_PAD, P_END, P_DONE };

struct btr_stream {
	struct archive *a;
	int fd;
	btr_index_t *idx;
	uint64_t image_base;
	size_t *by_path; /* large-file entries sorted by path */
	size_t nlarge;
	/* generator state */
	size_t cur;            /* current entry */
	enum phase ph;
	unsigned char *hdr;    /* headers of the current entry */
	size_t hdr_len, hdr_pos;
	uint64_t data_pos;     /* bytes of the current entry's data handed out */
	size_t pad_left;
	size_t end_left;
	unsigned char *buf;
	struct btr_stream *next; /* registry */
};

static struct btr_stream *registry;


/* ---- tar headers ---- */

static void octal(char *f, size_t n, uint64_t v)
{
	/* n-1 octal digits and a NUL; 0 when it doesn't fit (the pax header has the real value) */
	uint64_t max = 1;
	for(size_t i = 0; i < n - 1; i++) {
		max *= 8;
	}
	if(v >= max) {
		v = 0;
	}
	f[n - 1] = '\0';
	for(size_t i = n - 1; i-- > 0;) {
		f[i] = (char)('0' + (v & 7));
		v >>= 3;
	}
}

/* append a pax record "LEN key=value\n" where LEN counts the whole record */
static int pax_add(unsigned char **b, size_t *len, size_t *cap, const char *key,
		const void *val, size_t vlen)
{
	size_t base = strlen(key) + vlen + 3; /* ' ' '=' '\n' */
	size_t digits = 1, total;
	for(;;) {
		total = base + digits;
		size_t d = 1;
		for(size_t t = total; t >= 10; t /= 10) {
			d++;
		}
		if(d == digits) {
			break;
		}
		digits = d;
	}
	if(*len + total > *cap) {
		size_t nc = (*cap ? *cap * 2 : 1024) + total;
		unsigned char *nb = realloc(*b, nc);
		if(!nb) {
			return -1;
		}
		*b = nb;
		*cap = nc;
	}
	int n = snprintf((char *)*b + *len, total + 1, "%zu %s=", total, key);
	memcpy(*b + *len + n, val, vlen);
	(*b)[*len + total - 1] = '\n';
	*len += total;
	return 0;
}

static int pax_num(unsigned char **b, size_t *len, size_t *cap, const char *key, long long v)
{
	char s[32];
	int n = snprintf(s, sizeof(s), "%lld", v);
	return pax_add(b, len, cap, key, s, (size_t)n);
}

static void ustar(unsigned char *h, const char *name, size_t nlen, char type, uint32_t mode,
		uint32_t uid, uint32_t gid, uint64_t size, int64_t mtime, const char *link, size_t llen)
{
	memset(h, 0, BLK);
	memcpy(h, name, nlen > 99 ? 99 : nlen);
	octal((char *)h + 100, 8, mode & 07777);
	octal((char *)h + 108, 8, uid);
	octal((char *)h + 116, 8, gid);
	octal((char *)h + 124, 12, size);
	octal((char *)h + 136, 12, mtime < 0 ? 0 : (uint64_t)mtime);
	h[156] = (unsigned char)type;
	if(link) {
		memcpy(h + 157, link, llen > 99 ? 99 : llen);
	}
	memcpy(h + 257, "ustar", 6);
	memcpy(h + 263, "00", 2);
	memcpy(h + 265, "root", 4);
	memcpy(h + 297, "root", 4);
	memset(h + 148, ' ', 8);
	unsigned sum = 0;
	for(int i = 0; i < BLK; i++) {
		sum += h[i];
	}
	snprintf((char *)h + 148, 8, "%06o", sum);
	h[155] = ' ';
}

/* Build the headers of entry i into s->hdr. */
static int make_headers(struct btr_stream *s, size_t i)
{
	const btr_entry_t *e = &s->idx->entries[i];
	unsigned char *pax = NULL;
	size_t plen = 0, pcap = 0;
	char type;
	uint64_t size = 0;
	char *path = NULL;
	size_t path_len = e->path_len;

	switch(e->kind) {
		case BTR_K_FILE: type = '0'; size = e->size; break;
		case BTR_K_DIR: type = '5'; break;
		case BTR_K_SYMLINK: type = '2'; break;
		case BTR_K_HARDLINK: type = '1'; break;
		default: return -1;
	}
	/* tar names directories with a trailing slash; pacman's file lists do too */
	path = malloc(path_len + 2);
	if(!path) {
		return -1;
	}
	memcpy(path, e->path, path_len);
	if(e->kind == BTR_K_DIR) {
		path[path_len++] = '/';
	}
	path[path_len] = '\0';

	int bad = pax_add(&pax, &plen, &pcap, "path", path, path_len)
		|| pax_num(&pax, &plen, &pcap, "mtime", (long long)e->mtime)
		|| pax_num(&pax, &plen, &pcap, "uid", (long long)e->uid)
		|| pax_num(&pax, &plen, &pcap, "gid", (long long)e->gid)
		|| pax_num(&pax, &plen, &pcap, "size", (long long)size);
	if(!bad && (e->kind == BTR_K_SYMLINK || e->kind == BTR_K_HARDLINK)) {
		bad = pax_add(&pax, &plen, &pcap, "linkpath", e->target, e->target_len);
	}
	for(uint32_t k = 0; !bad && k < e->nxattrs; k++) {
		char key[512];
		if(e->xattrs[k].name_len > sizeof(key) - 14) {
			bad = 1;
			break;
		}
		snprintf(key, sizeof(key), "SCHILY.xattr.%s", (const char *)e->xattrs[k].name);
		bad = pax_add(&pax, &plen, &pcap, key, e->xattrs[k].value, e->xattrs[k].value_len);
	}
	if(bad) {
		free(pax);
		free(path);
		return -1;
	}
	size_t ppad = (BLK - plen % BLK) % BLK;
	size_t total = BLK + plen + ppad + BLK;
	unsigned char *h = calloc(1, total);
	if(!h) {
		free(pax);
		free(path);
		return -1;
	}
	ustar(h, "././@PaxHeader", 14, 'x', 0644, 0, 0, plen, 0, NULL, 0);
	memcpy(h + BLK, pax, plen);
	ustar(h + BLK + plen + ppad, path, path_len, type, e->mode, e->uid, e->gid, size,
			e->mtime, (e->kind == BTR_K_SYMLINK || e->kind == BTR_K_HARDLINK) ? e->target : NULL,
			e->target_len);
	free(pax);
	free(path);
	free(s->hdr);
	s->hdr = h;
	s->hdr_len = total;
	s->hdr_pos = 0;
	return 0;
}

static int is_large(const btr_entry_t *e)
{
	return e->kind == BTR_K_FILE && !e->small && e->size > 0;
}

/* Move to the next entry (or the end blocks). */
static int next_entry(struct btr_stream *s)
{
	if(s->cur >= s->idx->nentries) {
		s->ph = P_END;
		s->end_left = 2 * BLK;
		return 0;
	}
	if(make_headers(s, s->cur)) {
		archive_set_error(s->a, ENOMEM, "btrpkg: cannot make tar headers");
		return -1;
	}
	s->ph = P_HEADER;
	s->data_pos = 0;
	return 0;
}

static void after_data(struct btr_stream *s)
{
	const btr_entry_t *e = &s->idx->entries[s->cur];
	uint64_t size = e->kind == BTR_K_FILE ? e->size : 0;
	s->pad_left = (size_t)((BLK - size % BLK) % BLK);
	s->ph = P_PAD;
}

static la_ssize_t stream_read(struct archive *a, void *client, const void **out)
{
	struct btr_stream *s = client;
	size_t n = 0;
	(void)a;
	while(n < BUFSZ) {
		const btr_entry_t *e = s->cur < s->idx->nentries ? &s->idx->entries[s->cur] : NULL;
		switch(s->ph) {
			case P_HEADER: {
				size_t k = s->hdr_len - s->hdr_pos;
				if(k > BUFSZ - n) {
					k = BUFSZ - n;
				}
				memcpy(s->buf + n, s->hdr + s->hdr_pos, k);
				n += k;
				s->hdr_pos += k;
				if(s->hdr_pos == s->hdr_len) {
					if(e->kind == BTR_K_FILE && e->size > 0) {
						s->ph = P_DATA;
						/* hand large data out in reads of its own, so it can be skipped */
						if(is_large(e) && n > 0) {
							goto out;
						}
					} else {
						after_data(s);
					}
				}
				break;
			}
			case P_DATA: {
				uint64_t left = e->size - s->data_pos;
				size_t k = left > BUFSZ - n ? BUFSZ - n : (size_t)left;
				if(e->small) {
					memcpy(s->buf + n, s->idx->small + e->data_off + s->data_pos, k);
				} else {
					ssize_t r = pread(s->fd, s->buf + n, k, (off_t)(s->image_base + e->data_off + s->data_pos));
					if(r < 0 && errno == EINTR) {
						continue;
					}
					if(r <= 0) {
						archive_set_error(s->a, r < 0 ? errno : EIO, "btrpkg: reading %s: %s", e->path,
								r < 0 ? strerror(errno) : "cache file too short");
						return -1;
					}
					k = (size_t)r;
				}
				n += k;
				s->data_pos += k;
				if(s->data_pos == e->size) {
					after_data(s);
					if(is_large(e)) {
						goto out;
					}
				}
				break;
			}
			case P_PAD: {
				size_t k = s->pad_left > BUFSZ - n ? BUFSZ - n : s->pad_left;
				memset(s->buf + n, 0, k);
				n += k;
				s->pad_left -= k;
				if(!s->pad_left) {
					s->cur++;
					if(next_entry(s)) {
						return -1;
					}
					/* stop before a large file's headers too, so its data starts a read */
					if(s->ph == P_HEADER && is_large(&s->idx->entries[s->cur]) && n > 0) {
						goto out;
					}
				}
				break;
			}
			case P_END: {
				size_t k = s->end_left > BUFSZ - n ? BUFSZ - n : s->end_left;
				memset(s->buf + n, 0, k);
				n += k;
				s->end_left -= k;
				if(!s->end_left) {
					s->ph = P_DONE;
				}
				break;
			}
			case P_DONE:
				goto out;
		}
	}
out:
	*out = s->buf;
	return (la_ssize_t)n;
}

/* Skip within the current entry's data (and its padding), never past it. */
static la_int64_t stream_skip(struct archive *a, void *client, la_int64_t request)
{
	struct btr_stream *s = client;
	(void)a;
	if(request <= 0 || s->ph != P_DATA) {
		return 0;
	}
	const btr_entry_t *e = &s->idx->entries[s->cur];
	uint64_t left = e->size - s->data_pos;
	if((uint64_t)request < left) {
		s->data_pos += (uint64_t)request;
		return request;
	}
	s->data_pos = e->size;
	after_data(s);
	return (la_int64_t)left;
}

static int stream_close(struct archive *a, void *client)
{
	struct btr_stream *s = client;
	(void)a;
	for(struct btr_stream **p = &registry; *p; p = &(*p)->next) {
		if(*p == s) {
			*p = s->next;
			break;
		}
	}
	btr_index_free(s->idx);
	free(s->by_path);
	free(s->hdr);
	free(s->buf);
	free(s);
	return ARCHIVE_OK;
}

static const btr_entry_t *sort_base;

static int cmp_path(const void *x, const void *y)
{
	const btr_entry_t *a = &sort_base[*(const size_t *)x], *b = &sort_base[*(const size_t *)y];
	return strcmp(a->path, b->path);
}

int _alpm_btr_is_cache_file(int fd)
{
	unsigned char m[8];
	return pread(fd, m, 8, 0) == 8 && memcmp(m, "BTRPKG\0\0", 8) == 0;
}

/* Read the index at the start of fd. */
static btr_index_t *read_index(int fd, const unsigned char *expected_id, uint64_t file_size, char *err)
{
	unsigned char hb[BTR_HDR];
	btr_header_t h;
	btr_index_t *idx = NULL;
	if(pread(fd, hb, BTR_HDR, 0) != BTR_HDR) {
		snprintf(err, BTR_ERRLEN, "truncated header");
		return NULL;
	}
	if(btr_header_decode(hb, BTR_HDR, &h, err)) {
		return NULL;
	}
	uint64_t il = btr_index_len(&h);
	if(btr_cache_len(&h) > file_size) {
		snprintf(err, BTR_ERRLEN, "cache file shorter than its index says");
		return NULL;
	}
	unsigned char *b = malloc(il);
	if(!b) {
		snprintf(err, BTR_ERRLEN, "out of memory");
		return NULL;
	}
	uint64_t got = 0;
	while(got < il) {
		ssize_t r = pread(fd, b + got, il - got, (off_t)got);
		if(r < 0 && errno == EINTR) {
			continue;
		}
		if(r <= 0) {
			free(b);
			snprintf(err, BTR_ERRLEN, "reading the index: %s", r < 0 ? strerror(errno) : "short file");
			return NULL;
		}
		got += (uint64_t)r;
	}
	if(btr_index_parse(b, il, expected_id, &idx, err)) {
		idx = NULL;
	}
	free(b);
	return idx;
}

int _alpm_btr_validate(int fd, const unsigned char *expected_id, uint64_t file_size, char *err)
{
	btr_index_t *idx = read_index(fd, expected_id, file_size, err);
	if(!idx) {
		return -1;
	}
	btr_index_free(idx);
	return 0;
}

const char *const _alpm_btr_keydirs[] = { "/etc/btrpkg/keys", "/usr/share/btrpkg/keys", NULL };

int _alpm_btr_check_data(int fd, uint64_t file_size, char *err)
{
	btr_index_t *idx = read_index(fd, NULL, file_size, err);
	if(!idx) {
		return -1;
	}
	uint64_t base = btr_image_base(&idx->hdr);
	unsigned char *buf = malloc(BTR_MAX_EXTENT);
	int ret = 0;
	if(!buf) {
		snprintf(err, BTR_ERRLEN, "out of memory");
		btr_index_free(idx);
		return -1;
	}
	for(uint64_t i = 0; i < idx->hdr.nchunks && ret == 0; i++) {
		const btr_chunk_t *c = &idx->chunks[i];
		unsigned char h[32];
		size_t got = 0;
		if(c->unencoded_len > BTR_MAX_EXTENT) {
			snprintf(err, BTR_ERRLEN, "chunk %llu: too large", (unsigned long long)i);
			ret = -1;
			break;
		}
		while(got < c->unencoded_len) {
			ssize_t n = pread(fd, buf + got, c->unencoded_len - got, (off_t)(base + c->image_off + got));
			if(n < 0 && errno == EINTR) {
				continue;
			}
			if(n <= 0) {
				snprintf(err, BTR_ERRLEN, "chunk %llu: %s", (unsigned long long)i,
						n < 0 ? strerror(errno) : "short file");
				ret = -1;
				break;
			}
			got += (size_t)n;
		}
		if(ret == 0) {
			btr_sha256(buf, c->unencoded_len, h);
			if(memcmp(h, c->raw, 32) != 0) {
				snprintf(err, BTR_ERRLEN, "chunk %llu: data does not match the index", (unsigned long long)i);
				ret = -1;
			}
		}
	}
	free(buf);
	btr_index_free(idx);
	return ret;
}

int _alpm_btr_check_sig(int fd, const char *path, char *keypath, char *err)
{
	char sigpath[PATH_MAX], sig[4096];
	unsigned char hdr[BTR_HDR];
	ssize_t sl;
	if(snprintf(sigpath, sizeof(sigpath), "%s.sig", path) >= (int)sizeof(sigpath)) {
		snprintf(err, BTR_ERRLEN, "path too long");
		return -1;
	}
	int sfd = open(sigpath, O_RDONLY | O_CLOEXEC);
	if(sfd < 0) {
		if(errno == ENOENT) {
			return 1;
		}
		snprintf(err, BTR_ERRLEN, "opening the .sig: %s", strerror(errno));
		return -1;
	}
	sl = read(sfd, sig, sizeof(sig));
	close(sfd);
	if(sl <= 0) {
		snprintf(err, BTR_ERRLEN, "reading the .sig: %s", sl < 0 ? strerror(errno) : "empty");
		return -1;
	}
	if(pread(fd, hdr, BTR_HDR, 0) != BTR_HDR) {
		snprintf(err, BTR_ERRLEN, "truncated header");
		return -1;
	}
	return btr_sig_verify(hdr, sig, (size_t)sl, _alpm_btr_keydirs, keypath, err) == 0 ? 0 : -1;
}

int _alpm_btr_archive_open(struct archive *a, int fd, uint64_t file_size, char *err)
{
	struct btr_stream *s = calloc(1, sizeof(*s));
	if(!s) {
		snprintf(err, BTR_ERRLEN, "out of memory");
		return -1;
	}
	s->a = a;
	s->fd = fd;
	if(!(s->idx = read_index(fd, NULL, file_size, err)) || !(s->buf = malloc(BUFSZ))) {
		if(s->idx) {
			snprintf(err, BTR_ERRLEN, "out of memory");
		}
		btr_index_free(s->idx);
		free(s);
		return -1;
	}
	s->image_base = btr_image_base(&s->idx->hdr);
	s->by_path = malloc((s->idx->nentries ? s->idx->nentries : 1) * sizeof(size_t));
	if(!s->by_path) {
		btr_index_free(s->idx);
		free(s->buf);
		free(s);
		snprintf(err, BTR_ERRLEN, "out of memory");
		return -1;
	}
	for(size_t i = 0; i < s->idx->nentries; i++) {
		if(is_large(&s->idx->entries[i])) {
			s->by_path[s->nlarge++] = i;
		}
	}
	sort_base = s->idx->entries;
	qsort(s->by_path, s->nlarge, sizeof(size_t), cmp_path);
	if(next_entry(s)) {
		btr_index_free(s->idx);
		free(s->by_path);
		free(s->buf);
		free(s);
		snprintf(err, BTR_ERRLEN, "out of memory");
		return -1;
	}
	s->next = registry;
	registry = s;
	archive_read_set_callback_data(a, s);
	archive_read_set_read_callback(a, stream_read);
	archive_read_set_skip_callback(a, stream_skip);
	archive_read_set_close_callback(a, stream_close);
	if(archive_read_open1(a) != ARCHIVE_OK) {
		/* libarchive calls the close callback on failure */
		snprintf(err, BTR_ERRLEN, "%s", archive_error_string(a) ? archive_error_string(a) : "libarchive error");
		return -1;
	}
	return 0;
}

int _alpm_btr_large_file(struct archive *a, const char *entryname, int *fd, uint64_t *off,
		uint64_t *size)
{
	for(struct btr_stream *s = registry; s; s = s->next) {
		if(s->a != a) {
			continue;
		}
		size_t lo = 0, hi = s->nlarge;
		while(lo < hi) {
			size_t mid = lo + (hi - lo) / 2;
			const btr_entry_t *e = &s->idx->entries[s->by_path[mid]];
			int c = strcmp(e->path, entryname);
			if(c == 0) {
				/* only while the stream is at this entry's data, not read yet */
				if(s->ph != P_DATA || s->cur != s->by_path[mid] || s->data_pos != 0) {
					return 0;
				}
				*fd = s->fd;
				*off = s->image_base + e->data_off;
				*size = e->size;
				return 1;
			}
			if(c < 0) {
				lo = mid + 1;
			} else {
				hi = mid;
			}
		}
		return 0;
	}
	return 0;
}
