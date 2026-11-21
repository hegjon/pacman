/*
 * btrdump: test driver for lib/libalpm/btrpkg.c.
 *
 *   btrdump FILE                     the parsed index as text (same output as `btrpkg dump FILE`)
 *   btrdump --id HEX FILE            the same, requiring the header ID
 *   btrdump --verify SIG DIR FILE    check SIG (signify) over FILE's header with the keys in DIR
 *   btrdump --mutate FILE            flip every bit of the index and cut it at every length;
 *                                    every variant must be rejected (exit 1 otherwise)
 *   btrdump --chunks TRANSPORT       check every chunk of a transport file (.pkg.btr)
 */
#include <inttypes.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "btrpkg.h"

static unsigned char *slurp(const char *path, size_t *len)
{
	FILE *f = fopen(path, "rb");
	if(!f) {
		perror(path);
		exit(2);
	}
	size_t cap = 1 << 20, n = 0;
	unsigned char *b = malloc(cap);
	size_t r;
	while(b && (r = fread(b + n, 1, cap - n, f)) > 0) {
		n += r;
		if(n == cap) {
			cap *= 2;
			b = realloc(b, cap);
		}
	}
	fclose(f);
	if(!b) {
		fprintf(stderr, "out of memory\n");
		exit(2);
	}
	*len = n;
	return b;
}

static void hexout(FILE *o, const unsigned char *b, size_t n)
{
	for(size_t i = 0; i < n; i++) {
		fprintf(o, "%02x", b[i]);
	}
}

static void dump(const btr_index_t *x)
{
	const btr_header_t *h = &x->hdr;
	FILE *o = stdout;
	fputs("id ", o);
	hexout(o, h->id, 32);
	fprintf(o, "\nheader %" PRIu64 " %" PRIu64 " %" PRIu64 " %" PRIu64 " %" PRIu64 " %" PRIu64 " index %" PRIu64 " base %" PRIu64 "\n",
			h->nchunks, h->image_len, h->entries_len, h->entries_raw_len, h->blob_len, h->blob_raw_len,
			btr_index_len(h), btr_image_base(h));
	for(uint64_t i = 0; i < h->nchunks; i++) {
		const btr_chunk_t *c = &x->chunks[i];
		fprintf(o, "c %" PRIu64 " %u %u %u ", c->image_off, c->unencoded_len, c->encoded_len, c->compression);
		hexout(o, c->stored, 32);
		fputc(' ', o);
		hexout(o, c->raw, 32);
		fputc('\n', o);
	}
	for(size_t i = 0; i < x->nentries; i++) {
		const btr_entry_t *e = &x->entries[i];
		fprintf(o, "e %u %u %u %u %" PRId64 " %" PRIu64 " %" PRIu64 " %u ", e->kind, e->mode, e->uid, e->gid,
				e->mtime, e->size, e->data_off, e->small);
		hexout(o, (const unsigned char *)e->path, e->path_len);
		fputc(' ', o);
		hexout(o, (const unsigned char *)e->target, e->target_len);
		fprintf(o, " %u", e->nxattrs);
		for(uint32_t k = 0; k < e->nxattrs; k++) {
			fputc(' ', o);
			hexout(o, e->xattrs[k].name, e->xattrs[k].name_len);
			fputc('=', o);
			hexout(o, e->xattrs[k].value, e->xattrs[k].value_len);
		}
		fputc('\n', o);
	}
	unsigned char s[32];
	btr_sha256(x->small, x->small_len, s);
	fprintf(o, "small %zu ", x->small_len);
	hexout(o, s, 32);
	fputc('\n', o);
}

static unsigned char *bufs[4];
static int nbufs;

static unsigned char *load(const char *path, size_t *len)
{
	return bufs[nbufs++] = slurp(path, len);
}

static int finish(int code)
{
	while(nbufs) {
		free(bufs[--nbufs]);
	}
	return code;
}

static int run(int argc, char **argv);

int main(int argc, char **argv)
{
	return finish(run(argc, argv));
}

static int run(int argc, char **argv)
{
	char err[BTR_ERRLEN];
	btr_index_t *x = NULL;
	size_t len;

	if(argc == 2) {
		unsigned char *b = load(argv[1], &len);
		if(btr_index_parse(b, len, NULL, &x, err)) {
			fprintf(stderr, "%s: %s\n", argv[1], err);
			return 1;
		}
		dump(x);
		btr_index_free(x);
		return 0;
	}
	if(argc == 4 && strcmp(argv[1], "--id") == 0) {
		unsigned char id[32];
		if(strlen(argv[2]) != 64) {
			fprintf(stderr, "--id wants 64 hex digits\n");
			return 2;
		}
		for(int i = 0; i < 32; i++) {
			unsigned v;
			if(sscanf(argv[2] + 2 * i, "%2x", &v) != 1) {
				return 2;
			}
			id[i] = (unsigned char)v;
		}
		unsigned char *b = load(argv[3], &len);
		if(btr_index_parse(b, len, id, &x, err)) {
			fprintf(stderr, "%s: %s\n", argv[3], err);
			return 1;
		}
		dump(x);
		btr_index_free(x);
		return 0;
	}
	if(argc == 5 && strcmp(argv[1], "--verify") == 0) {
		size_t sl;
		unsigned char *sig = load(argv[2], &sl);
		unsigned char *b = load(argv[4], &len);
		const char *dirs[] = { argv[3], NULL };
		char key[PATH_MAX];
		if(len < BTR_HDR || btr_sig_verify(b, (const char *)sig, sl, dirs, key, err)) {
			fprintf(stderr, "%s: %s\n", argv[2], len < BTR_HDR ? "file too short" : err);
			return 1;
		}
		printf("good signature, key %s\n", key);
		return 0;
	}
	if(argc == 3 && strcmp(argv[1], "--mutate") == 0) {
		unsigned char *b = load(argv[2], &len);
		if(btr_index_parse(b, len, NULL, &x, err)) {
			fprintf(stderr, "%s: %s\n", argv[2], err);
			return 1;
		}
		size_t il = (size_t)btr_index_len(&x->hdr);
		btr_index_free(x);
		unsigned char *m = bufs[nbufs++] = malloc(il);
		memcpy(m, b, il);
		size_t accepted = 0, tried = 0;
		for(size_t i = 0; i < il * 8; i++) {
			m[i / 8] ^= (unsigned char)(1 << (i % 8));
			if(btr_index_parse(m, il, NULL, &x, err) == 0) {
				accepted++;
				fprintf(stderr, "accepted with bit %zu flipped\n", i);
				btr_index_free(x);
			}
			m[i / 8] ^= (unsigned char)(1 << (i % 8));
			tried++;
		}
		for(size_t n = 0; n < il; n++) {
			unsigned char *t = malloc(n ? n : 1);
			memcpy(t, m, n);
			if(btr_index_parse(t, n, NULL, &x, err) == 0) {
				accepted++;
				fprintf(stderr, "accepted cut at %zu\n", n);
				btr_index_free(x);
			}
			free(t);
			tried++;
		}
		printf("%s: %zu variants, %zu accepted\n", argv[2], tried, accepted);
		return accepted ? 1 : 0;
	}
	if(argc == 3 && strcmp(argv[1], "--chunks") == 0) {
		unsigned char *b = load(argv[2], &len);
		if(btr_index_parse(b, len, NULL, &x, err)) {
			fprintf(stderr, "%s: %s\n", argv[2], err);
			return 1;
		}
		uint64_t off = btr_index_len(&x->hdr);
		for(uint64_t i = 0; i < x->hdr.nchunks; i++) {
			const btr_chunk_t *c = &x->chunks[i];
			if(off + c->encoded_len > len || btr_check_chunk(i, c, b + off, c->encoded_len, err)) {
				fprintf(stderr, "%s: %s\n", argv[2], off + c->encoded_len > len ? "truncated" : err);
				btr_index_free(x);
				return 1;
			}
			off += c->encoded_len;
		}
		printf("%s: %" PRIu64 " chunks ok\n", argv[2], x->hdr.nchunks);
		btr_index_free(x);
		return 0;
	}
	fprintf(stderr, "usage: btrdump [--id HEX] FILE | --verify SIG DIR FILE | --mutate FILE | --chunks TRANSPORT\n");
	return 2;
}
