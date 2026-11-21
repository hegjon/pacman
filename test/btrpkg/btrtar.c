/*
 * btrtar: list an archive the way libalpm sees it, for comparing a btrpkg cache file (read
 * through btrstream.c) with the original .pkg.tar.zst (read by libarchive).
 *
 *   btrtar FILE          one line per entry: path type mode uid gid size mtime link xattrs sha256
 *   btrtar --skip FILE   the same without reading file data (exercises the skip path)
 */
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include <archive.h>
#include <archive_entry.h>
#include <openssl/evp.h>

#include "btrpkg.h"
#include "btrstream.h"

int main(int argc, char **argv)
{
	int skip = argc == 3 && strcmp(argv[1], "--skip") == 0;
	const char *path = argv[argc - 1];
	if(argc < 2 || (argc == 3 && !skip)) {
		fprintf(stderr, "usage: btrtar [--skip] FILE\n");
		return 2;
	}
	int fd = open(path, O_RDONLY | O_CLOEXEC);
	struct stat st;
	if(fd < 0 || fstat(fd, &st)) {
		perror(path);
		return 2;
	}
	struct archive *a = archive_read_new();
	archive_read_support_filter_all(a);
	archive_read_support_format_all(a);
	char err[BTR_ERRLEN];
	if(_alpm_btr_is_cache_file(fd)) {
		if(_alpm_btr_archive_open(a, fd, (uint64_t)st.st_size, err)) {
			fprintf(stderr, "%s: %s\n", path, err);
			return 1;
		}
	} else if(archive_read_open_fd(a, fd, 65536) != ARCHIVE_OK) {
		fprintf(stderr, "%s: %s\n", path, archive_error_string(a));
		return 1;
	}
	struct archive_entry *e;
	int r;
	static unsigned char buf[1 << 16];
	while((r = archive_read_next_header(a, &e)) == ARCHIVE_OK) {
		const char *link = archive_entry_hardlink(e);
		char type = 'f';
		if(link) {
			type = 'h';
		} else if(archive_entry_filetype(e) == AE_IFDIR) {
			type = 'd';
		} else if(archive_entry_filetype(e) == AE_IFLNK) {
			type = 'l';
			link = archive_entry_symlink(e);
		}
		printf("%s %c %o %lld %lld %lld %lld %s", archive_entry_pathname(e), type,
				(unsigned)archive_entry_perm(e), (long long)archive_entry_uid(e),
				(long long)archive_entry_gid(e), (long long)archive_entry_size(e),
				(long long)archive_entry_mtime(e), link ? link : "-");
		const char *xn;
		const void *xv;
		size_t xs;
		archive_entry_xattr_reset(e);
		while(archive_entry_xattr_next(e, &xn, &xv, &xs) == ARCHIVE_OK) {
			printf(" x:%s=", xn);
			for(size_t i = 0; i < xs; i++) {
				printf("%02x", ((const unsigned char *)xv)[i]);
			}
		}
		if(skip || type != 'f') {
			printf("\n");
			continue;
		}
		EVP_MD_CTX *c = EVP_MD_CTX_new();
		EVP_DigestInit_ex(c, EVP_sha256(), NULL);
		la_ssize_t n;
		while((n = archive_read_data(a, buf, sizeof(buf))) > 0) {
			EVP_DigestUpdate(c, buf, (size_t)n);
		}
		if(n < 0) {
			fprintf(stderr, "%s: %s\n", path, archive_error_string(a));
			return 1;
		}
		unsigned char h[32];
		EVP_DigestFinal_ex(c, h, NULL);
		EVP_MD_CTX_free(c);
		char hx[65];
		btr_hex(h, 32, hx);
		printf(" %s\n", hx);
	}
	if(r != ARCHIVE_EOF) {
		fprintf(stderr, "%s: %s\n", path, archive_error_string(a));
		return 1;
	}
	archive_read_free(a);
	close(fd);
	return 0;
}
