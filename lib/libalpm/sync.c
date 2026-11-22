/*
 *  sync.c
 *
 *  Copyright (c) 2006-2025 Pacman Development Team <pacman-dev@lists.archlinux.org>
 *  Copyright (c) 2002-2006 by Judd Vinet <jvinet@zeroflux.org>
 *  Copyright (c) 2005 by Aurelien Foret <orelien@chez.com>
 *  Copyright (c) 2005 by Christian Hamar <krics@linuxforum.hu>
 *  Copyright (c) 2005, 2006 by Miklos Vajna <vmiklos@frugalware.org>
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

#include <sys/types.h> /* off_t */
#include <stdbool.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <stdint.h> /* intmax_t */
#include <unistd.h>
#include <limits.h>

/* libalpm */
#include "sync.h"
#include "alpm_list.h"
#include "log.h"
#include "package.h"
#include "db.h"
#include "deps.h"
#include "conflict.h"
#include "trans.h"
#include "add.h"
#include "util.h"
#include "handle.h"
#include "alpm.h"
#include "dload.h"
#include "remove.h"
#include "diskspace.h"
#include "signing.h"

#ifdef HAVE_BTRPKG
#include <errno.h>
#include <fcntl.h>
#include <linux/magic.h>
#include <sys/stat.h>
#include <sys/vfs.h>
#include <sys/wait.h>
#include "btrpkg.h"
#include "btrstream.h"
#include "sandbox.h"
#include "util-common.h"
#include <pwd.h>
#include <ftw.h>


static const char *btr_xdata(alpm_pkg_t *pkg, const char *name)
{
	for(alpm_list_t *i = pkg->xdata; i; i = i->next) {
		alpm_pkg_xdata_t *x = i->data;
		if(strcmp(x->name, name) == 0) {
			return x->value;
		}
	}
	return NULL;
}

static int btr_unhex32(const char *s, unsigned char out[32])
{
	if(strlen(s) != 64) {
		return -1;
	}
	for(int i = 0; i < 64; i++) {
		char c = s[i];
		int v = c >= '0' && c <= '9' ? c - '0' : c >= 'a' && c <= 'f' ? c - 'a' + 10 : -1;
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

/* Sync targets whose database entry carries btrpkg data come as NAME.pkg.btr cache files,
 * when a helper is configured and the cache directory is on btrfs (their data is shared with
 * the installed files by reflink). Everything else is downloaded as usual. */
/* Where a package's repository keeps its btrparts, relative to the repository's URL: the
 * database's btrpkg.parts (e.g. ../pkg, shared by the architecture directories), else
 * pkg inside it. */
static const char *btr_parts(alpm_pkg_t *pkg)
{
	const char *p = btr_xdata(pkg, "btrpkg.parts");
	return p ? p : "pkg";
}

/* A btrpkg.parts value the helpers take: relative, no URL, no query, nothing but printable
 * characters (btrpkg checks it again). */
static int btr_parts_ok(const char *p)
{
	if(!*p || *p == '/' || strstr(p, "://")) {
		return 0;
	}
	for(const char *c = p; *c; c++) {
		if(*c <= ' ' || *c > '~' || strchr("\\?#%", *c)) {
			return 0;
		}
	}
	return 1;
}

static void btr_select(alpm_handle_t *handle, const char *cachedir)
{
	struct statfs sf;
	if(!handle->btrpkg_helper || !cachedir) {
		return;
	}
	if(statfs(cachedir, &sf) != 0 || sf.f_type != BTRFS_SUPER_MAGIC) {
		_alpm_log(handle, ALPM_LOG_DEBUG, "btrpkg: %s is not on btrfs, not using btrpkg packages\n", cachedir);
		return;
	}
	for(alpm_list_t *i = handle->trans->add; i; i = i->next) {
		alpm_pkg_t *spkg = i->data;
		const char *index, *id;
		if(spkg->origin == ALPM_PKG_FROM_FILE || spkg->btr) {
			continue;
		}
		index = btr_xdata(spkg, "btrpkg.index");
		id = btr_xdata(spkg, "btrpkg.id");
		if(!index || !id || strncmp(index, "index/", 6) != 0) {
			continue;
		}
		const char *name = index + 6;
		size_t len = strlen(name);
		if(len <= 7 || strcmp(name + len - 7, ".btridx") != 0 || name[0] == '.'
				|| memchr(name, '/', len - 7) || btr_unhex32(id, spkg->btr_id) != 0
				|| !btr_parts_ok(btr_parts(spkg))) {
			_alpm_log(handle, ALPM_LOG_WARNING, _("%s: unusable btrpkg data in the database\n"), spkg->name);
			continue;
		}
		/* the package file is already in a cache directory (an offline mirror such as the
		 * ISO's, or an earlier download): use it, never download it again as btrpkg */
		char *have = _alpm_filecache_find(handle, spkg->filename);
		if(have) {
			_alpm_log(handle, ALPM_LOG_DEBUG, "btrpkg: %s is in the cache as %s, not using btrpkg\n",
					spkg->name, have);
			free(have);
			continue;
		}
		char *fn = malloc(len - 7 + 9);
		if(!fn) {
			continue;
		}
		memcpy(fn, name, len - 7);
		strcpy(fn + len - 7, ".pkg.btr");
		FREE(spkg->btr_plain);
		spkg->btr_plain = spkg->filename;
		spkg->filename = fn;
		spkg->btr = 1;
		_alpm_log(handle, ALPM_LOG_DEBUG, "btrpkg: %s comes as %s\n", spkg->name, fn);
	}
}

static int compute_download_size(alpm_pkg_t *newpkg);

/* Back to the package's own file (the database's %FILENAME%), downloaded and checked as usual
 * (sha256sum, OpenPGP signature). */
static void btr_unselect(alpm_pkg_t *p)
{
	if(!p->btr || !p->btr_plain) {
		return;
	}
	FREE(p->filename);
	p->filename = p->btr_plain;
	p->btr_plain = NULL;
	p->btr = 0;
	p->btr_planned = 0;
	compute_download_size(p);
}

/* Whether fetch-ids put the (checked) index of `p` into DIR. */
static int btr_have_index(const char *dir, alpm_pkg_t *p)
{
	char path[PATH_MAX];
	struct stat st;
	size_t fl = strlen(p->filename) - 8; /* without .pkg.btr */
	if(snprintf(path, sizeof(path), "%s/index/%.*s.btridx", dir, (int)fl, p->filename) >= (int)sizeof(path)) {
		return 0;
	}
	return lstat(path, &st) == 0 && S_ISREG(st.st_mode);
}

/* Packages of `*mine` that have to come as package files: those without an index in DIR (no
 * server had one, e.g. a database older than what the servers keep), or all of them (`all`,
 * after the btrpkg download failed). They leave `*mine` and go to `*plain` (if given). */
static void btr_fall_back(alpm_handle_t *handle, alpm_list_t **mine, alpm_list_t **plain,
		const char *dir, int all)
{
	alpm_list_t *keep = NULL;
	for(alpm_list_t *i = *mine; i; i = i->next) {
		alpm_pkg_t *p = i->data;
		if(!all && btr_have_index(dir, p)) {
			keep = alpm_list_add(keep, p);
			continue;
		}
		if(!all) {
			_alpm_log(handle, ALPM_LOG_WARNING, _("btrpkg: no server has the index of %s, downloading the package instead\n"), p->name);
		}
		btr_unselect(p);
		if(plain) {
			*plain = alpm_list_add(*plain, p);
		}
	}
	alpm_list_free(*mine);
	*mine = keep;
}

/* The helper's argv: BtrPkgHelper split into words, then `extra` (NULL-terminated), then the
 * NAME=ID arguments of `pkgs`. Free with btr_argv_free. */
static char **btr_argv(alpm_handle_t *handle, const char *const *extra, alpm_list_t *pkgs)
{
	char **cmd = wordsplit(handle->btrpkg_helper);
	size_t ncmd = 0, nextra = 0, k = 0;
	if(!cmd) {
		return NULL;
	}
	while(cmd[ncmd]) {
		ncmd++;
	}
	while(extra[nextra]) {
		nextra++;
	}
	char **argv = calloc(ncmd + nextra + alpm_list_count(pkgs) + 1, sizeof(char *));
	if(!argv) {
		wordsplit_free(cmd);
		return NULL;
	}
	for(size_t j = 0; j < ncmd; j++) {
		argv[k++] = cmd[j];
	}
	free(cmd); /* the words now belong to argv */
	for(size_t j = 0; j < nextra; j++) {
		argv[k++] = strdup(extra[j]);
	}
	for(alpm_list_t *i = pkgs; i; i = i->next) {
		alpm_pkg_t *p = i->data;
		char hex[65];
		size_t fl = strlen(p->filename) - 8; /* without .pkg.btr */
		btr_hex(p->btr_id, 32, hex);
		char *id = malloc(fl + 1 + 64 + 1);
		if(id) {
			memcpy(id, p->filename, fl);
			id[fl] = '=';
			memcpy(id + fl + 1, hex, 65);
		}
		argv[k++] = id;
	}
	for(size_t j = 0; j < k; j++) {
		if(!argv[j]) {
			for(size_t m = 0; m < k; m++) {
				free(argv[m]);
			}
			free(argv);
			return NULL;
		}
	}
	return argv;
}

static void btr_argv_free(char **argv)
{
	for(size_t j = 0; argv && argv[j]; j++) {
		free(argv[j]);
	}
	free(argv);
}

/* The package whose cache file is NAME.pkg.btr. */
static alpm_pkg_t *btr_find(alpm_list_t *pkgs, const char *name, size_t len)
{
	for(alpm_list_t *i = pkgs; i; i = i->next) {
		alpm_pkg_t *p = i->data;
		if(strlen(p->filename) == len + 8 && strncmp(p->filename, name, len) == 0) {
			return p;
		}
	}
	return NULL;
}

/* Run the helper and wait for it. `sandboxed`: as DownloadUser under pacman's seccomp filter and
 * no-new-privileges (the helper applies Landlock itself: after Landlock it couldn't be started).
 * `progress`: the helper's stdout carries fetch-ids progress lines, turned into download
 * callbacks so the frontend draws its usual progress bars; otherwise stdout goes to /dev/null.
 * Returns the exit status, or -1. */
static int btr_run(alpm_handle_t *handle, char **argv, int sandboxed, int progress, alpm_list_t *pkgs)
{
	int pfd[2];
	if(pipe2(pfd, O_CLOEXEC) != 0) {
		return -1;
	}
	_alpm_log(handle, ALPM_LOG_DEBUG, "btrpkg: running %s %s%s\n", argv[0], argv[1] ? argv[1] : "",
			sandboxed ? " as the download user" : "");
	pid_t pid = fork();
	if(pid < 0) {
		close(pfd[0]);
		close(pfd[1]);
		return -1;
	}
	if(pid == 0) {
		_alpm_reset_signals();
		if(progress) {
			dup2(pfd[1], STDOUT_FILENO);
		} else {
			int null = open("/dev/null", O_WRONLY);
			if(null >= 0) {
				dup2(null, STDOUT_FILENO);
			}
		}
		if(sandboxed && alpm_sandbox_setup_child(handle, handle->sandboxuser, NULL, true) != 0) {
			fprintf(stderr, "btrpkg: switching to the download user '%s' failed\n", handle->sandboxuser);
			_exit(126);
		}
		execvp(argv[0], argv);
		fprintf(stderr, "btrpkg: cannot run %s: %s\n", argv[0], strerror(errno));
		_exit(127);
	}
	close(pfd[1]);
	FILE *in = fdopen(pfd[0], "r");
	char *line = NULL;
	size_t cap = 0;
	ssize_t n;
	off_t *total = calloc(alpm_list_count(pkgs) + 1, sizeof(off_t));
	while(in && (n = getline(&line, &cap, in)) > 0) {
		if(!progress || !handle->dlcb || !total) {
			continue;
		}
		if(line[n - 1] == '\n') {
			line[--n] = '\0';
		}
		char *kind = line, *name = strchr(line, '\t'), *num = NULL;
		if(!name) {
			continue;
		}
		*name++ = '\0';
		if((num = strchr(name, '\t'))) {
			*num++ = '\0';
		}
		alpm_pkg_t *p = btr_find(pkgs, name, strlen(name));
		if(!p) {
			continue;
		}
		size_t k = 0;
		for(alpm_list_t *i = pkgs; i && i->data != p; i = i->next) {
			k++;
		}
		if(strcmp(kind, "total") == 0 && num) {
			total[k] = (off_t)strtoll(num, NULL, 10);
			if(total[k] > 0) {
				alpm_download_event_init_t init = { .optional = 0 };
				handle->dlcb(handle->dlcb_ctx, p->filename, ALPM_DOWNLOAD_INIT, &init);
			}
		} else if(strcmp(kind, "got") == 0 && num && total[k] > 0) {
			alpm_download_event_progress_t pr = { .downloaded = (off_t)strtoll(num, NULL, 10), .total = total[k] };
			handle->dlcb(handle->dlcb_ctx, p->filename, ALPM_DOWNLOAD_PROGRESS, &pr);
		} else if(strcmp(kind, "done") == 0) {
			/* nothing needed from the network: like a file that is up to date */
			alpm_download_event_completed_t c = { .total = total[k], .result = total[k] > 0 ? 0 : 1 };
			if(total[k] == 0) {
				alpm_download_event_init_t init = { .optional = 0 };
				handle->dlcb(handle->dlcb_ctx, p->filename, ALPM_DOWNLOAD_INIT, &init);
			}
			handle->dlcb(handle->dlcb_ctx, p->filename, ALPM_DOWNLOAD_COMPLETED, &c);
		}
	}
	free(line);
	free(total);
	if(in) {
		fclose(in);
	} else {
		close(pfd[0]);
	}
	int status;
	while(waitpid(pid, &status, 0) < 0) {
		if(errno != EINTR) {
			return -1;
		}
	}
	return WIFEXITED(status) ? WEXITSTATUS(status) : -1;
}

/* Run pull-ids (root, no network) with a pipe each way. When it has reused everything it can
 * from this machine, it lists the chunks still missing in `missing` and prints
 * "fetch\tN\tBYTES"; then `fetch_argv` (fetch-ids --want) runs as the download user and fills the
 * download directory, and pull-ids is told "go". Returns pull-ids' exit status, or -1. */
static int btr_pull(alpm_handle_t *handle, char **pull_argv, char **fetch_argv, int sandboxed,
		alpm_list_t *pkgs)
{
	int out[2], in[2];
	if(pipe2(out, O_CLOEXEC) != 0) {
		return -1;
	}
	if(pipe2(in, O_CLOEXEC) != 0) {
		close(out[0]);
		close(out[1]);
		return -1;
	}
	_alpm_log(handle, ALPM_LOG_DEBUG, "btrpkg: running %s pull-ids\n", pull_argv[0]);
	pid_t pid = fork();
	if(pid < 0) {
		close(out[0]); close(out[1]); close(in[0]); close(in[1]);
		return -1;
	}
	if(pid == 0) {
		_alpm_reset_signals();
		dup2(out[1], STDOUT_FILENO);
		dup2(in[0], STDIN_FILENO);
		execvp(pull_argv[0], pull_argv);
		fprintf(stderr, "btrpkg: cannot run %s: %s\n", pull_argv[0], strerror(errno));
		_exit(127);
	}
	close(out[1]);
	close(in[0]);
	FILE *rd = fdopen(out[0], "r");
	char *line = NULL;
	size_t cap = 0;
	while(rd && getline(&line, &cap, rd) > 0) {
		if(strncmp(line, "fetch\t", 6) != 0) {
			continue;
		}
		_alpm_log(handle, ALPM_LOG_DEBUG, "btrpkg: %s", line);
		int rc = btr_run(handle, fetch_argv, sandboxed, 1, pkgs);
		if(rc == 0) {
			if(write(in[1], "go\n", 3) != 3) {
				break;
			}
		} else {
			_alpm_log(handle, ALPM_LOG_ERROR, _("failed retrieving btrpkg packages\n"));
			break; /* closing stdin makes pull-ids fail */
		}
	}
	free(line);
	close(in[1]);
	if(rd) {
		fclose(rd);
	} else {
		close(out[0]);
	}
	int status;
	while(waitpid(pid, &status, 0) < 0) {
		if(errno != EINTR) {
			return -1;
		}
	}
	return WIFEXITED(status) ? WEXITSTATUS(status) : -1;
}

/* CACHEDIR/download-btrpkg: created if needed, a real directory, and owned by the download user
 * when downloads are sandboxed. */
static int btr_download_dir(alpm_handle_t *handle, const char *cachedir, char *dir, size_t len,
		int sandboxed)
{
	struct stat st;
	snprintf(dir, len, "%sdownload-btrpkg", cachedir);
	if(mkdir(dir, 0755) != 0 && errno != EEXIST) {
		_alpm_log(handle, ALPM_LOG_ERROR, _("btrpkg: cannot create %s: %s\n"), dir, strerror(errno));
		return -1;
	}
	if(lstat(dir, &st) != 0 || !S_ISDIR(st.st_mode)) {
		_alpm_log(handle, ALPM_LOG_ERROR, _("btrpkg: %s is not a directory\n"), dir);
		return -1;
	}
	if(sandboxed) {
		struct passwd const *pw = getpwnam(handle->sandboxuser);
		if(!pw || chown(dir, pw->pw_uid, pw->pw_gid) != 0) {
			_alpm_log(handle, ALPM_LOG_ERROR, _("btrpkg: cannot hand %s to the download user\n"), dir);
			return -1;
		}
	}
	return 0;
}

/* fetch-ids arguments for one repository: `--index-only` when `want` is NULL, else
 * `--want WANT --progress`; the servers' btrparts directory (`--parts`); then --server for every
 * CacheServer and Server entry, in that order, and DIR. NULL-terminated; free the array (not the
 * strings). */
static const char **btr_fetch_args(alpm_db_t *db, const char *parts, const char *dir, const char *want, int sandboxed)
{
	size_t nserv = alpm_list_count(db->cache_servers) + alpm_list_count(db->servers), k = 0;
	if(nserv == 0) {
		return NULL;
	}
	const char **ex = calloc(10 + 2 * nserv + 1, sizeof(char *));
	if(!ex) {
		return NULL;
	}
	ex[k++] = "fetch-ids";
	ex[k++] = "--parts";
	ex[k++] = parts;
	if(want) {
		ex[k++] = "--want";
		ex[k++] = want;
		ex[k++] = "--progress";
	} else {
		ex[k++] = "--index-only";
		ex[k++] = "--skip-missing"; /* btr_fall_back takes care of those */
	}
	if(sandboxed) {
		ex[k++] = "--landlock";
	}
	for(alpm_list_t *s = db->cache_servers; s; s = s->next) {
		ex[k++] = "--server";
		ex[k++] = s->data;
	}
	for(alpm_list_t *s = db->servers; s; s = s->next) {
		ex[k++] = "--server";
		ex[k++] = s->data;
	}
	ex[k++] = dir;
	return ex;
}

/* Take the packages of the first package's repository and btrparts directory out of *pkgs. */
static alpm_list_t *btr_take_repo(alpm_list_t **pkgs)
{
	alpm_db_t *db = ((alpm_pkg_t *)(*pkgs)->data)->origin_data.db;
	const char *parts = btr_parts((*pkgs)->data);
	alpm_list_t *mine = NULL, *others = NULL;
	for(alpm_list_t *i = *pkgs; i; i = i->next) {
		alpm_pkg_t *p = i->data;
		if(p->origin_data.db == db && strcmp(btr_parts(p), parts) == 0) {
			mine = alpm_list_add(mine, p);
		} else {
			others = alpm_list_add(others, p);
		}
	}
	alpm_list_free(*pkgs);
	*pkgs = others;
	return mine;
}

/* Get the indexes of `mine` (one repository) into DIR, as the download user when sandboxed. */
static int btr_fetch_indexes(alpm_handle_t *handle, alpm_list_t *mine, const char *dir, int sandboxed)
{
	alpm_db_t *db = ((alpm_pkg_t *)mine->data)->origin_data.db;
	const char **ex = btr_fetch_args(db, btr_parts(mine->data), dir, NULL, sandboxed);
	char **argv = ex ? btr_argv(handle, ex, mine) : NULL;
	int ret = argv ? btr_run(handle, argv, sandboxed, 0, mine) : -1;
	if(ret != 0) {
		_alpm_log(handle, ALPM_LOG_ERROR, _("failed retrieving btrpkg indexes from %s\n"), db->treename);
	}
	btr_argv_free(argv);
	free(ex);
	return ret == 0 ? 0 : -1;
}

/* Before the transaction summary: the real download size of every btrpkg target without a cache
 * file. The indexes are fetched (and kept for the download), then pull-ids --plan checks which
 * chunks this machine has, writing nothing. Targets it can't plan keep the upper bound. */
static void btr_plan(alpm_handle_t *handle, const char *cachedir, alpm_list_t *targets)
{
	alpm_list_t *btr = NULL;
	char dir[PATH_MAX];
	int sandboxed = _alpm_use_sandbox(handle);
	for(alpm_list_t *i = targets; i; i = i->next) {
		alpm_pkg_t *p = i->data;
		char *fpath;
		if(!p->btr || p->origin != ALPM_PKG_FROM_SYNCDB) {
			continue;
		}
		if((fpath = _alpm_filecache_find(handle, p->filename))) {
			free(fpath);
			continue;
		}
		btr = alpm_list_add(btr, p);
	}
	if(!btr || btr_download_dir(handle, cachedir, dir, sizeof(dir), sandboxed) != 0) {
		alpm_list_free(btr);
		return;
	}
	while(btr) {
		alpm_list_t *mine = btr_take_repo(&btr);
		if(btr_fetch_indexes(handle, mine, dir, sandboxed) == 0) {
			/* no index anywhere: the package file, sized and downloaded as usual */
			btr_fall_back(handle, &mine, NULL, dir, 0);
		}
		if(mine) {
			const char *plan[] = { "--installed", handle->root, "pull-ids", "--plan", dir, cachedir, NULL };
			char **argv = btr_argv(handle, plan, mine);
			int out[2];
			if(argv && pipe2(out, O_CLOEXEC) == 0) {
				pid_t pid = fork();
				if(pid == 0) {
					_alpm_reset_signals();
					dup2(out[1], STDOUT_FILENO);
					execvp(argv[0], argv);
					_exit(127);
				}
				close(out[1]);
				FILE *rd = fdopen(out[0], "r");
				char *line = NULL;
				size_t cap = 0;
				while(rd && getline(&line, &cap, rd) > 0) {
					char name[PATH_MAX];
					long long cb, ib;
					if(sscanf(line, "need\t%4095[^\t]\t%lld\t%lld", name, &cb, &ib) == 3) {
						alpm_pkg_t *p = btr_find(mine, name, strlen(name));
						if(p) {
							p->btr_need = (off_t)(cb + ib);
							p->btr_planned = 1;
						}
					}
				}
				free(line);
				if(rd) {
					fclose(rd);
				} else {
					close(out[0]);
				}
				if(pid > 0) {
					int status;
					while(waitpid(pid, &status, 0) < 0 && errno == EINTR) {
					}
				}
			}
			btr_argv_free(argv);
		}
		alpm_list_free(mine);
	}
}

/* Remove a download directory that only root used (no download user): nftw without following
 * symlinks, not crossing mounts. */
static int btr_rm_entry(const char *path, const struct stat *st, int type, struct FTW *ftw)
{
	(void)st; (void)ftw;
	return (type == FTW_DP ? rmdir(path) : unlink(path)) == 0 ? 0 : -1;
}

static void btr_rmtree(const char *dir)
{
	nftw(dir, btr_rm_entry, 16, FTW_DEPTH | FTW_PHYS | FTW_MOUNT);
}

/* Download the btrpkg targets among `files` (removing them from it), per repository:
 *   1. fetch-ids --index-only, as the download user when pacman sandboxes downloads (also under
 *      Landlock: it writes only to CACHEDIR/download-btrpkg/): the indexes and signatures.
 *      Usually already there from btr_plan, and then nothing is fetched.
 *   2. pull-ids (root, no network) checks the indexes against the database's IDs, takes every
 *      chunk it can from the installed versions and older cache files (each read back and
 *      hashed), then names the chunks still missing.
 *   3. fetch-ids --want (download user again) gets exactly those, from the CacheServer entries
 *      first, then Server entries, each server asked for what the previous one lacked. Chunks
 *      are checked against their hashes on arrival, and again by pull-ids when it reads them.
 *   4. pull-ids writes NAME.pkg.btr with encoded writes and removes the download directory.
 * Root never writes into the download directory and never touches the network. After a failure
 * the directory stays, so the next run fetches only what is still missing.
 * Packages no server has an index for (step 1), and every package of a repository whose btrpkg
 * download failed, go back to `files`: their package files come the usual way, from the same
 * servers, checked by sha256sum and OpenPGP signature. Only a broken download directory fails. */
static int btr_download(alpm_handle_t *handle, const char *cachedir, alpm_list_t **files)
{
	alpm_list_t *btr = NULL, *rest = NULL;
	int ret = 0;
	for(alpm_list_t *i = *files; i; i = i->next) {
		alpm_pkg_t *p = i->data;
		if(p->btr) {
			btr = alpm_list_add(btr, p);
		} else {
			rest = alpm_list_add(rest, p);
		}
	}
	alpm_list_free(*files);
	*files = rest;
	if(!btr) {
		return 0;
	}

	int sandboxed = _alpm_use_sandbox(handle);
	char dir[PATH_MAX], missing[PATH_MAX];
	/* root writes the list of missing chunks: not in the download user's directory */
	snprintf(missing, sizeof(missing), "%sdownload-btrpkg.want", cachedir);
	if(btr_download_dir(handle, cachedir, dir, sizeof(dir), sandboxed) != 0) {
		alpm_list_free(btr);
		return -1;
	}

	while(btr && ret == 0) {
		alpm_list_t *mine = btr_take_repo(&btr);
		alpm_db_t *db = ((alpm_pkg_t *)mine->data)->origin_data.db;
		const char **ex = NULL;
		char **argv = NULL, **fetch = NULL;
		int failed = 0;
		/* the indexes first (usually already there from btr_plan); packages no server has an
		 * index for come as package files */
		if(btr_fetch_indexes(handle, mine, dir, sandboxed) != 0) {
			failed = 1;
			goto next;
		}
		btr_fall_back(handle, &mine, files, dir, 0);
		if(!mine) {
			goto next;
		}
		if(!sandboxed) {
			/* no download user (DisableSandbox, or pacstrap, which always disables it): one root
			 * process fetches straight into the cache files, so the chunks aren't written twice
			 * (download directory, then cache file). Servers in order: CacheServer, then
			 * Server; each attempt is all or nothing, so a failed one leaves no cache file. */
			int done = 0;
			for(int pass = 0; pass < 2 && !done; pass++) {
				for(alpm_list_t *s = pass ? db->servers : db->cache_servers; s && !done; s = s->next) {
					const char *pull[] = { "--installed", handle->root, "pull-ids", "--progress",
						"--parts", btr_parts(mine->data), s->data, cachedir, NULL };
					argv = btr_argv(handle, pull, mine);
					if(argv && btr_run(handle, argv, 0, 1, mine) == 0) {
						done = 1;
					} else {
						_alpm_log(handle, ALPM_LOG_WARNING, _("btrpkg: %s failed, trying the next server\n"),
								(const char *)s->data);
					}
					btr_argv_free(argv);
					argv = NULL;
				}
			}
			failed = !done;
			btr_rmtree(dir); /* the indexes */
			goto next;
		}
		ex = btr_fetch_args(db, btr_parts(mine->data), dir, missing, sandboxed);
		fetch = ex ? btr_argv(handle, ex, mine) : NULL;
		const char *pull[] = { "--installed", handle->root, "pull-ids", "--consume",
			"--fetch-via", missing, dir, cachedir, NULL };
		argv = btr_argv(handle, pull, mine);
		if(!fetch || !argv || btr_pull(handle, argv, fetch, sandboxed, mine) != 0) {
			failed = 1;
		}
next:
		if(failed && mine) {
			/* every attempt is all or nothing, so no cache file is half written: the package
			 * files instead, from the same servers, checked as usual */
			_alpm_log(handle, ALPM_LOG_WARNING, _("btrpkg: could not get the packages from %s as btrpkg, downloading the package files instead\n"), db->treename);
			btr_fall_back(handle, &mine, files, dir, 1);
		}
		unlink(missing);
		btr_argv_free(argv);
		btr_argv_free(fetch);
		free(ex);
		alpm_list_free(mine);
	}
	alpm_list_free(btr);
	return ret;
}

/* The check of a btrpkg cache file that replaces the sha256sum and OpenPGP checks: the index
 * must parse and have the header ID the database gives, and with package signatures on, a
 * signify signature (NAME.pkg.btr.sig, from the server) by a key in _alpm_btr_keydirs. The
 * ID check is recorded as sha256 (it is a SHA-256 over the header, which holds the hashes of
 * everything else), the signature as btrpkg-validation extended data (pkg->btr_signer), not
 * as pgp. */
static int btr_validate(alpm_handle_t *handle, alpm_pkg_t *pkg, const char *path, int siglevel,
		int *validation)
{
	char err[BTR_ERRLEN];
	struct stat st;
	int fd = open(path, O_RDONLY | O_CLOEXEC);
	if(fd < 0 || fstat(fd, &st) != 0) {
		if(fd >= 0) {
			close(fd);
		}
		handle->pm_errno = ALPM_ERR_PKG_OPEN;
		return -1;
	}
	if(_alpm_btr_validate(fd, pkg->btr_id, (uint64_t)st.st_size, err) != 0) {
		_alpm_log(handle, ALPM_LOG_ERROR, _("%s: %s\n"), pkg->name, err);
		close(fd);
		handle->pm_errno = ALPM_ERR_PKG_INVALID_CHECKSUM;
		return -1;
	}
	*validation = ALPM_PKG_VALIDATION_SHA256SUM;
	FREE(pkg->btr_signer);
	if(siglevel & ALPM_SIG_PACKAGE) {
		char keypath[PATH_MAX];
		int r = _alpm_btr_check_sig(fd, path, keypath, err);
		close(fd);
		if(r == 1) {
			if(siglevel & ALPM_SIG_PACKAGE_OPTIONAL) {
				return 0;
			}
			handle->pm_errno = ALPM_ERR_PKG_MISSING_SIG;
			return -1;
		}
		if(r != 0) {
			_alpm_log(handle, ALPM_LOG_ERROR, _("%s: btrpkg signature: %s\n"), pkg->name, err);
			handle->pm_errno = ALPM_ERR_PKG_INVALID_CHECKSUM;
			return -1;
		}
		_alpm_log(handle, ALPM_LOG_DEBUG, "btrpkg: %s signed by %s\n", pkg->name, keypath);
		STRDUP(pkg->btr_signer, keypath, RET_ERR(handle, ALPM_ERR_MEMORY, -1));
		return 0;
	}
	close(fd);
	return 0;
}
#endif /* HAVE_BTRPKG */

struct keyinfo_t {
       char* uid;
       char* keyid;
};

alpm_pkg_t SYMEXPORT *alpm_sync_get_new_version(alpm_pkg_t *pkg, alpm_list_t *dbs_sync)
{
	alpm_list_t *i;
	alpm_pkg_t *spkg = NULL;

	ASSERT(pkg != NULL, return NULL);
	pkg->handle->pm_errno = ALPM_ERR_OK;

	for(i = dbs_sync; !spkg && i; i = i->next) {
		alpm_db_t *db = i->data;
		spkg = _alpm_db_get_pkgfromcache(db, pkg->name);
	}

	if(spkg == NULL) {
		_alpm_log(pkg->handle, ALPM_LOG_DEBUG, "'%s' not found in sync db => no upgrade\n",
				pkg->name);
		return NULL;
	}

	/* compare versions and see if spkg is an upgrade */
	if(_alpm_pkg_compare_versions(spkg, pkg) > 0) {
		_alpm_log(pkg->handle, ALPM_LOG_DEBUG, "new version of '%s' found (%s => %s)\n",
					pkg->name, pkg->version, spkg->version);
		return spkg;
	}
	/* spkg is not an upgrade */
	return NULL;
}

static int check_literal(alpm_handle_t *handle, alpm_pkg_t *lpkg,
		alpm_pkg_t *spkg, int enable_downgrade)
{
	/* 1. literal was found in sdb */
	int cmp = _alpm_pkg_compare_versions(spkg, lpkg);
	if(cmp > 0) {
		_alpm_log(handle, ALPM_LOG_DEBUG, "new version of '%s' found (%s => %s)\n",
				lpkg->name, lpkg->version, spkg->version);
		/* check IgnorePkg/IgnoreGroup */
		if(alpm_pkg_should_ignore(handle, spkg)
				|| alpm_pkg_should_ignore(handle, lpkg)) {
			_alpm_log(handle, ALPM_LOG_WARNING, _("%s: ignoring package upgrade (%s => %s)\n"),
					lpkg->name, lpkg->version, spkg->version);
		} else {
			_alpm_log(handle, ALPM_LOG_DEBUG, "adding package %s-%s to the transaction targets\n",
					spkg->name, spkg->version);
			return 1;
		}
	} else if(cmp < 0) {
		if(enable_downgrade) {
			/* check IgnorePkg/IgnoreGroup */
			if(alpm_pkg_should_ignore(handle, spkg)
					|| alpm_pkg_should_ignore(handle, lpkg)) {
				_alpm_log(handle, ALPM_LOG_WARNING, _("%s: ignoring package downgrade (%s => %s)\n"),
						lpkg->name, lpkg->version, spkg->version);
			} else {
				_alpm_log(handle, ALPM_LOG_WARNING, _("%s: downgrading from version %s to version %s\n"),
						lpkg->name, lpkg->version, spkg->version);
				return 1;
			}
		} else {
			alpm_db_t *sdb = alpm_pkg_get_db(spkg);
			_alpm_log(handle, ALPM_LOG_WARNING, _("%s: local (%s) is newer than %s (%s)\n"),
					lpkg->name, lpkg->version, sdb->treename, spkg->version);
		}
	}
	return 0;
}

static alpm_list_t *check_replacers(alpm_handle_t *handle, alpm_pkg_t *lpkg,
		alpm_db_t *sdb)
{
	/* 2. search for replacers in sdb */
	alpm_list_t *replacers = NULL;
	alpm_list_t *k;
	_alpm_log(handle, ALPM_LOG_DEBUG,
			"searching for replacements for %s in %s\n",
			lpkg->name, sdb->treename);
	for(k = _alpm_db_get_pkgcache(sdb); k; k = k->next) {
		int found = 0;
		alpm_pkg_t *spkg = k->data;
		alpm_list_t *l;
		for(l = alpm_pkg_get_replaces(spkg); l; l = l->next) {
			alpm_depend_t *replace = l->data;
			/* we only want to consider literal matches at this point. */
			if(_alpm_depcmp_literal(lpkg, replace)) {
				found = 1;
				break;
			}
		}
		if(found) {
			alpm_question_replace_t question = {
				.type = ALPM_QUESTION_REPLACE_PKG,
				.replace = 0,
				.oldpkg = lpkg,
				.newpkg = spkg,
				.newdb = sdb
			};
			alpm_pkg_t *tpkg;
			/* check IgnorePkg/IgnoreGroup */
			if(alpm_pkg_should_ignore(handle, spkg)
					|| alpm_pkg_should_ignore(handle, lpkg)) {
				_alpm_log(handle, ALPM_LOG_WARNING,
						_("ignoring package replacement (%s-%s => %s-%s)\n"),
						lpkg->name, lpkg->version, spkg->name, spkg->version);
				continue;
			}

			QUESTION(handle, &question);
			if(!question.replace) {
				continue;
			}

			/* If spkg is already in the target list, we append lpkg to spkg's
			 * removes list */
			tpkg = alpm_pkg_find(handle->trans->add, spkg->name);
			if(tpkg) {
				/* sanity check, multiple repos can contain spkg->name */
				if(tpkg->origin_data.db != sdb) {
					_alpm_log(handle, ALPM_LOG_WARNING, _("cannot replace %s by %s\n"),
							lpkg->name, spkg->name);
					continue;
				}
				_alpm_log(handle, ALPM_LOG_DEBUG, "appending %s to the removes list of %s\n",
						lpkg->name, tpkg->name);
				tpkg->removes = alpm_list_add(tpkg->removes, lpkg);
				/* check the to-be-replaced package's reason field */
				if(alpm_pkg_get_reason(lpkg) == ALPM_PKG_REASON_EXPLICIT) {
					tpkg->reason = ALPM_PKG_REASON_EXPLICIT;
				}
			} else {
				/* add spkg to the target list */
				/* copy over reason */
				spkg->reason = alpm_pkg_get_reason(lpkg);
				spkg->removes = alpm_list_add(NULL, lpkg);
				_alpm_log(handle, ALPM_LOG_DEBUG,
						"adding package %s-%s to the transaction targets\n",
						spkg->name, spkg->version);
				replacers = alpm_list_add(replacers, spkg);
			}
		}
	}
	return replacers;
}

int SYMEXPORT alpm_sync_sysupgrade(alpm_handle_t *handle, int enable_downgrade)
{
	alpm_list_t *i, *j;
	alpm_trans_t *trans;

	CHECK_HANDLE(handle, return -1);
	trans = handle->trans;
	ASSERT(trans != NULL, RET_ERR(handle, ALPM_ERR_TRANS_NULL, -1));
	ASSERT(trans->state == STATE_INITIALIZED, RET_ERR(handle, ALPM_ERR_TRANS_NOT_INITIALIZED, -1));

	_alpm_log(handle, ALPM_LOG_DEBUG, "checking for package upgrades\n");
	for(i = _alpm_db_get_pkgcache(handle->db_local); i; i = i->next) {
		alpm_pkg_t *lpkg = i->data;

		if(alpm_pkg_find(trans->remove, lpkg->name)) {
			_alpm_log(handle, ALPM_LOG_DEBUG, "%s is marked for removal -- skipping\n", lpkg->name);
			continue;
		}

		if(alpm_pkg_find(trans->add, lpkg->name)) {
			_alpm_log(handle, ALPM_LOG_DEBUG, "%s is already in the target list -- skipping\n", lpkg->name);
			continue;
		}

		/* Search for replacers then literal (if no replacer) in each sync database. */
		for(j = handle->dbs_sync; j; j = j->next) {
			alpm_db_t *sdb = j->data;
			alpm_list_t *replacers;

			if(!(sdb->usage & ALPM_DB_USAGE_UPGRADE)) {
				continue;
			}

			/* Check sdb */
			replacers = check_replacers(handle, lpkg, sdb);
			if(replacers) {
				trans->add = alpm_list_join(trans->add, replacers);
				/* jump to next local package */
				break;
			} else {
				alpm_pkg_t *spkg = _alpm_db_get_pkgfromcache(sdb, lpkg->name);
				if(spkg) {
					if(check_literal(handle, lpkg, spkg, enable_downgrade)) {
						trans->add = alpm_list_add(trans->add, spkg);
					}
					/* jump to next local package */
					break;
				}
			}
		}
	}

	return 0;
}

alpm_list_t SYMEXPORT *alpm_find_group_pkgs(alpm_list_t *dbs,
		const char *name)
{
	alpm_list_t *i, *j, *pkgs = NULL, *ignorelist = NULL;

	for(i = dbs; i; i = i->next) {
		alpm_db_t *db = i->data;
		alpm_group_t *grp = alpm_db_get_group(db, name);

		if(!grp) {
			continue;
		}

		for(j = grp->packages; j; j = j->next) {
			alpm_pkg_t *pkg = j->data;
			alpm_trans_t *trans = db->handle->trans;

			if(alpm_pkg_find(ignorelist, pkg->name)) {
				continue;
			}
			if(trans != NULL && trans->flags & ALPM_TRANS_FLAG_NEEDED) {
				alpm_pkg_t *local = _alpm_db_get_pkgfromcache(db->handle->db_local, pkg->name);
				if(local && _alpm_pkg_compare_versions(pkg, local) == 0) {
					/* with the NEEDED flag, packages up to date are not reinstalled */
					_alpm_log(db->handle, ALPM_LOG_WARNING, _("%s-%s is up to date -- skipping\n"),
							local->name, local->version);
					ignorelist = alpm_list_add(ignorelist, pkg);
					continue;
				}
			}
			if(alpm_pkg_should_ignore(db->handle, pkg)) {
				alpm_question_install_ignorepkg_t question = {
					.type = ALPM_QUESTION_INSTALL_IGNOREPKG,
					.install = 0,
					.pkg = pkg
				};
				ignorelist = alpm_list_add(ignorelist, pkg);
				QUESTION(db->handle, &question);
				if(!question.install) {
					continue;
				}
			}
			if(!alpm_pkg_find(pkgs, pkg->name)) {
				pkgs = alpm_list_add(pkgs, pkg);
			}
		}
	}
	alpm_list_free(ignorelist);
	return pkgs;
}

/** Compute the size of the files that will be downloaded to install a
 * package.
 * @param newpkg the new package to upgrade to
 */
static int compute_download_size(alpm_pkg_t *newpkg)
{
	const char *fname;
	char *fpath, *fnamepart = NULL;
	off_t size = 0;
	alpm_handle_t *handle = newpkg->handle;
	int ret = 0;
	size_t fnamepartlen = 0;

	if(newpkg->origin != ALPM_PKG_FROM_SYNCDB) {
		newpkg->infolevel |= INFRQ_DSIZE;
		newpkg->download_size = 0;
		return 0;
	}

	ASSERT(newpkg->filename != NULL, RET_ERR(handle, ALPM_ERR_PKG_INVALID_NAME, -1));
	fname = newpkg->filename;
	fpath = _alpm_filecache_find(handle, fname);

	/* downloaded file exists, so there's nothing to grab */
	if(fpath) {
		size = 0;
		goto finish;
	}
#ifdef HAVE_BTRPKG
	if(newpkg->btr) {
		/* what pull-ids --plan found missing after checking local data (btr_plan); without a
		 * plan, the transport size (index and every chunk) as an upper bound */
		if(newpkg->btr_planned) {
			size = newpkg->btr_need;
		} else {
			const char *bs = btr_xdata(newpkg, "btrpkg.size");
			size = bs ? (off_t)strtoll(bs, NULL, 10) : newpkg->size;
		}
		goto finish;
	}
#endif

	fnamepartlen = strlen(fname) + 6;
	CALLOC(fnamepart, fnamepartlen, sizeof(char), return -1);
	snprintf(fnamepart, fnamepartlen, "%s.part", fname);
	fpath = _alpm_filecache_find(handle, fnamepart);
	if(fpath) {
		struct stat st;
		if(stat(fpath, &st) == 0) {
			/* subtract the size of the .part file */
			_alpm_log(handle, ALPM_LOG_DEBUG, "using (package - .part) size\n");
			size = newpkg->size - st.st_size;
			size = size < 0 ? 0 : size;
		}

		/* tell the caller that we have a partial */
		ret = 1;
	} else {
		size = newpkg->size;
	}

finish:
	_alpm_log(handle, ALPM_LOG_DEBUG, "setting download size %jd for pkg %s\n",
			(intmax_t)size, newpkg->name);

	newpkg->infolevel |= INFRQ_DSIZE;
	newpkg->download_size = size;

	FREE(fpath);
	FREE(fnamepart);

	return ret;
}

int _alpm_sync_prepare(alpm_handle_t *handle, alpm_list_t **data)
{
	alpm_list_t *i, *j;
	alpm_list_t *deps = NULL;
	alpm_list_t *unresolvable = NULL;
	int from_sync = 0;
	int ret = 0;
	alpm_trans_t *trans = handle->trans;
	alpm_event_t event;

	if(data) {
		*data = NULL;
	}

	for(i = trans->add; i; i = i->next) {
		alpm_pkg_t *spkg = i->data;
		if (spkg->origin == ALPM_PKG_FROM_SYNCDB){
			from_sync = 1;
			break;
		}
	}

	/* ensure all sync database are valid if we will be using them */
	for(i = handle->dbs_sync; i; i = i->next) {
		const alpm_db_t *db = i->data;
		if(db->status & DB_STATUS_INVALID) {
			RET_ERR(handle, ALPM_ERR_DB_INVALID, -1);
		}
		/* missing databases are not allowed if we have sync targets */
		if(from_sync && db->status & DB_STATUS_MISSING) {
			RET_ERR(handle, ALPM_ERR_DB_NOT_FOUND, -1);
		}
	}

	if(!(trans->flags & ALPM_TRANS_FLAG_NODEPS)) {
		alpm_list_t *resolved = NULL;
		alpm_list_t *remove = alpm_list_copy(trans->remove);
		alpm_list_t *localpkgs;

		/* Build up list by repeatedly resolving each transaction package */
		/* Resolve targets dependencies */
		event.type = ALPM_EVENT_RESOLVEDEPS_START;
		EVENT(handle, &event);
		_alpm_log(handle, ALPM_LOG_DEBUG, "resolving target's dependencies\n");

		/* build remove list for resolvedeps */
		for(i = trans->add; i; i = i->next) {
			alpm_pkg_t *spkg = i->data;
			for(j = spkg->removes; j; j = j->next) {
				remove = alpm_list_add(remove, j->data);
			}
		}

		/* Compute the fake local database for resolvedeps (partial fix for the
		 * phonon/qt issue) */
		localpkgs = alpm_list_diff(_alpm_db_get_pkgcache(handle->db_local),
				trans->add, _alpm_pkg_cmp);

		/* Resolve packages in the transaction one at a time, in addition
		   building up a list of packages which could not be resolved. */
		for(i = trans->add; i; i = i->next) {
			alpm_pkg_t *pkg = i->data;
			if(_alpm_resolvedeps(handle, localpkgs, pkg, trans->add,
						&resolved, remove, data) == -1) {
				unresolvable = alpm_list_add(unresolvable, pkg);
			}
			/* Else, [resolved] now additionally contains [pkg] and all of its
			   dependencies not already on the list */
		}
		alpm_list_free(localpkgs);
		alpm_list_free(remove);

		/* If there were unresolvable top-level packages, prompt the user to
		   see if they'd like to ignore them rather than failing the sync */
		if(unresolvable != NULL) {
			alpm_question_remove_pkgs_t question = {
				.type = ALPM_QUESTION_REMOVE_PKGS,
				.skip = 0,
				.packages = unresolvable
			};
			QUESTION(handle, &question);
			if(question.skip) {
				/* User wants to remove the unresolvable packages from the
				   transaction. The packages will be removed from the actual
				   transaction when the transaction packages are replaced with a
				   dependency-reordered list below */
				handle->pm_errno = ALPM_ERR_OK;
				if(data) {
					alpm_list_free_inner(*data,
							(alpm_list_fn_free)alpm_depmissing_free);
					alpm_list_free(*data);
					*data = NULL;
				}
			} else {
				/* pm_errno was set by resolvedeps, callback may have overwrote it */
				alpm_list_free(resolved);
				alpm_list_free(unresolvable);
				ret = -1;
				GOTO_ERR(handle, ALPM_ERR_UNSATISFIED_DEPS, cleanup);
			}
		}

		/* Ensure two packages don't have the same filename */
		for(i = resolved; i; i = i->next) {
			alpm_pkg_t *pkg1 = i->data;
			for(j = i->next; j; j = j->next) {
				alpm_pkg_t *pkg2 = j->data;
				if(strcmp(pkg1->filename, pkg2->filename) == 0) {
					ret = -1;
					handle->pm_errno = ALPM_ERR_TRANS_DUP_FILENAME;
					_alpm_log(handle, ALPM_LOG_ERROR, _("packages %s and %s have the same filename: %s\n"),
						pkg1->name, pkg2->name, pkg1->filename);
				}
			}
		}

		if(ret != 0) {
			alpm_list_free(resolved);
			goto cleanup;
		}

		/* Set DEPEND reason for pulled packages */
		for(i = resolved; i; i = i->next) {
			alpm_pkg_t *pkg = i->data;
			if(!alpm_pkg_find(trans->add, pkg->name)) {
				pkg->reason = ALPM_PKG_REASON_DEPEND;
			}
		}

		/* Unresolvable packages will be removed from the target list; set these
		 * aside in the transaction as a list we won't operate on. If we free them
		 * before the end of the transaction, we may kill pointers the frontend
		 * holds to package objects. */
		trans->unresolvable = unresolvable;

		alpm_list_free(trans->add);
		trans->add = resolved;

		event.type = ALPM_EVENT_RESOLVEDEPS_DONE;
		EVENT(handle, &event);
	}

	if(!(trans->flags & ALPM_TRANS_FLAG_NOCONFLICTS)) {
		/* check for inter-conflicts and whatnot */
		event.type = ALPM_EVENT_INTERCONFLICTS_START;
		EVENT(handle, &event);

		_alpm_log(handle, ALPM_LOG_DEBUG, "looking for conflicts\n");

		/* 1. check for conflicts in the target list */
		_alpm_log(handle, ALPM_LOG_DEBUG, "check targets vs targets\n");
		deps = _alpm_innerconflicts(handle, trans->add);

		for(i = deps; i; i = i->next) {
			alpm_conflict_t *conflict = i->data;
			const char *name1 = conflict->package1->name;
			const char *name2 = conflict->package2->name;
			alpm_pkg_t *rsync, *sync, *sync1, *sync2;

			/* have we already removed one of the conflicting targets? */
			sync1 = alpm_pkg_find(trans->add, name1);
			sync2 = alpm_pkg_find(trans->add, name2);
			if(!sync1 || !sync2) {
				continue;
			}

			_alpm_log(handle, ALPM_LOG_DEBUG, "conflicting packages in the sync list: '%s' <-> '%s'\n",
					name1, name2);

			/* if sync1 provides sync2, we remove sync2 from the targets, and vice versa */
			alpm_depend_t *dep1 = alpm_dep_from_string(name1);
			alpm_depend_t *dep2 = alpm_dep_from_string(name2);
			if(_alpm_depcmp(sync1, dep2)) {
				rsync = sync2;
				sync = sync1;
			} else if(_alpm_depcmp(sync2, dep1)) {
				rsync = sync1;
				sync = sync2;
			} else {
				_alpm_log(handle, ALPM_LOG_ERROR, _("unresolvable package conflicts detected\n"));
				handle->pm_errno = ALPM_ERR_CONFLICTING_DEPS;
				ret = -1;
				if(data) {
					alpm_conflict_t *newconflict = _alpm_conflict_dup(conflict);
					if(newconflict) {
						*data = alpm_list_add(*data, newconflict);
					}
				}
				alpm_list_free_inner(deps, (alpm_list_fn_free)alpm_conflict_free);
				alpm_list_free(deps);
				alpm_dep_free(dep1);
				alpm_dep_free(dep2);
				goto cleanup;
			}
			alpm_dep_free(dep1);
			alpm_dep_free(dep2);

			/* Prints warning */
			_alpm_log(handle, ALPM_LOG_WARNING,
					_("removing '%s-%s' from target list because it conflicts with '%s-%s'\n"),
					rsync->name, rsync->version, sync->name, sync->version);
			trans->add = alpm_list_remove(trans->add, rsync, _alpm_pkg_cmp, NULL);
			/* rsync is not a transaction target anymore */
			trans->unresolvable = alpm_list_add(trans->unresolvable, rsync);
		}

		alpm_list_free_inner(deps, (alpm_list_fn_free)alpm_conflict_free);
		alpm_list_free(deps);
		deps = NULL;

		/* 2. we check for target vs db conflicts (and resolve)*/
		_alpm_log(handle, ALPM_LOG_DEBUG, "check targets vs db and db vs targets\n");
		deps = _alpm_outerconflicts(handle->db_local, trans->add);

		for(i = deps; i; i = i->next) {
			alpm_question_conflict_t question = {
				.type = ALPM_QUESTION_CONFLICT_PKG,
				.remove = 0,
				.conflict = i->data
			};
			alpm_conflict_t *conflict = i->data;
			const char *name1 = conflict->package1->name;
			const char *name2 = conflict->package2->name;
			int found = 0;

			/* if name2 (the local package) is not elected for removal,
			   we ask the user */
			if(alpm_pkg_find(trans->remove, name2)) {
				found = 1;
			}
			for(j = trans->add; j && !found; j = j->next) {
				alpm_pkg_t *spkg = j->data;
				if(alpm_pkg_find(spkg->removes, name2)) {
					found = 1;
				}
			}
			if(found) {
				continue;
			}

			_alpm_log(handle, ALPM_LOG_DEBUG, "package '%s-%s' conflicts with '%s-%s'\n",
					name1, conflict->package1->version, name2,conflict->package2->version);

			QUESTION(handle, &question);
			if(question.remove) {
				/* append to the removes list */
				alpm_pkg_t *sync = alpm_pkg_find(trans->add, name1);
				alpm_pkg_t *local = _alpm_db_get_pkgfromcache(handle->db_local, name2);
				_alpm_log(handle, ALPM_LOG_DEBUG, "electing '%s' for removal\n", name2);
				sync->removes = alpm_list_add(sync->removes, local);
			} else { /* abort */
				_alpm_log(handle, ALPM_LOG_ERROR, _("unresolvable package conflicts detected\n"));
				handle->pm_errno = ALPM_ERR_CONFLICTING_DEPS;
				ret = -1;
				if(data) {
					alpm_conflict_t *newconflict = _alpm_conflict_dup(conflict);
					if(newconflict) {
						*data = alpm_list_add(*data, newconflict);
					}
				}
				alpm_list_free_inner(deps, (alpm_list_fn_free)alpm_conflict_free);
				alpm_list_free(deps);
				goto cleanup;
			}
		}
		event.type = ALPM_EVENT_INTERCONFLICTS_DONE;
		EVENT(handle, &event);
		alpm_list_free_inner(deps, (alpm_list_fn_free)alpm_conflict_free);
		alpm_list_free(deps);
	}

	/* Build trans->remove list */
	for(i = trans->add; i; i = i->next) {
		alpm_pkg_t *spkg = i->data;
		for(j = spkg->removes; j; j = j->next) {
			alpm_pkg_t *rpkg = j->data;
			if(!alpm_pkg_find(trans->remove, rpkg->name)) {
				alpm_pkg_t *copy;
				_alpm_log(handle, ALPM_LOG_DEBUG, "adding '%s' to remove list\n", rpkg->name);
				if(_alpm_pkg_dup(rpkg, &copy) == -1) {
					return -1;
				}
				trans->remove = alpm_list_add(trans->remove, copy);
			}
		}
	}

	if(!(trans->flags & ALPM_TRANS_FLAG_NODEPS)) {
		_alpm_log(handle, ALPM_LOG_DEBUG, "checking dependencies\n");
		deps = alpm_checkdeps(handle, _alpm_db_get_pkgcache(handle->db_local),
				trans->remove, trans->add, 1);
		if(deps) {
			handle->pm_errno = ALPM_ERR_UNSATISFIED_DEPS;
			ret = -1;
			if(data) {
				*data = deps;
			} else {
				alpm_list_free_inner(deps,
						(alpm_list_fn_free)alpm_depmissing_free);
				alpm_list_free(deps);
			}
			goto cleanup;
		}
	}
#ifdef HAVE_BTRPKG
	/* decide now which targets come as btrpkg cache files, so their download size and cache
	 * file names are right in what the frontend shows before the transaction. Not for a
	 * transaction that only shows what it would do (pacman -Sp sets NOLOCK): that stays the
	 * stock view, the repository's file names and sizes, with no network I/O, as root or not.
	 * If it is committed after all, _alpm_sync_load decides then. */
	if(!(trans->flags & ALPM_TRANS_FLAG_NOLOCK)) {
		btr_select(handle, _alpm_filecache_setup(handle));
		btr_plan(handle, _alpm_filecache_setup(handle), trans->add);
	}
#endif
	for(i = trans->add; i; i = i->next) {
		/* update download size field */
		alpm_pkg_t *spkg = i->data;
		alpm_pkg_t *lpkg = alpm_db_get_pkg(handle->db_local, spkg->name);
		if(compute_download_size(spkg) < 0) {
			ret = -1;
			goto cleanup;
		}
		if(lpkg && _alpm_pkg_dup(lpkg, &spkg->oldpkg) != 0) {
			ret = -1;
			goto cleanup;
		}
	}

cleanup:
	return ret;
}

off_t SYMEXPORT alpm_pkg_download_size(alpm_pkg_t *newpkg)
{
	if(!(newpkg->infolevel & INFRQ_DSIZE)) {
		compute_download_size(newpkg);
	}
	return newpkg->download_size;
}

/**
 * Prompts to delete the file now that we know it is invalid.
 * @param handle the context handle
 * @param filename the absolute path of the file to test
 * @param reason an error code indicating the reason for package invalidity
 *
 * @return 1 if file was removed, 0 otherwise
 */
static int prompt_to_delete(alpm_handle_t *handle, const char *filepath,
		alpm_errno_t reason)
{
	alpm_question_corrupted_t question = {
		.type = ALPM_QUESTION_CORRUPTED_PKG,
		.remove = 0,
		.filepath = filepath,
		.reason = reason
	};
	QUESTION(handle, &question);
	if(question.remove) {
		char *sig_filepath;

		unlink(filepath);

		sig_filepath = _alpm_sigpath(handle, filepath);
		unlink(sig_filepath);
		FREE(sig_filepath);
	}
	return question.remove;
}

static int find_dl_candidates(alpm_handle_t *handle, alpm_list_t **files)
{
	for(alpm_list_t *i = handle->trans->add; i; i = i->next) {
		alpm_pkg_t *spkg = i->data;

		if(spkg->origin != ALPM_PKG_FROM_FILE) {
			alpm_db_t *repo = spkg->origin_data.db;
			bool need_download;
			int siglevel = alpm_db_get_siglevel(alpm_pkg_get_db(spkg));

			if(!repo->servers) {
				handle->pm_errno = ALPM_ERR_SERVER_NONE;
				_alpm_log(handle, ALPM_LOG_ERROR, "%s: %s\n",
						alpm_strerror(handle->pm_errno), repo->treename);
				return -1;
			}

			ASSERT(spkg->filename != NULL, RET_ERR(handle, ALPM_ERR_PKG_INVALID_NAME, -1));

			need_download = spkg->download_size != 0 || !_alpm_filecache_exists(handle, spkg->filename);
			/* even if the package file in the cache we need to check for
			 * accompanion *.sig file as well.
			 * If *.sig is not cached then force download the package + its signature file.
			 */
			if(!need_download && (siglevel & ALPM_SIG_PACKAGE)) {
				char *sig_filename = NULL;
				int len = strlen(spkg->filename) + 5;

				MALLOC(sig_filename, len, RET_ERR(handle, ALPM_ERR_MEMORY, -1));
				snprintf(sig_filename, len, "%s.sig", spkg->filename);

				need_download = !_alpm_filecache_exists(handle, sig_filename);

				FREE(sig_filename);
			}

			if(need_download) {
				*files = alpm_list_add(*files, spkg);
			}
		}
	}

	return 0;
}


static int download_files(alpm_handle_t *handle)
{
	const char *cachedir;
	char * temporary_cachedir = NULL;
	alpm_list_t *i, *files = NULL;
	int ret = 0;
	alpm_event_t event;
	alpm_list_t *payloads = NULL;

	cachedir = _alpm_filecache_setup(handle);
	temporary_cachedir = _alpm_download_dir_setup(handle, cachedir);
	if(temporary_cachedir == NULL) {
		ret = -1;
		goto finish;
	}
	handle->trans->state = STATE_DOWNLOADING;

	ret = find_dl_candidates(handle, &files);
	if(ret != 0) {
		goto finish;
	}

	if(files) {
		/* check for necessary disk space for download */
		if(handle->checkspace) {
			off_t *file_sizes;
			size_t idx, num_files;

			_alpm_log(handle, ALPM_LOG_DEBUG, "checking available disk space for download\n");

			num_files = alpm_list_count(files);
			CALLOC(file_sizes, num_files, sizeof(off_t), goto finish);

			for(i = files, idx = 0; i; i = i->next, idx++) {
				const alpm_pkg_t *pkg = i->data;
				file_sizes[idx] = pkg->download_size;
			}

			ret = _alpm_check_downloadspace(handle, temporary_cachedir, num_files, file_sizes);
			free(file_sizes);

			if(ret != 0) {
				goto finish;
			}
		}

		event.type = ALPM_EVENT_PKG_RETRIEVE_START;
		event.pkg_retrieve.total_size = 0;
		event.pkg_retrieve.num = 0;

		/* sum up the number of packages to download and its total size */
		for(i = files; i; i = i->next) {
			alpm_pkg_t *spkg = i->data;
			event.pkg_retrieve.total_size += spkg->download_size;
			event.pkg_retrieve.num++;
		}

		EVENT(handle, &event);
#ifdef HAVE_BTRPKG
		/* btrpkg packages first (they are in the totals above); the rest as usual */
		ret = btr_download(handle, cachedir, &files);
		if(ret != 0) {
			event.type = ALPM_EVENT_PKG_RETRIEVE_FAILED;
			EVENT(handle, &event);
			goto finish;
		}
#endif
		for(i = files; i; i = i->next) {
			alpm_pkg_t *pkg = i->data;
			int siglevel = alpm_db_get_siglevel(alpm_pkg_get_db(pkg));
			struct dload_payload *payload = NULL;

			CALLOC(payload, 1, sizeof(*payload), GOTO_ERR(handle, ALPM_ERR_MEMORY, finish));
			STRDUP(payload->remote_name, pkg->filename, FREE(payload); GOTO_ERR(handle, ALPM_ERR_MEMORY, finish));
			STRDUP(payload->filepath, pkg->filename,
				_alpm_dload_payload_reset(payload); FREE(payload);
				GOTO_ERR(handle, ALPM_ERR_MEMORY, finish));
			payload->destfile_name = _alpm_get_fullpath(temporary_cachedir, payload->remote_name, "");
			payload->tempfile_name = _alpm_get_fullpath(temporary_cachedir, payload->remote_name, ".part");
			if(!payload->destfile_name || !payload->tempfile_name) {
				_alpm_dload_payload_reset(payload);
				FREE(payload);
				GOTO_ERR(handle, ALPM_ERR_MEMORY, finish);
			}
			payload->max_size = pkg->size;
			payload->cache_servers = pkg->origin_data.db->cache_servers;
			payload->servers = pkg->origin_data.db->servers;
			payload->handle = handle;
			payload->allow_resume = 1;
			payload->download_signature = (siglevel & ALPM_SIG_PACKAGE);
			payload->signature_optional = (siglevel & ALPM_SIG_PACKAGE_OPTIONAL);

			payloads = alpm_list_add(payloads, payload);
		}

		ret = payloads ? _alpm_download(handle, payloads, cachedir, temporary_cachedir) : 0;
		if(ret == -1) {
			event.type = ALPM_EVENT_PKG_RETRIEVE_FAILED;
			EVENT(handle, &event);
			_alpm_log(handle, ALPM_LOG_WARNING, _("failed to retrieve some files\n"));
			goto finish;
		}
		event.type = ALPM_EVENT_PKG_RETRIEVE_DONE;
		EVENT(handle, &event);
	}

finish:
	if(payloads) {
		alpm_list_free_inner(payloads, (alpm_list_fn_free)_alpm_dload_payload_reset);
		FREELIST(payloads);
	}

	if(files) {
		alpm_list_free(files);
	}

	for(i = handle->trans->add; i; i = i->next) {
		alpm_pkg_t *pkg = i->data;
		pkg->infolevel &= ~INFRQ_DSIZE;
		pkg->download_size = 0;
	}
	FREE(temporary_cachedir);

	return ret;
}

#ifdef HAVE_LIBGPGME

static int key_cmp(const void *k1, const void *k2) {
	const struct keyinfo_t *key1 = k1;
	const char *key2 = k2;

	return strcmp(key1->keyid, key2);
}

static int check_keyring(alpm_handle_t *handle)
{
	size_t current = 0, numtargs;
	alpm_list_t *i, *errors = NULL;
	alpm_event_t event;
	struct keyinfo_t *keyinfo;

	event.type = ALPM_EVENT_KEYRING_START;
	EVENT(handle, &event);

	numtargs = alpm_list_count(handle->trans->add);

	for(i = handle->trans->add; i; i = i->next, current++) {
		alpm_pkg_t *pkg = i->data;
		int level;

		int percent = (current * 100) / numtargs;
		PROGRESS(handle, ALPM_PROGRESS_KEYRING_START, "", percent,
				numtargs, current);

		if(pkg->origin == ALPM_PKG_FROM_FILE) {
			continue; /* pkg_load() has been already called, this package is valid */
		}
		if(pkg->btr) {
			continue; /* signify signature, checked in check_validity */
		}

		level = alpm_db_get_siglevel(alpm_pkg_get_db(pkg));
		if((level & ALPM_SIG_PACKAGE)) {
			unsigned char *sig = NULL;
			size_t sig_len;
			int ret = alpm_pkg_get_sig(pkg, &sig, &sig_len);
			if(ret == 0) {
				alpm_list_t *keys = NULL;
				if(alpm_extract_keyid(handle, pkg->name, sig,
							sig_len, &keys) == 0) {
					alpm_list_t *k;
					for(k = keys; k; k = k->next) {
						char *key = k->data;
						_alpm_log(handle, ALPM_LOG_DEBUG, "found signature key: %s\n", key);
						if(!alpm_list_find(errors, key, key_cmp) &&
								_alpm_key_in_keychain(handle, key) == 0) {
							keyinfo = malloc(sizeof(struct keyinfo_t));
							if(!keyinfo) {
								break;
							}
							keyinfo->uid = strdup(pkg->packager);
							keyinfo->keyid = strdup(key);
							errors = alpm_list_add(errors, keyinfo);
						}
					}
					FREELIST(keys);
				}
			}
			free(sig);
		}
	}

	PROGRESS(handle, ALPM_PROGRESS_KEYRING_START, "", 100,
			numtargs, current);
	event.type = ALPM_EVENT_KEYRING_DONE;
	EVENT(handle, &event);

	if(errors) {
		event.type = ALPM_EVENT_KEY_DOWNLOAD_START;
		EVENT(handle, &event);
		int fail = 0;
		alpm_list_t *k;
		for(k = errors; k; k = k->next) {
			keyinfo = k->data;
			if(_alpm_key_import(handle, keyinfo->uid, keyinfo->keyid) == -1) {
				fail = 1;
			}
			free(keyinfo->uid);
			free(keyinfo->keyid);
			free(keyinfo);
		}
		alpm_list_free(errors);
		event.type = ALPM_EVENT_KEY_DOWNLOAD_DONE;
		EVENT(handle, &event);
		if(fail) {
			_alpm_log(handle, ALPM_LOG_ERROR, _("required key missing from keyring\n"));
			return -1;
		}
	}

	return 0;
}
#endif /* HAVE_LIBGPGME */

static int check_validity(alpm_handle_t *handle,
		size_t total, uint64_t total_bytes)
{
	struct validity {
		alpm_pkg_t *pkg;
		char *path;
		alpm_siglist_t *siglist;
		int siglevel;
		int validation;
		alpm_errno_t error;
	};
	size_t current = 0;
	uint64_t current_bytes = 0;
	alpm_list_t *i, *errors = NULL;
	alpm_event_t event;

	/* Check integrity of packages */
	event.type = ALPM_EVENT_INTEGRITY_START;
	EVENT(handle, &event);

	for(i = handle->trans->add; i; i = i->next, current++) {
		struct validity v = { i->data, NULL, NULL, 0, 0, 0 };
		int percent = (int)(((double)current_bytes / total_bytes) * 100);

		PROGRESS(handle, ALPM_PROGRESS_INTEGRITY_START, "", percent,
				total, current);
		if(v.pkg->origin == ALPM_PKG_FROM_FILE) {
			continue; /* pkg_load() has been already called, this package is valid */
		}

		current_bytes += v.pkg->size;
		v.path = _alpm_filecache_find(handle, v.pkg->filename);

		if(!v.path) {
			_alpm_log(handle, ALPM_LOG_ERROR,
					_("%s: could not find package in cache\n"), v.pkg->name);
			RET_ERR(handle, ALPM_ERR_PKG_NOT_FOUND, -1);
		}

		v.siglevel = alpm_db_get_siglevel(alpm_pkg_get_db(v.pkg));

		int invalid_pkg;
#ifdef HAVE_BTRPKG
		if(v.pkg->btr) {
			invalid_pkg = btr_validate(handle, v.pkg, v.path, v.siglevel, &v.validation) == -1;
		} else
#endif
		invalid_pkg = _alpm_pkg_validate_internal(handle, v.path, v.pkg,
					v.siglevel, &v.siglist, &v.validation) == -1;
		if(invalid_pkg) {
			struct validity *invalid;
			v.error = handle->pm_errno;
			MALLOC(invalid, sizeof(struct validity), return -1);
			memcpy(invalid, &v, sizeof(struct validity));
			errors = alpm_list_add(errors, invalid);
		} else {
			alpm_siglist_cleanup(v.siglist);
			free(v.siglist);
			free(v.path);
			v.pkg->validation = v.validation;
		}
	}

	PROGRESS(handle, ALPM_PROGRESS_INTEGRITY_START, "", 100,
			total, current);
	event.type = ALPM_EVENT_INTEGRITY_DONE;
	EVENT(handle, &event);

	if(errors) {
		for(i = errors; i; i = i->next) {
			struct validity *v = i->data;
			switch(v->error) {
				case ALPM_ERR_PKG_MISSING_SIG:
					_alpm_log(handle, ALPM_LOG_ERROR,
							_("%s: missing required signature\n"), v->pkg->name);
					break;
				case ALPM_ERR_PKG_INVALID_SIG:
					_alpm_process_siglist(handle, v->pkg->name, v->siglist,
							v->siglevel & ALPM_SIG_PACKAGE_OPTIONAL,
							v->siglevel & ALPM_SIG_PACKAGE_MARGINAL_OK,
							v->siglevel & ALPM_SIG_PACKAGE_UNKNOWN_OK);
					__attribute__((fallthrough));
				case ALPM_ERR_PKG_INVALID_CHECKSUM:
					prompt_to_delete(handle, v->path, v->error);
					break;
				case ALPM_ERR_PKG_NOT_FOUND:
				case ALPM_ERR_BADPERMS:
				case ALPM_ERR_PKG_OPEN:
					_alpm_log(handle, ALPM_LOG_ERROR, _("failed to read file %s: %s\n"), v->path, alpm_strerror(v->error));
					break;
				default:
					/* ignore */
					break;
			}
			alpm_siglist_cleanup(v->siglist);
			free(v->siglist);
			free(v->path);
			free(v);
		}
		alpm_list_free(errors);

		if(handle->pm_errno == ALPM_ERR_OK) {
			RET_ERR(handle, ALPM_ERR_PKG_INVALID, -1);
		}
		return -1;
	}

	return 0;
}

static int dep_not_equal(const alpm_depend_t *left, const alpm_depend_t *right)
{
	return left->name_hash != right->name_hash
		|| strcmp(left->name, right->name) != 0
		|| left->mod != right->mod
		|| (left->version == NULL) != (right->version == NULL)
		|| ((left->version && right->version) && strcmp(left->version, right->version) != 0);
}

static int check_pkg_field_matches_db(alpm_handle_t *handle, const char *field,
		alpm_list_t *left, alpm_list_t *right, alpm_list_fn_cmp cmp)
{
	switch(alpm_list_cmp_unsorted(left, right, cmp)) {
		case 0:
			_alpm_log(handle, ALPM_LOG_DEBUG,
					"internal package %s mismatch\n", field);
			return 1;
		case 1:
			return 0;
		default:
			RET_ERR(handle, ALPM_ERR_MEMORY, -1);
	}
}

static int check_pkg_matches_db(alpm_pkg_t *spkg, alpm_pkg_t *pkgfile)
{
	alpm_handle_t *handle = spkg->handle;
	int error = 0;

#define CHECK_FIELD(STR, FIELD, CMP) do { \
	int ok = check_pkg_field_matches_db(handle, STR, spkg->FIELD, pkgfile->FIELD, (alpm_list_fn_cmp)CMP); \
	if(ok == -1) { \
		return 1; \
	} else if(ok != 0) { \
		error = 1; \
	} \
} while(0)

	if(strcmp(spkg->name, pkgfile->name) != 0) {
		_alpm_log(handle, ALPM_LOG_DEBUG,
				"internal package name mismatch, expected: '%s', actual: '%s'\n",
				spkg->name, pkgfile->name);
		error = 1;
	}
	if(strcmp(spkg->version, pkgfile->version) != 0) {
		_alpm_log(handle, ALPM_LOG_DEBUG,
				"internal package version mismatch, expected: '%s', actual: '%s'\n",
				spkg->version, pkgfile->version);
		error = 1;
	}
	if(spkg->isize != pkgfile->isize) {
		_alpm_log(handle, ALPM_LOG_DEBUG,
				"internal package install size mismatch, expected: '%ld', actual: '%ld'\n",
				spkg->isize, pkgfile->isize);
		error = 1;
	}

	CHECK_FIELD("depends", depends, dep_not_equal);
	CHECK_FIELD("conflicts", conflicts, dep_not_equal);
	CHECK_FIELD("replaces", replaces, dep_not_equal);
	CHECK_FIELD("provides", provides, dep_not_equal);
	CHECK_FIELD("groups", groups, strcmp);

#undef CHECK_FIELD

	return error;
}


static int load_packages(alpm_handle_t *handle, alpm_list_t **data,
		size_t total, size_t total_bytes)
{
	size_t current = 0, current_bytes = 0;
	int errors = 0;
	alpm_list_t *i, *delete = NULL;
	alpm_event_t event;

	/* load packages from disk now that they are known-valid */
	event.type = ALPM_EVENT_LOAD_START;
	EVENT(handle, &event);

	for(i = handle->trans->add; i; i = i->next, current++) {
		int error = 0;
		alpm_pkg_t *spkg = i->data;
		char *filepath;
		int percent = (int)(((double)current_bytes / total_bytes) * 100);

		PROGRESS(handle, ALPM_PROGRESS_LOAD_START, "", percent,
				total, current);
		if(spkg->origin == ALPM_PKG_FROM_FILE) {
			continue; /* pkg_load() has been already called, this package is valid */
		}

		current_bytes += spkg->size;
		filepath = _alpm_filecache_find(handle, spkg->filename);

		if(!filepath) {
			FREELIST(delete);
			_alpm_log(handle, ALPM_LOG_ERROR,
					_("%s: could not find package in cache\n"), spkg->name);
			RET_ERR(handle, ALPM_ERR_PKG_NOT_FOUND, -1);
		}

		/* load the package file and replace pkgcache entry with it in the target list */
		/* TODO: alpm_pkg_get_db() will not work on this target anymore */
		_alpm_log(handle, ALPM_LOG_DEBUG,
				"replacing pkgcache entry with package file for target %s\n",
				spkg->name);
		alpm_pkg_t *pkgfile =_alpm_pkg_load_internal(handle, filepath, 1);
		if(!pkgfile) {
			_alpm_log(handle, ALPM_LOG_DEBUG, "failed to load pkgfile internal\n");
			error = 1;
		} else {
			error |= check_pkg_matches_db(spkg, pkgfile);
		}
		if(error != 0) {
			errors++;
			*data = alpm_list_add(*data, strdup(spkg->filename));
			delete = alpm_list_add(delete, filepath);
			_alpm_pkg_free(pkgfile);
			continue;
		}
		free(filepath);
		/* copy over the install reason */
		pkgfile->reason = spkg->reason;
		/* copy over validation method */
		pkgfile->validation = spkg->validation;
#ifdef HAVE_BTRPKG
		/* the signature record, or (unsigned) none: never what the package's own .PKGINFO says */
		if(spkg->btr && _alpm_pkg_set_btr_signer(pkgfile, spkg->btr_signer) != 0) {
			_alpm_pkg_free(pkgfile);
			RET_ERR(handle, ALPM_ERR_MEMORY, -1);
		}
#endif
		/* transfer oldpkg */
		pkgfile->oldpkg = spkg->oldpkg;
		spkg->oldpkg = NULL;
		i->data = pkgfile;
		/* spkg has been removed from the target list, so we can free the
		 * sync-specific fields */
		_alpm_pkg_free_trans(spkg);
	}

	PROGRESS(handle, ALPM_PROGRESS_LOAD_START, "", 100,
			total, current);
	event.type = ALPM_EVENT_LOAD_DONE;
	EVENT(handle, &event);

	if(errors) {
		for(i = delete; i; i = i->next) {
			prompt_to_delete(handle, i->data, ALPM_ERR_PKG_INVALID);
		}
		FREELIST(delete);

		if(handle->pm_errno == ALPM_ERR_OK) {
			RET_ERR(handle, ALPM_ERR_PKG_INVALID, -1);
		}
		return -1;
	}

	return 0;
}

int _alpm_sync_load(alpm_handle_t *handle, alpm_list_t **data)
{
	alpm_list_t *i;
	size_t total = 0;
	uint64_t total_bytes = 0;
	alpm_trans_t *trans = handle->trans;

#ifdef HAVE_BTRPKG
	btr_select(handle, _alpm_filecache_setup(handle));
	btr_plan(handle, _alpm_filecache_setup(handle), trans->add);
#endif
	if(download_files(handle) == -1) {
		return -1;
	}

#ifdef HAVE_LIBGPGME
	/* make sure all required signatures are in keyring */
	if(check_keyring(handle)) {
		return -1;
	}
#endif

	/* get the total size of all packages so we can adjust the progress bar more
	 * realistically if there are small and huge packages involved */
	for(i = trans->add; i; i = i->next) {
		alpm_pkg_t *spkg = i->data;
		if(spkg->origin != ALPM_PKG_FROM_FILE) {
			total_bytes += spkg->size;
		}
		total++;
	}
	/* this can only happen maliciously */
	total_bytes = total_bytes ? total_bytes : 1;

	if(check_validity(handle, total, total_bytes) != 0) {
		return -1;
	}

	if(trans->flags & ALPM_TRANS_FLAG_DOWNLOADONLY) {
		return 0;
	}

	if(load_packages(handle, data, total, total_bytes)) {
		return -1;
	}

	return 0;
}

int _alpm_sync_check(alpm_handle_t *handle, alpm_list_t **data)
{
	alpm_trans_t *trans = handle->trans;
	alpm_event_t event;

	/* fileconflict check */
	if(!(trans->flags & ALPM_TRANS_FLAG_DBONLY)) {
		event.type = ALPM_EVENT_FILECONFLICTS_START;
		EVENT(handle, &event);

		_alpm_log(handle, ALPM_LOG_DEBUG, "looking for file conflicts\n");
		alpm_list_t *conflict = _alpm_db_find_fileconflicts(handle,
				trans->add, trans->remove);
		if(conflict) {
			if(data) {
				*data = conflict;
			} else {
				alpm_list_free_inner(conflict,
						(alpm_list_fn_free)alpm_fileconflict_free);
				alpm_list_free(conflict);
			}
			RET_ERR(handle, ALPM_ERR_FILE_CONFLICTS, -1);
		}

		event.type = ALPM_EVENT_FILECONFLICTS_DONE;
		EVENT(handle, &event);
	}

	/* check available disk space */
	if(handle->checkspace && !(trans->flags & ALPM_TRANS_FLAG_DBONLY)) {
		event.type = ALPM_EVENT_DISKSPACE_START;
		EVENT(handle, &event);

		_alpm_log(handle, ALPM_LOG_DEBUG, "checking available disk space\n");
		if(_alpm_check_diskspace(handle) == -1) {
			_alpm_log(handle, ALPM_LOG_ERROR, _("not enough free disk space\n"));
			return -1;
		}

		event.type = ALPM_EVENT_DISKSPACE_DONE;
		EVENT(handle, &event);
	}

	return 0;
}

int _alpm_sync_commit(alpm_handle_t *handle)
{
	alpm_trans_t *trans = handle->trans;

	/* remove conflicting and to-be-replaced packages */
	if(trans->remove) {
		_alpm_log(handle, ALPM_LOG_DEBUG,
				"removing conflicting and to-be-replaced packages\n");
		/* we want the frontend to be aware of commit details */
		if(_alpm_remove_packages(handle, 0) == -1) {
			_alpm_log(handle, ALPM_LOG_ERROR,
					_("could not commit removal transaction\n"));
			return -1;
		}
	}

	/* install targets */
	_alpm_log(handle, ALPM_LOG_DEBUG, "installing packages\n");
	if(_alpm_upgrade_packages(handle) == -1) {
		_alpm_log(handle, ALPM_LOG_ERROR, _("could not commit transaction\n"));
		return -1;
	}

	return 0;
}
