/*
 *  btrstream.h
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
#ifndef ALPM_BTRSTREAM_H
#define ALPM_BTRSTREAM_H

#include <stdint.h>

struct archive;

/* Whether fd is a btrpkg file (index, transport or cache file). */
int _alpm_btr_is_cache_file(int fd);

/* Check the index at the start of a cache file: everything btr_index_parse checks, the header
 * ID when expected_id is not NULL, and that the file is as long as the index says. err:
 * BTR_ERRLEN bytes. */
int _alpm_btr_validate(int fd, const unsigned char *expected_id, uint64_t file_size, char *err);

/* For a cache file that didn't come from pull-ids (pacman -U): every chunk's unencoded data,
 * read back through the file, must have the index's hash. pull-ids checks each chunk as it
 * assembles a cache file; nothing else does. */
int _alpm_btr_check_data(int fd, uint64_t file_size, char *err);

/* The btrpkg key directories, as btrpkg itself searches them. */
extern const char *const _alpm_btr_keydirs[];

/* The signify signature of the cache file at path (path.sig) over its header, by a key in
 * _alpm_btr_keydirs. 0: signed, keypath (PATH_MAX) names the key; 1: no signature file;
 * -1: a bad signature or a read error, err says which. */
int _alpm_btr_check_sig(int fd, const char *path, char *keypath, char *err);

/* Open archive `a` (formats already enabled) on the cache file fd as a tar stream. fd stays
 * owned by the caller and must outlive the archive. */
int _alpm_btr_archive_open(struct archive *a, int fd, uint64_t file_size, char *err);

/* If the entry `a` is positioned at is a large file of a btrpkg archive whose data hasn't been
 * read yet, its place in the cache file: 1 with fd, offset and size set; 0 otherwise. The data
 * at off is block-aligned and zero-padded to a 4 KiB boundary. */
int _alpm_btr_large_file(struct archive *a, const char *entryname, int *fd, uint64_t *off,
		uint64_t *size);

#endif /* ALPM_BTRSTREAM_H */
