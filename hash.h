
/*
 * s3backer - FUSE-based single file backing store via Amazon S3
 * 
 * Copyright 2008-2011 Archie L. Cobbs <archie@dellroad.org>
 * 
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 * 
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 * 
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
 * 02110-1301, USA.
 */

/*
 * Our hash table implementation.
 *
 * We make the following simplifying assumptions:
 *
 * 1.  Keys are of type cb_block_t
 * 2.  Values are structures in which the first field is the key
 * 3.  No attempts will be made to overload the table
 */

/* Definitions */
typedef void cb_hash_visit_t(void *arg, void *value);

/* Declarations */
struct cb_hash;

/* hash.c */
extern int cb_hash_create(struct cb_hash **hashp, u_int maxkeys);
extern void cb_hash_destroy(struct cb_hash *hash);
extern u_int cb_hash_size(struct cb_hash *hash);
extern void *cb_hash_get(struct cb_hash *hash, cb_block_t key);
extern void *cb_hash_put(struct cb_hash *hash, void *value);
extern void cb_hash_put_new(struct cb_hash *hash, void *value);
extern void cb_hash_remove(struct cb_hash *hash, cb_block_t key);
extern void cb_hash_foreach(struct cb_hash *hash, cb_hash_visit_t *visitor, void *arg);

