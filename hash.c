
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
 * This is a simple closed hash table implementation with linear probing.
 * We pre-allocate the hash array based on the expected maximum size.
 */

#include "cloudbacker.h"
#include "hash.h"

/* Definitions */
#define LOAD_FACTOR                 0.666666
#define FIRST(hash, key)            (cb_hash_index((hash), (key)))
#define NEXT(hash, index)           ((index) + 1 < (hash)->alen ? (index) + 1 : 0)
#define EMPTY(value)                ((value) == NULL)
#define VALUE(hash, index)          ((hash)->array[(index)])
#define KEY(value)                  (*(cb_block_t *)(value))

/* Hash table structure */
struct cb_hash {
    u_int       maxkeys;            /* max capacity */
    u_int       numkeys;            /* number of keys in table */
    u_int       alen;               /* hash array length */
    void        *array[0];          /* hash array */
};

/* Declarations */
static u_int cb_hash_index(struct cb_hash *hash, cb_block_t key);

/* Public functions */

int
cb_hash_create(struct cb_hash **hashp, u_int maxkeys)
{
    struct cb_hash *hash;
    u_int alen;

    if (maxkeys >= (u_int)(UINT_MAX * LOAD_FACTOR) - 1)
        return EINVAL;
    alen = (u_int)(maxkeys / LOAD_FACTOR) + 1;
    if ((hash = calloc(1, sizeof(*hash) + alen * sizeof(*hash->array))) == NULL)
        return ENOMEM;
    hash->maxkeys = maxkeys;
    hash->alen = alen;
    *hashp = hash;
    return 0;
}

void
cb_hash_destroy(struct cb_hash *hash)
{
    free(hash);
}

u_int
cb_hash_size(struct cb_hash *hash)
{
    return hash->numkeys;
}

void *
cb_hash_get(struct cb_hash *hash, cb_block_t key)
{
    u_int i;

    for (i = FIRST(hash, key); 1; i = NEXT(hash, i)) {
        void *const value = VALUE(hash, i);

        if (EMPTY(value))
            return NULL;
        if (KEY(value) == key)
            return value;
    }
}

void *
cb_hash_put(struct cb_hash *hash, void *value)
{
    const cb_block_t key = KEY(value);
    u_int i;

    for (i = FIRST(hash, key); 1; i = NEXT(hash, i)) {
        void *const value2 = VALUE(hash, i);

        if (EMPTY(value))
            break;
        if (KEY(value2) == key) {
            VALUE(hash, i) = value;         /* replace existing value having the same key with new value */
            return value2;
        }
    }
    assert(hash->numkeys < hash->maxkeys);
    VALUE(hash, i) = value;
    hash->numkeys++;
    return NULL;
}

/*
 * Optimization of cb_hash_put() for when it is known that no matching entry exists.
 */
void
cb_hash_put_new(struct cb_hash *hash, void *value)
{
    const cb_block_t key = KEY(value);
    u_int i;

    for (i = FIRST(hash, key); 1; i = NEXT(hash, i)) {
        void *const value2 = VALUE(hash, i);

        if (EMPTY(value2))
            break;
        assert(KEY(value2) != key);
    }
    assert(hash->numkeys < hash->maxkeys);
    VALUE(hash, i) = value;
    hash->numkeys++;
}

void
cb_hash_remove(struct cb_hash *hash, cb_block_t key)
{
    u_int i;
    u_int j;
    u_int k;

    /* Find entry */
    for (i = FIRST(hash, key); 1; i = NEXT(hash, i)) {
        void *const value = VALUE(hash, i);

        if (EMPTY(value))               /* no such entry */
            return;
        if (KEY(value) == key)          /* entry found */
            break;
    }

    /* Repair subsequent entries as necessary */
    for (j = NEXT(hash, i); 1; j = NEXT(hash, j)) {
        void *const value = VALUE(hash, j);

        if (value == NULL)
            break;
        k = FIRST(hash, KEY(value));
        if (j > i ? (k <= i || k > j) : (k <= i && k > j)) {
            VALUE(hash, i) = value;
            i = j;
        }
    }

    /* Remove entry */
    assert(VALUE(hash, i) != NULL);
    VALUE(hash, i) = NULL;
    hash->numkeys--;
}

void
cb_hash_foreach(struct cb_hash *hash, cb_hash_visit_t *visitor, void *arg)
{
    u_int i;

    for (i = 0; i < hash->alen; i++) {
        void *const value = VALUE(hash, i);

        if (value != NULL)
            (*visitor)(arg, value);
    }
}

/*
 * Jenkins one-at-a-time hash
 */
static u_int
cb_hash_index(struct cb_hash *hash, cb_block_t key)
{
    u_int value = 0;
    int i;
 
    for (i = 0; i < sizeof(key); i++) {
        value += ((u_char *)&key)[i];
        value += (value << 10);
        value ^= (value >> 6);
    }
    value += (value << 3);
    value ^= (value >> 11);
    value += (value << 15);
    return value % hash->alen;
}

