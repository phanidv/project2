#ifndef VM_SWAP_H
#define VM_SWAP_H

#include "devices/block.h"
#include "threads/synch.h"
#include "threads/vaddr.h"
#include <bitmap.h>

/**
 * Number of pages in a sector.
 */
#define SECTORS_IN_A_PAGE (PGSIZE / BLOCK_SECTOR_SIZE)

/**
 * Value that will represent free space in a bitmap.
 */
#define FREE_VALUE 0

/**
 * Block that will represent swap space.
 */
struct block *swap_space;

/**
 * Bitmap that will keep the track of free/used space in swap space.
 */
struct bitmap *swap_bitmap;

/**
 * Lock that will be used while doing swap related tasks.
 */
struct lock swap_block_lock;

void initialize_swap_space (void);
size_t put_frame_in_swap (void *frame);
void get_frame_from_swap (size_t used_index, void* frame);

#endif /* vm/swap.h */
