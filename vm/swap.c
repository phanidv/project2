#include "vm/swap.h"

#define SECTOR_OFFSET SECTORS_IN_A_PAGE

void create_bitmap(struct block *swap_space);

block_sector_t find_first_free();
void swap_store (size_t first_free_bit, void *frame);

void free_swap_bits(size_t swap_index);
void swap_load(size_t swap_index, void* frame);

/**
 * Initializing the swap space, swap bitmap and the lock.
 */
void initialize_swap_space(void) {

	// Getting the swap block.
	swap_space = block_get_role(BLOCK_SWAP);

	lock_init(&swap_block_lock);

	if (swap_space == NULL) {

		PANIC("Failed to create swap space");
	}
	create_bitmap(swap_space);
}

/**
 * Initializes the bitmap.
 */
void create_bitmap(struct block *swap_space)
{
	block_sector_t swap_size = block_size(swap_space);

	/**
	 * Creating a bitmap where each value represents a sector.
	 */
	swap_bitmap = bitmap_create(swap_size);

	if (swap_bitmap == NULL) {

		PANIC("Failed to create swap bitmap");
	}

	/**
	 * Initializing the entire bitmap to 0.
	 */
	bitmap_set_all(swap_bitmap, FREE_VALUE);
}

/**
 * Putting the given frame in swap space and returning the index.
 */
size_t put_frame_in_swap(void *frame) {

	// Panic if swap space of bitmap was not created.
	if (!swap_space || !swap_bitmap) {

		PANIC("Swap space not found.");
	}

	lock_acquire(&swap_block_lock);

	// Retrieving the first contiguous free sector of size PGSIZE/BLOCK_SIZE
	block_sector_t first_free = find_first_free();

	// Storing the page into swap space
	swap_store(first_free, frame);

	lock_release(&swap_block_lock);

	return first_free;
}

/**
 * Finds the first contiguous free sector that can be used to swap the given frame.
 * Also, flips the bit to 1.
 */
block_sector_t find_first_free() {

	block_sector_t first_free = bitmap_scan_and_flip(swap_bitmap, 0,
			PGSIZE / BLOCK_SECTOR_SIZE, false);

	// No space in the swap
	if (first_free == BITMAP_ERROR) {

		PANIC("No more space in swap space");
	}

	return first_free;
}


/*
 * Writes a page from memory onto the swap space
 */
void swap_store(size_t first_free_bit, void *frame) {

	int i;
	for (i = 0; i < PGSIZE / BLOCK_SECTOR_SIZE; i++) {
		block_write(swap_space, first_free_bit + i,
				frame + i * BLOCK_SECTOR_SIZE);
	}
}

/**
 * Removes the frame from swap space and putting in RAM.
 */
void get_frame_from_swap(size_t swap_index, void* frame) {

	// Panic if swap space or bitmap was not created.
	if (!swap_space || !swap_bitmap) {

		PANIC("Swap space not found.");
	}

	lock_acquire(&swap_block_lock);

	//
	free_swap_bits(swap_index);

	swap_load(swap_index, frame);

	lock_release(&swap_block_lock);
}

/**
 * Frees the swap bits starting at the swap_index of size PGSIZE/BLOCK_SIZE
 */
void free_swap_bits(size_t swap_index) {

	// If trying to read the value of swap space where nothing was swapped, then Panic.
	if (bitmap_test(swap_bitmap, swap_index) == FREE_VALUE) {
		PANIC("Swap space for given frame is empty!!");
	}

	// Flip the bits to 0, i.e. making it free for further use.
	bitmap_set_multiple(swap_bitmap, swap_index, PGSIZE / BLOCK_SECTOR_SIZE, false);
}

/**
 * Loads the page referenced by swap_index from swap space onto the memory
 */
void swap_load(size_t swap_index, void* frame) {

	int i;
	for (i = 0; i < PGSIZE / BLOCK_SECTOR_SIZE; i++) {
		block_read(swap_space, swap_index + i, frame + i * BLOCK_SECTOR_SIZE);
	}
}
