#include "vm/swap.h"

#define SECTOR_OFFSET SECTORS_IN_A_PAGE

void create_bitmap(struct block *swap_space);

/**
 * Initializing the swap space, swap bitmap and the lock.
 */
void initialize_swap_space(void) {
	/**
	 * Getting the swap block.
	 */
	swap_space = block_get_role(BLOCK_SWAP);

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
	block_sector_t sectors_in_a_block = block_size(swap_space);

	/**
	 * Calculating size of bitmap
	 */
	size_t size_of_bitmap = sectors_in_a_block / SECTORS_IN_A_PAGE;

	/**
	 * Creating a bitmap where each value represents a frame.
	 */
	swap_bitmap = bitmap_create(size_of_bitmap);

	if (swap_bitmap == NULL) {
		PANIC("Failed to create swap bitmap");
	}

	/**
	 * Initializing the entire bitmap to 0.
	 */
	bitmap_set_all(swap_bitmap, FREE_VALUE);
	lock_init(&swap_block_lock);
}

/**
 * Putting the given frame in swap space and returning the index.
 */
size_t put_frame_in_swap(void *frame) {
	/**
	 * Panic if swap space of bitmap was not created.
	 */
	if (!swap_space || !swap_bitmap) {
		PANIC("Swap space not found.");
	}

	lock_acquire(&swap_block_lock);

	/**
	 * Find the first free bit which represents a frame that can be used to swap the given frame. Also, flip the bit to 1.
	 */
	size_t first_free_bit = bitmap_scan_and_flip(swap_bitmap, 0, 1, FREE_VALUE);

	if (first_free_bit == BITMAP_ERROR) {
		PANIC("No more space in swap space");
	}

	int index;
	block_sector_t sector;
	void *buffer;

	/**
	 * Write sector by sector.
	 */
	for (index = 0; index < SECTORS_IN_A_PAGE; index++) {
		sector = index + first_free_bit * SECTOR_OFFSET;
		buffer = index * BLOCK_SECTOR_SIZE + frame;
		block_write(swap_space, sector, (uint8_t*) buffer);
	}
	lock_release(&swap_block_lock);

	/**
	 * Returns the index.
	 */
	return first_free_bit;
}

/**
 *Removing the frame from swap space and putting in RAM.
 */
void get_frame_from_swap(size_t swap_index, void* frame) {
	/**
	 * Panic if swap space of bitmap was not created.
	 */
	if (!swap_space || !swap_bitmap) {
		return;
	}

	lock_acquire(&swap_block_lock);

	/**
	 * If trying to read the value of swap space where nothing was swapped, then Panic.
	 */
	if (bitmap_test(swap_bitmap, swap_index) == FREE_VALUE) {
		PANIC("Swap space for given frame is empty!!");
	}

	/**
	 * Flip the bit to 0, i.e. making it free for further use.
	 */
	bitmap_flip(swap_bitmap, swap_index);

	int index;
	block_sector_t sector;
	void *buffer;

	/**
	 * Reading sector by sector.
	 */
	for (index = 0; index < SECTORS_IN_A_PAGE; index++) {
		sector = index + swap_index * SECTOR_OFFSET;
		buffer = index * BLOCK_SECTOR_SIZE + frame;
		block_read(swap_space, sector, (uint8_t*) buffer);
	}

	lock_release(&swap_block_lock);
}
