#include "filesys/file.h"
#include "threads/malloc.h"
#include "threads/palloc.h"
#include "threads/synch.h"
#include "threads/thread.h"
#include "userprog/pagedir.h"
#include "userprog/syscall.h"
#include "vm/frame.h"
#include "vm/page.h"
#include "vm/swap.h"

void create_frame_table_entry(void *frame, struct supplemental_pte *spte);
void* evict_frame_using_clock(enum palloc_flags flags);
struct list_elem * get_element_to_be_eliminated();
void eliminate_frame(struct list_elem *e);
void eliminate_frame(struct list_elem *e);
void swap_or_flush(struct frame_table_entry *fte);
void flush_mmap(struct frame_table_entry *fte);

/**
 * Initializes the frame table and frame_table_lock.
 */
void initialize_frame_table(void) {
	list_init(&frame_table);
	lock_init(&frame_table_lock);
}

/**
 * Gets a frame from the memory.
 */
void* get_frame(enum palloc_flags flags, struct supplemental_pte *spte) {
	/**
	 * Return NULL if flag is PAL_ZERO or PAL_ASSERT.
	 */
	if (flags == PAL_ZERO || flags == PAL_ASSERT) {
		return NULL;
	}

	void *frame = palloc_get_page(flags);

	if (frame == NULL) {

		/**
		 * Get a frame using the clock algorithm that will evict one.
		 */
		frame = evict_frame_using_clock(flags);
		/**
		 * If still no luck, PANIC.
		 */
		if (frame == NULL) {
			PANIC("Frame eviction failed!!!");
		}
	}

	/**
	 * Create a new frame table entry for the newly allocated frame.
	 */
	create_frame_table_entry(frame, spte);

	return frame;
}

/**
 * Frees the given frame table entry and frame.
 */
void free_frame_table_entry(struct frame_table_entry *fte, void *frame) {
	lock_acquire(&frame_table_lock);
	list_remove(&fte->elem);
	free(fte);
	palloc_free_page(frame);
	lock_release(&frame_table_lock);
}

/**
 * Creates a new frame table entry and adds it to the list of frame table.
 */
void create_frame_table_entry(void *frame, struct supplemental_pte *spte) {
	lock_acquire(&frame_table_lock);
	struct frame_table_entry *frame_table_entry_ = malloc(
			sizeof(struct frame_table_entry));
	frame_table_entry_->frame = frame;
	frame_table_entry_->supplementary_page_entry_ = spte;
	frame_table_entry_->pagedir = thread_current()->pagedir;
	spte->frame_table_entry_ = frame_table_entry_;
	list_push_back(&frame_table, &frame_table_entry_->elem);
	lock_release(&frame_table_lock);
}

/**
 * Evicts a frame using the clock algorithm and returns it.
 */
void* evict_frame_using_clock(enum palloc_flags flags) {

	lock_acquire(&frame_table_lock);

	// Find the element to be eliminated
	struct list_elem *e = NULL;

	/**
	 * Keep finding till we find one element.
	 */
	while (e == NULL) {
		e = get_element_to_be_eliminated();
	}

	// Eliminate it
	eliminate_frame(e);

	lock_release(&frame_table_lock);

	// Return the frame.
	return palloc_get_page(flags);
}

/**
 * Eliminate the frame represented by frame_table_enrty represented by list_elem e.
 */
void eliminate_frame(struct list_elem *e) {
	struct frame_table_entry *fte =
			list_entry(e, struct frame_table_entry, elem);

	// If frame is dirty
	if (pagedir_is_dirty(fte->pagedir, fte->supplementary_page_entry_->user_virtual_address)) {
		swap_or_flush(fte);
	}

	// Finally eliminate the frame.
	list_remove(&fte->elem);
	fte->supplementary_page_entry_->is_page_loaded = false;
	palloc_free_page(fte->frame);
	pagedir_clear_page(fte->pagedir, fte->supplementary_page_entry_->user_virtual_address);
	free(fte);
}

/**
 * Swap or flush the frame depending on its type.
 */
void swap_or_flush(struct frame_table_entry *fte) {
	// If the file is memory mapped, flush it out.
	if (fte->supplementary_page_entry_->table_entry_type == MEM_MAPPAED_PAGE) {
		flush_mmap(fte);
	} else {
		// Swap frame.
		fte->supplementary_page_entry_->swap_index = put_frame_in_swap(fte->frame);
		fte->supplementary_page_entry_->table_entry_type = SWAPED_PAGE;
	}
}

/**
 * Flush out the memory mapped file.
 */
void flush_mmap(struct frame_table_entry *fte) {
	lock_acquire(&file_resource_lock);
	file_write_at(fte->supplementary_page_entry_->required_file, fte->frame, fte->supplementary_page_entry_->read_bytes,
			fte->supplementary_page_entry_->offset);
	lock_release(&file_resource_lock);
}

/**
 * Gets the element to be eliminated using clock algorithm.
 * The element returned will not be pinned neither its accessed bit will be true.
 * If none found, return null. Caller of this function can call this again and again till it wants a proper result back.
 */
struct list_elem * get_element_to_be_eliminated() {
	struct list_elem *e = list_begin(&frame_table);

	while (e != list_end(&frame_table)) {

		struct frame_table_entry *fte =
				list_entry(e, struct frame_table_entry, elem);

		if (!fte->supplementary_page_entry_->is_page_pinned) {

			if (pagedir_is_accessed(fte->pagedir, fte->supplementary_page_entry_->user_virtual_address)) {
				pagedir_set_accessed(fte->pagedir, fte->supplementary_page_entry_->user_virtual_address, false);
			} else {
				return e;
			}
		}
		e = list_next(e);
	}
	return NULL;
}
