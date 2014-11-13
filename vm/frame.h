#ifndef VM_FRAME_H
#define VM_FRAME_H

#include <list.h>
#include "threads/palloc.h"
#include "threads/synch.h"
#include "vm/page.h"

/**
 * List that will hold frame table entries.
 */
struct list frame_table;

/**
 * A Frame table entry.
 */
struct frame_table_entry {
	/**
	 * The allocated frame.
	 */
	void *frame;
	/**
	 * The supplementary page table.
	 */
	struct supplemental_pte *supplementary_page_entry_;
	/**
	 * The page directory of the thread to which this frame belongs to.
	 */
	uint32_t *pagedir;

	struct list_elem elem;
};

/**
 * Lock for frame table.
 */
struct lock frame_table_lock;

void initialize_frame_table (void);
void* get_frame (enum palloc_flags flags, struct supplemental_pte *spte);
void free_frame_table_entry(struct frame_table_entry *fte, void *frame);

#endif /* vm/frame.h */
