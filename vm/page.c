#include <string.h>
#include <stdbool.h>
#include "filesys/file.h"
#include "threads/interrupt.h"
#include "threads/malloc.h"
#include "threads/palloc.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "userprog/pagedir.h"
#include "userprog/process.h"
#include "userprog/syscall.h"
#include "vm/frame.h"
#include "vm/page.h"
#include "vm/swap.h"

bool read_file_into_memory(struct supplemental_pte *sup_pte, uint8_t *frame);

/**
 * Initializes the supplementary page table.
 */
void init_sup_page_table(struct hash *spt) {
	hash_init(spt, get_sup_page_hash, sup_page_less_func, NULL);
}

/**
 * The destructor of supplementary page table.
 */
void destroy_sup_page_table(struct hash *spt) {
	hash_destroy(spt, sup_page_destroyer);
}

/**
 * The function that is called on each entry in supplementary page table when the entire table is destructed.
 */
void sup_page_destroyer(struct hash_elem *e, void *aux UNUSED) {

	struct supplemental_pte *spte = hash_entry(e, struct supplemental_pte,
			sup_pte_elem);
	/**
	 * Is page is currently loaded. Free the frame first.
	 */
	if (spte->is_page_loaded) {
		free_frame_table_entry(spte->frame_table_entry_, pagedir_get_page(thread_current()->pagedir,spte->user_virtual_address));

		pagedir_clear_page(thread_current()->pagedir, spte->user_virtual_address);
	}
	/**
	 * Free entry.
	 */
	free(spte);
}

/**
 * Returns the supplemental page table given a user virtual address
 */
struct supplemental_pte* get_supplemental_pte(void *user_virtual_address) {

	struct supplemental_pte spte;
	spte.user_virtual_address = pg_round_down(user_virtual_address);

	struct hash_elem *e = hash_find(&thread_current()->spt, &spte.sup_pte_elem);

	if (e != NULL) {
		return hash_entry (e, struct supplemental_pte, sup_pte_elem);
	}

	return NULL;
}

/**
 * Loads a file into memory either from swap space or disk.
 */
bool load_file_from_swap_or_disk(struct supplemental_pte *sup_pte) {

	sup_pte->is_page_pinned = true;

	if (sup_pte->is_page_loaded) {
		return false;
	} else if (sup_pte->table_entry_type == SWAPED_PAGE) {
		return set_swap_file_in_frame(sup_pte);
	}
	return set_file_in_frame(sup_pte);
}

/**
 * Loads a file from swap space into memory.
 */
bool set_swap_file_in_frame(struct supplemental_pte *sup_pte) {

	uint8_t *frame = get_frame(PAL_USER, sup_pte);

	if (frame == NULL) {
		return false;
	}

	if (install_page(sup_pte->user_virtual_address, frame,
			sup_pte->is_page_writable)) {
		get_frame_from_swap(sup_pte->swap_index, sup_pte->user_virtual_address);
		sup_pte->is_page_loaded = true;
		return true;
	}

	free_frame_table_entry(sup_pte->frame_table_entry_, frame);
	return false;
}

/**
 * Loads the file from disk into memory.
 */
bool set_file_in_frame(struct supplemental_pte *sup_pte) {

	enum palloc_flags flags = PAL_USER;

	/**
	 * As read bytes are zero, we need to allocate page as well as filled with zeros.
	 */
	if (sup_pte->read_bytes == 0)
	{
		flags = PAL_USER + PAL_ZERO;
	}

	uint8_t *frame = get_frame(flags, sup_pte);

	if (frame == NULL) {
		return false;
	}

	/**
	 * Load the file from memory is read bytes are greates than 0.
	 */
	if (sup_pte->read_bytes > 0) {

		bool successful_read = read_file_into_memory(sup_pte, frame);

		/**
		 * If read was unsuccessful, return false;
		 */
		if (!successful_read) {
			return false;
		}
	}

	/**
	 * Install the page.
	 */
	if (!install_page(sup_pte->user_virtual_address, frame, sup_pte->is_page_writable)) {
		/**
		 * If installation failed, free the frame and frame table entry.
		 */
		free_frame_table_entry(sup_pte->frame_table_entry_, frame);
		return false;
	}

	/**
	 * Success.
	 */
	sup_pte->is_page_loaded = true;

	return true;
}

/**
 * Reads the file into memory frame.
 */
bool read_file_into_memory(struct supplemental_pte *sup_pte, uint8_t *frame)
{
	lock_acquire(&file_resource_lock);

	int number_of_bytes_read = file_read_at(sup_pte->required_file, frame, sup_pte->read_bytes, sup_pte->offset);

	/**
	 * If  number of bytes read were same as expected.
	 */
	if ((int) sup_pte->read_bytes == number_of_bytes_read) {
		lock_release(&file_resource_lock);
		memset(frame + sup_pte->read_bytes, 0, sup_pte->zero_bytes);
		return true;
	}

	/**
	 * If  number of bytes read were not same as expected.
	 */
	lock_release(&file_resource_lock);
	free_frame_table_entry(sup_pte->frame_table_entry_, frame);
	return false;
}

/**
 * Push the meta data of part of the file to be loaded in supplemental page table.
 */
bool push_file_in_supplemental_page_table(struct file *file, int32_t ofs,
		uint8_t *upage, uint32_t read_bytes, uint32_t zero_bytes, bool writable) {

	struct supplemental_pte *sup_pte = create_supplemental_pte(file, ofs, upage,
			read_bytes, zero_bytes, DISK_PAGE, writable);

	if (sup_pte != NULL) {
		return (hash_insert(&thread_current()->spt, &sup_pte->sup_pte_elem) == NULL);
	}
	return false;

}

/**
 * Push the meta data of part of the memory mapped file to be loaded in supplemental page table.
 */
bool push_mapped_file_in_supplemental_page_table(struct file *file, int32_t ofs,
		uint8_t *upage, uint32_t read_bytes, uint32_t zero_bytes) {

	struct supplemental_pte *sup_pte = create_supplemental_pte(file, ofs, upage,
			read_bytes, zero_bytes, MEM_MAPPAED_PAGE, true);

	if (sup_pte) {
		if (create_mem_map_entry(sup_pte)) {
			if ((hash_insert(&thread_current()->spt, &sup_pte->sup_pte_elem))) {
				sup_pte->table_entry_type = TABLE_ENTRY_ERR;
				return false;
			}
		} else {
			free(sup_pte);
			return false;
		}
	} else {
		return false;
	}
	return true;
}

/**
 * Create a supplemental page table.
 */
struct supplemental_pte* create_supplemental_pte(struct file *file, int32_t ofs,
		uint8_t *upage, uint32_t read_bytes, uint32_t zero_bytes,
		sup_pte_type type, bool writable) {
	struct supplemental_pte *sup_pte = malloc(sizeof(struct supplemental_pte));

	if (sup_pte == NULL) {
		return NULL;
	}

	if (type != SWAPED_PAGE) {
		sup_pte->required_file = file;
		sup_pte->offset = ofs;
		sup_pte->read_bytes = read_bytes;
		sup_pte->zero_bytes = zero_bytes;

		sup_pte->is_page_loaded = false;

	} else {
		sup_pte->is_page_loaded = true;
		sup_pte->is_page_pinned = true;
	}

	sup_pte->user_virtual_address = upage;
	sup_pte->table_entry_type = type;
	sup_pte->is_page_writable = writable;
	sup_pte->is_page_pinned = false;
	sup_pte->frame_table_entry_ = NULL;

	return sup_pte;
}

/**
 * Increments the stack size dynamically.
 */
bool increment_stack_size(void *user_virtual_address) {

	if (is_stack_max(user_virtual_address)) {
		return false;
	}

	struct supplemental_pte *sup_pte = create_supplemental_pte(NULL, NULL,
			pg_round_down(user_virtual_address), NULL, NULL, SWAPED_PAGE, true);

	if (sup_pte) {
		uint8_t *frame = get_frame(PAL_USER, sup_pte);
		if (frame) {
			bool test = install_page(sup_pte->user_virtual_address, frame,
					sup_pte->is_page_writable);
			if (!test) {
				free(sup_pte);
				free_frame_table_entry(sup_pte->frame_table_entry_, frame);
				return false;
			}
		} else {
			free(sup_pte);
			return false;
		}
	} else {
		return false;
	}

	if (intr_context()) {
		sup_pte->is_page_pinned = false;
	}

	return (hash_insert(&thread_current()->spt, &sup_pte->sup_pte_elem) == NULL);
}

/**
 * Checks if the virtual address has reached stack max size.
 */
bool is_stack_max(void *user_virtual_address) {

	if ((size_t) (PHYS_BASE - pg_round_down(user_virtual_address))
			< MAX_STACK_SIZE) {
		return false;
	}
	return true;
}

/**
 * The hash code generator for supplementary page table.
 */
unsigned get_sup_page_hash(const struct hash_elem *e, void *aux UNUSED) {
	struct supplemental_pte *sup_pte = hash_entry(e, struct supplemental_pte,
			sup_pte_elem);
	return hash_int((int) sup_pte->user_virtual_address);
}

/**
 *
 */
bool sup_page_less_func(const struct hash_elem *a, const struct hash_elem *b,
		void *aux UNUSED) {
	struct supplemental_pte *sup_pte_a =
			hash_entry(a, struct supplemental_pte, sup_pte_elem);
	struct supplemental_pte *sup_pte_b =
			hash_entry(b, struct supplemental_pte, sup_pte_elem);
	if (sup_pte_a->user_virtual_address < sup_pte_b->user_virtual_address) {
		return true;
	}
	return false;
}
