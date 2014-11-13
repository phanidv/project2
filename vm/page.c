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

void init_sup_page_table(struct hash *spt) {
	hash_init(spt, get_sup_page_hash, sup_page_less_func, NULL);
}

void destroy_sup_page_table(struct hash *spt) {
	hash_destroy(spt, sup_page_destroyer);
}

void sup_page_destroyer(struct hash_elem *e, void *aux UNUSED) {
	struct supplemental_pte *spte = hash_entry(e, struct supplemental_pte,
			sup_pte_elem);
	if (spte->is_page_loaded) {
		free_frame_table_entry(spte->frame_table_entry_, pagedir_get_page(thread_current()->pagedir,spte->user_virtual_address));

		pagedir_clear_page(thread_current()->pagedir,
				spte->user_virtual_address);
	}
	free(spte);
}

struct supplemental_pte* get_supplemental_pte(void *uva) {
	struct supplemental_pte spte;
	spte.user_virtual_address = pg_round_down(uva);

	struct hash_elem *e = hash_find(&thread_current()->spt, &spte.sup_pte_elem);
	if (!e) {
		return NULL;
	}
	return hash_entry (e, struct supplemental_pte, sup_pte_elem);
}

bool supplemental_page_table_handler(struct supplemental_pte *sup_pte) {
	sup_pte->is_page_pinned = true;
	bool handler_return = false;

	if (sup_pte->is_page_loaded) {
		return handler_return;
	} else if (sup_pte->table_entry_type == DISK_PAGE
			|| sup_pte->table_entry_type == MEM_MAPPAED_PAGE) {
		handler_return = set_file_in_frame(sup_pte);
	} else if (sup_pte->table_entry_type == SWAPED_PAGE) {
		handler_return = set_swap_file_in_frame(sup_pte);
	} else {
		return handler_return;
	}

	return handler_return;
}

bool set_swap_file_in_frame(struct supplemental_pte *sup_pte) {
	uint8_t *frame = get_frame(PAL_USER, sup_pte);

	if (!frame) {
		return false;
	}
	if (!install_page(sup_pte->user_virtual_address, frame,
			sup_pte->is_page_writable)) {
		free_frame_table_entry(sup_pte->frame_table_entry_, frame);
		return false;
	}
	get_frame_from_swap(sup_pte->swap_index, sup_pte->user_virtual_address);
	sup_pte->is_page_loaded = true;

	return true;
}

bool set_file_in_frame(struct supplemental_pte *sup_pte) {
	enum palloc_flags flags = PAL_USER;
	bool is_file_in_frame = false;

	// TODO
	if (sup_pte->read_bytes == 0) {
		flags |= PAL_ZERO;
		//return is_file_in_frame;
	}

	uint8_t *frame = get_frame(flags, sup_pte);
	if (!frame) {
		return is_file_in_frame;
	}

	if (sup_pte->read_bytes > 0) {
		lock_acquire(&file_resource_lock);
		if ((int) sup_pte->read_bytes
				!= file_read_at(sup_pte->required_file, frame,
						sup_pte->read_bytes, sup_pte->offset)) {
			lock_release(&file_resource_lock);
			free_frame_table_entry(sup_pte->frame_table_entry_, frame);
			return is_file_in_frame;
		}
		lock_release(&file_resource_lock);

		memset(frame + sup_pte->read_bytes, 0, sup_pte->zero_bytes);
	}

	if (!install_page(sup_pte->user_virtual_address, frame,
			sup_pte->is_page_writable)) {
		free_frame_table_entry(sup_pte->frame_table_entry_, frame);
		return is_file_in_frame;
	}

	is_file_in_frame = true;
	sup_pte->is_page_loaded = true;

	return is_file_in_frame;
}

bool push_file_in_supplemental_page_table(struct file *file, int32_t ofs,
		uint8_t *upage, uint32_t read_bytes, uint32_t zero_bytes, bool writable) {

	struct supplemental_pte *sup_pte = create_supplemental_pte(file, ofs, upage,
			read_bytes, zero_bytes, DISK_PAGE, writable);

	if (sup_pte) {
		return (hash_insert(&thread_current()->spt, &sup_pte->sup_pte_elem)
				== NULL);
	} else {
		return false;
	}
}

bool push_mapped_file_in_supplemental_page_table(struct file *file, int32_t ofs,
		uint8_t *upage, uint32_t read_bytes, uint32_t zero_bytes) {
	struct supplemental_pte *sup_pte = create_supplemental_pte(file, ofs, upage,
			read_bytes, zero_bytes, MEM_MAPPAED_PAGE, true);

	bool return_val = false;
	if (sup_pte) {
		if (process_add_mmap(sup_pte)) {
			if ((hash_insert(&thread_current()->spt, &sup_pte->sup_pte_elem))) {
				sup_pte->table_entry_type = TABLE_ENTRY_ERR;
				return return_val;
			}
		} else {
			free(sup_pte);
			return return_val;
		}
	} else {
		return return_val;
	}

	return_val = true;
	return return_val;
}

struct supplemental_pte* create_supplemental_pte(struct file *file, int32_t ofs,
		uint8_t *upage, uint32_t read_bytes, uint32_t zero_bytes,
		sup_pte_type type, bool writable) {
	struct supplemental_pte *sup_pte = malloc(sizeof(struct supplemental_pte));
	if (!sup_pte) {
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

bool is_stack_max(void *user_virtual_address) {
	if ((size_t) (PHYS_BASE - pg_round_down(user_virtual_address))
			< MAX_STACK_SIZE) {
		return false;
	}
	return true;
}

unsigned get_sup_page_hash(const struct hash_elem *e, void *aux UNUSED) {
	struct supplemental_pte *sup_pte = hash_entry(e, struct supplemental_pte,
			sup_pte_elem);
	return hash_int((int) sup_pte->user_virtual_address);
}

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
