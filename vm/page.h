#ifndef VM_PAGE_H
#define VM_PAGE_H

#include <hash.h>
#include "vm/frame.h"

/**
 * This determines the max stack size. Currently set to 8MB.
 */
#define MAX_STACK_SIZE (1 << 23)

/**
 * This enum determines the type of entry in supplemental page table.
 *
 * The type helps in deciding from where does the data need to be put
 * back on the stack, i.e disk or swap-space.
 */
typedef enum {
	DISK_PAGE, SWAPED_PAGE, MEM_MAPPAED_PAGE, TABLE_ENTRY_ERR
} sup_pte_type;

/**
 *	The supplemental page table entry has the following fields:
 *
 *	user_virtual_address = this maps the table entry with the user pool virtual address.
 *	sup_pte_elem = the hash elem that is inserted the supplemental hash-table.
 *
 *	following 4 params are set if the table entry tracks data to be loaded from file/disk.
 *	required_file = file pointer whose data the entry tracks.
 *	offset = the offset from where the file data has to be read.
 *	read_bytes = saves the bytes read in when we copy data from file to frame.
 *	zero_bytes = count of bytes that need o be set to 0 when copying data to frame.
 *
 *	swap_index = this param is determines the index where the file was swapped to.
 *
 *	table_entry_type = determines what meta-data the table entry is storing. viz file or swap meta-data.
 *
 *	is_page_loaded = is set to true if the page is in frame.
 *
 *	is_page_pinned = is set to true if the page is pinned. This is required when eviction happens.
 *	We neglect the pages from our eviction algorithm if the page is pinned to frame.
 *
 *	is_page_writable = is set to true if the page is writable by the user prog.
 *
 *	frame_table_entry_ = The corresponding frame table entry.
 *
 */
struct supplemental_pte {
	void *user_virtual_address;

	struct hash_elem sup_pte_elem;

	struct file *required_file;
	size_t offset;
	size_t read_bytes;
	size_t zero_bytes;

	size_t swap_index;

	sup_pte_type table_entry_type;
	bool is_page_loaded;
	bool is_page_pinned;
	bool is_page_writable;

	struct frame_table_entry *frame_table_entry_;
};

/**
 * supplemental page table init and destroy
 */
void init_sup_page_table(struct hash *spt);
void destroy_sup_page_table(struct hash *spt);

/**
 * create and retrieve entry
 */
struct supplemental_pte* get_supplemental_pte(void *uva);
struct supplemental_pte* create_supplemental_pte(struct file *file, int32_t ofs,
		uint8_t *upage, uint32_t read_bytes, uint32_t zero_bytes, sup_pte_type type, bool writable);

/**
 * event handler
 */
bool load_file_from_swap_or_disk(struct supplemental_pte *sup_pte);

/**
 * load data into frame from file/swap-space
 */bool set_swap_file_in_frame(struct supplemental_pte *sup_pte);
bool set_file_in_frame(struct supplemental_pte *sup_pte);

/**
 * push entries into supplemental page table
 */bool push_file_in_supplemental_page_table(struct file *file, int32_t ofs,
		uint8_t *upage, uint32_t read_bytes, uint32_t zero_bytes, bool writable);

bool push_mapped_file_in_supplemental_page_table(struct file *file, int32_t ofs,
		uint8_t *upage, uint32_t read_bytes, uint32_t zero_bytes);

/**
 *increase stack size
 */bool increment_stack_size(void *uva);


/**
 * helper methods
 */
unsigned get_sup_page_hash(const struct hash_elem *e, void *aux UNUSED);
bool sup_page_less_func(const struct hash_elem *a,
		const struct hash_elem *b, void *aux UNUSED);
void sup_page_destroyer(struct hash_elem *e, void *aux UNUSED);
bool is_stack_max(void *user_virtual_address);
bool put_frame_in_memory(uint8_t *frame,struct supplemental_pte *sup_pte);
#endif
