#ifndef _LIST_H
#define _LIST_H_

struct llist_head;

typedef struct llist_head {
	struct llist_head* prev;
	struct llist_head* next;
	void* data;
} llist_head;

int llist_head_init(struct llist_head** head, void* data);
void llist_head_free(struct llist_head* head);
int llist_append(struct llist_head** list, void* data);
void llist_remove(struct llist_head** list, struct llist_head* elem);
int llist_remove_data(struct llist_head** head, void* data);
int llist_remove_index(struct llist_head** head, unsigned int index);
int llist_get_value_at_index(struct llist_head* head, void** data, unsigned int index);
unsigned int llist_length(struct llist_head* head);

#endif
