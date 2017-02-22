#include <string.h>
#include <errno.h>
#include <malloc.h>

#include "list.h"

int llist_head_init(struct llist_head** head, void* data)
{
	int err = 0;
	*head = malloc(sizeof(struct llist_head));
	if(!*head)
	{
		err = -ENOMEM;
		goto exit_err;
	}
	memset(*head, 0, sizeof(struct llist_head));
	(*head)->data = data;
exit_err:
	return err;
}

void llist_head_free(struct llist_head* head)
{
	struct llist_head* next;
	while(head)
	{
		next = head->next;
		free(head);
		head = next;
	}
}

int llist_append(struct llist_head** list, void* data)
{
	int err = 0;
	struct llist_head* entry;
	if(!*list)
		err = llist_head_init(list, data);
	else
	{
		entry = *list;
		while(entry->next)
		{
			entry = entry->next;
		}
		if((err = llist_head_init(&entry->next, data)))
			goto exit_err;
		entry->next->prev = entry;
	}
exit_err:
	return err;
}

void llist_remove(struct llist_head** list, struct llist_head* elem)
{
	if(elem == *list)
		*list = elem->next;
	if(elem->prev && elem->next)
	{
		elem->prev->next = elem->next;
		elem->next->prev = elem->prev;
	}
	else if(elem->prev)
		elem->prev->next = NULL;
	else if(elem->next)
		elem->next->prev = NULL;
	elem->next = NULL;
	llist_head_free(elem);
}

int llist_remove_data(struct llist_head** head, void* data)
{
	struct llist_head* entry = *head;
	while(entry)
	{
		if(entry->data == data)
		{
			llist_remove(head, entry);
			return 0;
		}
		entry = entry->next;
	}
	return -ENOENT;
}

int llist_remove_index(struct llist_head** head, unsigned int index)
{
	struct llist_head* entry = *head;
	while(index-- > 0)
	{
		if(!entry)
			return -ENOENT;
		entry = entry->next;
	}
	if(!entry)
		return -ENOENT;
	llist_remove(head, entry);
	return 0;
}

int llist_get_value_at_index(struct llist_head* head, void** data, unsigned int index)
{
	while(index-- > 0)
	{
		if(!head)
			return -ENOENT;
		head = head->next;
	}
	if(!head)
		return -ENOENT;
	*data = head->data;
	return 0;
}

unsigned int llist_length(struct llist_head* head)
{
	unsigned int len = 0;
	while(head)
	{
		len++;
		head = head->next;
	}
	return len;
}
