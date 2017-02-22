#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include "list.h"

int main()
{
	char* head = "Foo";
	char* one = "Bar";
	char* two = "FooBar";
	char* three = "Baz";
	char* data;
	int err;
	unsigned int len;
	struct llist_head* list = NULL;
	llist_append(&list, head);
	llist_append(&list, one);
	llist_append(&list, two);
	printf("List length: %u\n", llist_length(list));
	llist_remove_index(&list, 0);
	llist_append(&list, three);
	llist_remove_index(&list, 2);
	llist_remove_index(&list, 1);
	llist_remove_index(&list, 0);
	len = llist_length(list);
	printf("List length: %u\n", len);
	while(len > 0)
	{
		len--;
		err = llist_get_value_at_index(list, &data, len);
		printf("Got element %u from list, err=%d\n", len, err);
		if(!err)
			printf("Element %u is: '%s'\n", len, data);
	}
	return 0;
}
