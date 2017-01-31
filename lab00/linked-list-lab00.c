#include <stdio.h>
#include <stdlib.h>

struct list_item {
	int value;
	struct list_item* next;
};

void append(struct list_item *first, int x) {
	struct list_item *item = first;
	while(item->next != NULL) {
		item = item->next;
	}
	struct list_item *last = (struct list_item*)malloc(sizeof(struct list_item));
	item->next = last;
	last->value = x; 
	last->next = NULL;
}

void prepend(struct list_item *first, int x) {
	struct list_item *new = (struct list_item*)malloc(sizeof(struct list_item));
	new->value = x;
	new->next = first->next;
	first->next = new;
	printf("%p\n", new);
	printf("%p\n", first->next);
}

void print(struct list_item *first) {
	struct list_item *item = first;
	// Skip the root (if exists any other items)
	if(first->next != NULL){
		item = first->next;
	}
	else{
		return;
	}
	while(item->next != NULL) {
		printf("%d \n", item->value);
		item = item->next;
	}
	printf("%d \n\n", item->value);
}

void input_sorted(struct list_item *first, int x) {
	struct list_item *new = (struct list_item*) malloc(sizeof(struct list_item));	
	struct list_item *item = first;
	struct list_item *previous = NULL;
	while(item->next != NULL) {
		previous = item;
		item = item->next;
		if(item->value >= x) {
			previous->next = new;
			new->next = item;
			break;
		}
		else if(item->next == NULL) {
			item->next = new;
			new->next = NULL;
		}
	}
	new->value = x;
}

void clear(struct list_item *first) {
	struct list_item *item = first->next;
	do{
		struct list_item *temp = item->next;
		free(item);
		item = temp;
	}
	while(item->next != NULL);
}

void main(int argc, char **argv) {
	struct list_item root;
	root.value = -1;
	root.next = NULL;

	// Testing the linked list
	append(&root, 2);
	append(&root, 3);
	append(&root, 5);
	append(&root, 6);
	print(&root);
	prepend(&root, 1);
	print(&root);
	input_sorted(&root, 4);
	input_sorted(&root, 7);
	print(&root);
	clear(&root);
}













