#include "cmsan_interval.h"

#include "interval-tree/interval_tree_generic.h"
#include "interval-tree/rbtree.h"

#include <stdlib.h>

struct MemTreeNode {

  struct rb_node rb;
  struct MemRange rng;
  uintptr_t __subtree_last;
};

#define START(node) ((node)->rng.start)
#define LAST(node) ((node)->rng.end)

INTERVAL_TREE_DEFINE(struct MemTreeNode, rb, uintptr_t, __subtree_last, START,
                     LAST, static, mem_tree)

static struct rb_root root = RB_ROOT;

struct MemRange *CmsanIntervalSearchFirst(uintptr_t start, uintptr_t end) {

  struct MemTreeNode *node = mem_tree_iter_first(&root, start, end);
  if (node)
    return &node->rng;
  return NULL;
}

void CmsanIntervalExecuteAll(uintptr_t start, uintptr_t end, void* retaddr) {

  struct MemTreeNode *node = mem_tree_iter_first(&root, start, end);
  while (node) {
    switch (node->rng.type) {
    case CONSTRAINFUNC1TY:
      ((ConstrainFunc1)node->rng.fn)(node->rng.start, retaddr);
      break;
    case CONSTRAINFUNC2TY:
      ((ConstrainFunc2)node->rng.fn)(node->rng.start, retaddr);
      break;
    case CONSTRAINFUNC4TY:
      ((ConstrainFunc4)node->rng.fn)(node->rng.start, retaddr);
      break;
    case CONSTRAINFUNC8TY:
      ((ConstrainFunc8)node->rng.fn)(node->rng.start, retaddr);
      break;
    case CONSTRAINFUNCNTY:
      ((ConstrainFuncN)node->rng.fn)(node->rng.start,
                                     node->rng.end - node->rng.start, retaddr);
      break;
    default:
      abort();
    }
    node = mem_tree_iter_next(node, start, end);
  }
}

void CmsanIntervalUnset(uintptr_t start, uintptr_t end) {

  struct MemTreeNode *prev_node = mem_tree_iter_first(&root, start, end);
  while (prev_node) {

    struct MemTreeNode *n = mem_tree_iter_next(prev_node, start, end);
    mem_tree_remove(prev_node, &root);
    prev_node = n;
  }
}

void CmsanIntervalSet(uintptr_t start, uintptr_t end, void *fn, uint8_t type) {

  // CmsanIntervalUnset(start, end); // TODO(andrea) evaluate if use this in set

  struct MemTreeNode *node = calloc(sizeof(struct MemTreeNode), 1);
  node->rng.start = start;
  node->rng.end = end;
  node->rng.fn = fn;
  node->rng.type = type;
  mem_tree_insert(node, &root);
}
