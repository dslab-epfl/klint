//#include "pool-old.c"

#include "os/structs/pool.h"

#include <stdlib.h>

#include "os/memory.h"

//@ #include <list.gh>
//@ #include <nat.gh>
//@ #include "proof/arith.gh"
//@ #include "proof/sizeex.gh"

// Use an array of cells large enough to fit the range of possible 'index' values + 2 special values.
// Forms a two closed linked lists inside the array.
// The first list represents the "free" cells. It is a single linked list.
// Initially the whole array (except 2 special cells holding metadata) is added to the "free" list.
// The second list represents the "occupied" cells and it is double-linked, the order matters.
// It is supposed to store the ordered sequence, and support moving any element to the top.
//
// The lists are organized as follows:
//              +----+   +---+   +-------------------+   +-----
//              |    V   |   V   |                   V   |
//  [. + .][    .]  {    .} {    .} {. + .} {. + .} {    .} ....
//   ^   ^                           ^   ^   ^   ^
//   |   |                           |   |   |   |
//   |   +---------------------------+   +---+   +-------------
//   +---------------------------------------------------------
//
// Where {    .} is a "free" list cell, and {. + .} is an "alloc" list cell, and dots represent prev/next fields.
// [] - denote the special cells - the ones that are always kept in the corresponding lists.
// Empty "alloc" and "free" lists look like this:
//
//   +---+   +---+
//   V   V   V   |
//  [. + .] [    .]
//
// i.e. cells[0].next == 0 && cells[0].prev == 0 for the "alloc" list, and cells[1].next == 1 for the free list.
// For any cell in the "alloc" list, 'prev' and 'next' fields must be different.
// Any cell in the "free" list, in contrast, have 'prev' and 'next' equal;
// After initialization, any cell is always on one and only one of these lists.

struct os_pool {
  size_t* cell_prevs;
  size_t* cell_nexts;
  time_t* timestamps;
};

#define POOL_RESERVED 2

enum POOL_ENUM {
    ALLOC_LIST_HEAD = 0,
    FREE_LIST_HEAD = 1,
    INDEX_SHIFT = POOL_RESERVED
};

/*@
  fixpoint list<pair<size_t, size_t> > zip_cells(list<size_t> prevs, list<size_t> nexts) {
    switch(prevs) {
      case nil: return nil;
      case cons(ph, pt):
        return switch(nexts) {
          case nil: return nil;
          case cons(nh, nt): return cons(pair(ph, nh), zip_cells(pt, nt));
        };
    }
  }

  predicate poolp_raw(struct os_pool* pool, size_t size; list<pair<size_t, size_t> > cells, list<time_t> timestamps) =
    struct_os_pool_padding(pool) &*&
    pool->cell_prevs |-> ?cell_prevs_ptr &*&
    pool->cell_nexts |-> ?cell_nexts_ptr &*&
    pool->timestamps |-> ?timestamps_ptr &*&
    cell_prevs_ptr[0..size+POOL_RESERVED] |-> ?cell_prevs &*&
    cell_nexts_ptr[0..size+POOL_RESERVED] |-> ?cell_nexts &*&
    cells == zip_cells(cell_prevs, cell_nexts) &*&
    timestamps_ptr[0..size] |-> timestamps;

  predicate free_indexesp(list<pair<size_t, size_t> > cells, list<size_t> free_indexes, size_t start, size_t cur) =
    switch(free_indexes) {
      case nil:
        return nth(cur, cells) == pair(start, start);
      case cons(h, t):
        return nth(cur, cells) == pair(h, h) &*&
               cur != h &*&
               free_indexesp(cells, t, start, h);
  };

  predicate allocated_indexesp(list<pair<size_t, size_t> > cells, list<size_t> allocated_indexes, size_t start, size_t cur) =
    switch(allocated_indexes) {
      case nil:
        return nth(cur, cells) == pair(?x, start) &*&
               nth(start, cells) == pair(cur, ?y) &*&
               cur == start ? (x == start &*& y == cur)
                            : true;
      case cons(h, t):
        return nth(cur, cells) == pair(?x, h) &*&
               nth(h, cells) == pair(cur, ?y) &*&
               cur != h &*&
               allocated_indexesp(cells, t, start, h);
    };
  
  predicate poolp(struct os_pool* pool, size_t size, list<pair<size_t, time_t> > items) =
    poolp_raw(pool, size, ?cells, ?timestamps) &*&
    free_indexesp(cells, ?free_indexes, FREE_LIST_HEAD, FREE_LIST_HEAD) &*&
    allocated_indexesp(cells, ?allocated_indexes, ALLOC_LIST_HEAD, ALLOC_LIST_HEAD) &*&
    allocated_indexes == map(fst, items);
@*/


/*@

@*/

struct os_pool* os_pool_alloc(size_t size)
/*@ requires size <= (SIZE_MAX / 16) - 2; @*/
/*@ ensures poolp(result, size, nil); @*/
{
  struct os_pool* pool = (struct os_pool*) os_memory_alloc(1, sizeof(struct os_pool));
  //@ close_struct_zero(pool);
  pool->cell_prevs = (size_t*) os_memory_alloc(size + POOL_RESERVED, sizeof(size_t));
  pool->cell_nexts = (size_t*) os_memory_alloc(size + POOL_RESERVED, sizeof(size_t));
  pool->timestamps = (time_t*) os_memory_alloc(size, sizeof(time_t));
  //@ chars_to_times(pool->timestamps, size);
  //@ close poolp_raw(pool, size, ?cells, ?timestamps);

  pool->cell_prevs[ALLOC_LIST_HEAD] = 0;
  pool->cell_nexts[ALLOC_LIST_HEAD] = 0;
  pool->cell_prevs[FREE_LIST_HEAD] = INDEX_SHIFT;
  pool->cell_nexts[FREE_LIST_HEAD] = INDEX_SHIFT;
  //@ initial_empty_cell(FREE_LIST_HEAD);
    while (i < (size + INDEX_SHIFT - 1))
        /*@ invariant INDEX_SHIFT <= i &*&
                      i <= size + INDEX_SHIFT -1 &*&
                      cells > (struct dchain_cell*)0 &*&
                      dcellsp(cells + i, size + DCHAIN_RESERVED - i, _) &*&
                      dcellsp(cells + FREE_LIST_HEAD, i - FREE_LIST_HEAD,
                              empty_cells_seg(nat_of_int(i - FREE_LIST_HEAD),
                                              FREE_LIST_HEAD));
                      @*/
                      //@ decreases size + INDEX_SHIFT - 1 - i;
    {
        //@ open dcellsp(cells + i, size + DCHAIN_RESERVED - i, _);
        //@ dcell_limits(cells + i);
        struct dchain_cell* current = cells + i;
        current->next = i + 1;
        current->prev = current->next;
        //@ put_cell_back(cells + FREE_LIST_HEAD, i - FREE_LIST_HEAD, FREE_LIST_HEAD);
        ++i;
    }
    //@ assert i == size + INDEX_SHIFT - 1;
    //@ open dcellsp(cells + i, size + DCHAIN_RESERVED - i, _);
    //@ dcell_limits(cells + i);
    struct dchain_cell* last = cells + i;
    last->next = FREE_LIST_HEAD;
    last->prev = last->next;
    //@ assert i == size + 1;
    //@ mul_subst(i, size+1, sizeof(struct dchain_cell));
    //@ close dcellp(cells+size+1,dcell(1,1));
    //@ empty_dchain_produced(cells, size);
    //@ full_free_list_len(nat_of_int(size), 2);
    //@ full_free_list_all_engaged(nat_of_int(size));
    //@ full_free_list_all_lbounded(nat_of_int(size), INDEX_SHIFT);
    //@ close dchainip(empty_dchaini_fp(size), cells);
  //@ close double_chainp(empty_dchain_fp(index_range, 0), chain_alloc);
  return chain_alloc;
}