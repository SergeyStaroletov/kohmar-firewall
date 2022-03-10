/*
 * Anomaly Detection System for network traffic
 * @license GNU GPL
 * @authors Staroletov (used some GPL code)
 */

#ifndef MMAP_UTILS_H_
#define MMAP_UTILS_H_

struct new_packet_header {
  int flag_ready;
  int size;
};

struct packet_ring_buffer {
  char **pg_vec;
  unsigned int head;
  unsigned int frames_per_block;
  unsigned int frame_size;
  unsigned int frame_max;

  unsigned int pg_vec_order;
  unsigned int pg_vec_pages;
  unsigned int pg_vec_len;

  atomic_t pending;
};

struct packet_ring_buffer tx_ring;

struct pkt_mmap {
  struct tpacket_req *req;
  int order;
  struct packet_ring_buffer *rb;
  char **pg_vec;
  /* character device structures */
  dev_t mmap_dev;
  struct cdev mmap_cdev;
  int max_packets;
  int number_packets;
  atomic_t number_atomic;
  const struct vm_operations_struct *packet_mmap_ops;
};

static struct pkt_mmap *mmap_rx;

static int packet_mmap(struct vm_area_struct *vma, struct pkt_mmap *p_mmap);
static void packet_mm_open_tx(struct vm_area_struct *vma) {}
static void packet_mm_close_tx(struct vm_area_struct *vma) {}

static const struct vm_operations_struct packet_mmap_ops_tx = {
    .open = packet_mm_open_tx,
    .close = packet_mm_close_tx,
};

// RX
static void packet_mm_open_rx(struct vm_area_struct *vma) {}
static void packet_mm_close_rx(struct vm_area_struct *vma) {}

static const struct vm_operations_struct packet_mmap_ops_rx = {
    .open = packet_mm_open_rx,
    .close = packet_mm_close_rx,
};

/* methods of the character device */
static int mmap_open_rx(struct inode *inode, struct file *filp);
static int mmap_release_rx(struct inode *inode, struct file *filp);
static int mmap_mmap_rx(struct file *filp, struct vm_area_struct *vma);

/* the file operations, i.e. all character device methods */
static struct file_operations mmap_fops_rx = {
    .open = mmap_open_rx,
    .release = mmap_release_rx,
    .mmap = mmap_mmap_rx,
    .owner = THIS_MODULE,
};

/* character device open method */
static int mmap_open_rx(struct inode *inode, struct file *filp) { return 0; }
/* character device last close method */
static int mmap_release_rx(struct inode *inode, struct file *filp) { return 0; }
/* character device mmap method */
static int mmap_mmap_rx(struct file *filp, struct vm_area_struct *vma) {
  return packet_mmap(vma, mmap_rx);
}

static int packet_mmap(struct vm_area_struct *vma, struct pkt_mmap *p_mmap) {
  unsigned long size, expected_size;
  unsigned long start;
  int err = -EINVAL;
  int i;

  if (vma->vm_pgoff)
    return -EINVAL;

  expected_size = 0;

  if (p_mmap->rb->pg_vec) {
    expected_size +=
        p_mmap->rb->pg_vec_len * p_mmap->rb->pg_vec_pages * PAGE_SIZE;
  }

  if (expected_size == 0)
    goto out;

  size = vma->vm_end - vma->vm_start;
  if (size != expected_size)
    goto out;

  start = vma->vm_start;
  if (p_mmap->rb->pg_vec == NULL)
    return 0;

  for (i = 0; i < p_mmap->rb->pg_vec_len; i++) {
    struct page *page = virt_to_page(p_mmap->rb->pg_vec[i]);
    int pg_num;

    for (pg_num = 0; pg_num < p_mmap->rb->pg_vec_pages; pg_num++, page++) {
      err = vm_insert_page(vma, start, page);
      if (unlikely(err))
        goto out;
      start += PAGE_SIZE;
    }
  }

  vma->vm_ops = p_mmap->packet_mmap_ops;
  err = 0;

out:
  return err;
}

static inline char *alloc_one_pg_vec_page(unsigned long order) {
  gfp_t gfp_flags = GFP_KERNEL | __GFP_COMP | __GFP_ZERO | __GFP_NOWARN;

  return (char *)__get_free_pages(gfp_flags, order);
}

static void free_pg_vec(char **pg_vec, unsigned int order, unsigned int len) {
  int i;

  for (i = 0; i < len; i++) {
    if (likely(pg_vec[i]))
      free_pages((unsigned long)pg_vec[i], order);
  }
  kfree(pg_vec);
}

static char **alloc_pg_vec(struct tpacket_req *req, int order) {
  unsigned int block_nr = req->tp_block_nr;
  char **pg_vec;
  int i;

  pg_vec = kzalloc(block_nr * sizeof(char *), GFP_KERNEL);
  if (unlikely(!pg_vec))
    goto out;

  for (i = 0; i < block_nr; i++) {
    pg_vec[i] = alloc_one_pg_vec_page(order);
    if (unlikely(!pg_vec[i]))
      goto out_free_pgvec;
    memset(pg_vec[i], 0, req->tp_block_size);
  }

out:
  return pg_vec;

out_free_pgvec:
  free_pg_vec(pg_vec, order, block_nr);
  pg_vec = NULL;
  goto out;
}

inline void *packet_lookup_frame(unsigned int position,
                                 struct pkt_mmap *p_mmap) {
  unsigned int pg_vec_pos, frame_offset;
  void *hraw;

  pg_vec_pos = position / p_mmap->rb->frames_per_block;
  frame_offset = position % p_mmap->rb->frames_per_block;

  hraw =
      p_mmap->rb->pg_vec[pg_vec_pos] + (frame_offset * p_mmap->rb->frame_size);

  return hraw;
}

inline static void *mmap_get_next_pointer(struct pkt_mmap *p_mmap) {
  unsigned int pg_vec_pos, frame_offset;

  atomic_inc(&p_mmap->number_atomic);
  p_mmap->number_packets = atomic_read(&p_mmap->number_atomic);

  if (p_mmap->number_packets > p_mmap->max_packets - 1) {
    p_mmap->number_packets = 1;
    atomic_set(&p_mmap->number_atomic, 1);
  }

  pg_vec_pos = p_mmap->number_packets / p_mmap->rb->frames_per_block;
  frame_offset = p_mmap->number_packets % p_mmap->rb->frames_per_block;

  *((int *)p_mmap->rb->pg_vec[0]) =
      p_mmap->number_packets; // 0 index is reserved to put here the last added
                              // number

  return p_mmap->rb->pg_vec[pg_vec_pos] +
         (frame_offset * p_mmap->rb->frame_size);
}

/* init mmap */
int init_mmap_all(int buf_size, char *chardevname, struct pkt_mmap *p_mmap,
                  const struct vm_operations_struct *packet_mmap_ops,
                  const struct file_operations *mmap_fops) {
  int block_count;
  int ret;

  if (p_mmap == NULL) {
    log("!p_mmap");
    return -1;
  }

  block_count = buf_size / 4096;

  p_mmap->packet_mmap_ops = packet_mmap_ops;

  // 1. fill req
  p_mmap->req = kmalloc(sizeof(struct tpacket_req), GFP_ATOMIC);
  memset(p_mmap->req, 0, sizeof(*p_mmap->req));
  p_mmap->req->tp_block_size = 4096; // one page max
  p_mmap->req->tp_frame_size = 2048; // greater then mtu size
  p_mmap->req->tp_block_nr = block_count;
  p_mmap->req->tp_frame_nr = block_count * 2;

  // 2. create pg_vec
  printk("get order\n");
  p_mmap->order = get_order(p_mmap->req->tp_block_size);

  printk("alloc\n");
  p_mmap->pg_vec = alloc_pg_vec(p_mmap->req, p_mmap->order);

  // 3. create rb
  p_mmap->rb = kmalloc(sizeof(struct packet_ring_buffer), GFP_ATOMIC);
  p_mmap->rb->pg_vec = p_mmap->pg_vec;
  p_mmap->rb->frame_max = (p_mmap->req->tp_frame_nr - 1);
  p_mmap->rb->head = 0;
  p_mmap->rb->frame_size = p_mmap->req->tp_frame_size;
  p_mmap->rb->pg_vec_order = p_mmap->order;
  p_mmap->rb->pg_vec_len = p_mmap->req->tp_block_nr;
  p_mmap->rb->pg_vec_pages = p_mmap->req->tp_block_size / PAGE_SIZE;
  p_mmap->rb->frames_per_block =
      p_mmap->req->tp_block_size / p_mmap->req->tp_frame_size;

  /* get the major number of the character device */
  ret = -1;
  if ((ret = alloc_chrdev_region(&(p_mmap->mmap_dev), 0, 1, chardevname)) < 0) {
    printk(KERN_ERR "could not allocate major number for mmap\n");
    goto out_unalloc_region;
  }

  /* initialize the device structure and register the device with the kernel */
  cdev_init(&(p_mmap->mmap_cdev), mmap_fops);

  if ((ret = cdev_add(&(p_mmap->mmap_cdev), p_mmap->mmap_dev, 1)) < 0) {
    printk(KERN_ERR "could not allocate chrdev for mmap\n");
    goto out_unalloc_region;
  }

  p_mmap->max_packets = p_mmap->req->tp_frame_nr;

  *((int *)p_mmap->rb->pg_vec[0]) = 0;

  return 0;

out_unalloc_region:
  return ret;
}

void mmap_clear_all(struct pkt_mmap *p_mmap) {
  cdev_del(&p_mmap->mmap_cdev);
  unregister_chrdev_region(p_mmap->mmap_dev, 1);
  printk("mmap free...\n");
  free_pg_vec(p_mmap->pg_vec, p_mmap->order, p_mmap->req->tp_block_nr);
  kfree(p_mmap);
}

#endif /* MMAP_UTILS_H_ */
