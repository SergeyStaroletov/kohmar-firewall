/*
 * Anomaly Detection System for network traffic
 * @license GNU GPL
 * @authors Staroletov, Chudov
 */

#ifndef PROC_FS_H_
#define PROC_FS_H_

struct proc_dir_entry *Our_Proc_File;
#define PROC_ENTRY_FILENAME "ads_drv"

/*
 * Put data into the proc fs file.
 */
ssize_t procfile_read(char *buffer, char **buffer_location, off_t offset,
                      int buffer_length, int *eof, void *data) {
  int len; /* The number of bytes actually used */

  int p1, p2;
  static char my_buffer[120];

  if (offset > 0)
    return 0;

  p1 = atomic_read(&got_p);
  p2 = atomic_read(&filtered_packets);

  len = sprintf(my_buffer, "grabbed %d packets\nmodule filtered %d packets\n",
                p1, p2);

  *buffer_location = my_buffer;

  return len;
}

void init_procfs(void) {

  /*
   * * Create our /proc file

  Our_Proc_File = create_proc_entry(PROC_ENTRY_FILENAME, 0644, NULL);

  if (Our_Proc_File == NULL) {
    printk(KERN_ALERT "Error: Could not initialize /proc/%s\n",
  PROC_ENTRY_FILENAME); return;
  }

  Our_Proc_File->read_proc = procfile_read;
  Our_Proc_File->mode = S_IFREG | S_IRUGO;
  Our_Proc_File->uid = 0;
  Our_Proc_File->gid = 0;
  Our_Proc_File->size = 120;
*/
}

void remove_proc(void) {
  // remove_proc_entry(PROC_ENTRY_FILENAME, NULL);
}

#endif /* PROC_FS_H_ */
