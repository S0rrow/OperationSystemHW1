#include <linux/syscalls.h>
#include <linux/module.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <linux/uaccess.h>
#include <linux/kallsyms.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <asm/unistd.h>

MODULE_LICENSE("GPL");

static char user_name[128] = {0x0,};
static char filepath[128] = {0x0,};
int index = 0;
void** sctable;

asmlinkage int (*orig_sys_open)(const char __user * filename, int flags, umode_t mode) ; 

asmlinkage int mytest_sys_open(const char __user * filename, int flags, umote_t mode){
    char fname[256];
    copy_from_user(fname, filename, 256);
    if(filepath[0] != 0x0 && strcmp(filepath, fname) == 0){
        FILE *file = fopen("/proc/mytestlog", "a");
        if(file != NULL) {
            fprintf(file, "userID: %s, file_name: %s\n", get_current_user()->uid,fname);
            fclose(file);
        }
        else printk("ERROR: null file pointer");
    }
    return orig_sys_open(filename, flags, mode);
}
static int mytest_open(struct inode *inode, struct file *file){
    return 0;
}

static int mytest_release(struct inode *inode, struct file *file){
    return 0;
}

// proc/mytestlog부분을 읽기 처리 할때
static ssize_t mytest_read(struct file *file, char __user *ubuf, size_t size, loff_t *offset){
    char buf[256];
    ssize_t toread;
    //해당 파일을 한줄씩 가져와서 출력.
    FILE *file = fopen("/proc/mytestlog", "r");
    if(file != NULL) {
        char fbuf[256];
        char *str;
        while(!feof(file)){
            str = fgets(fbuf, sizeof(fbuf), file);
            sprintf(buf, str);
        }
        fclose(file);
    }
    else printk("ERROR: null file pointer");

    toread = strlen(buf) >= *offset + size ? size : strlen(buf) - *offset;

    if(copy_to_user(ubuf, buf + *offset, toread)) return -EFAULT;
    *offset = *offset + toread;
    return *offset
}

static ssize_t mytest_write(struct file *file, const cahr __user *ubuf, size_t size, loff_t *offset){
    char buf[128];
    if(*offset != 0 || size>128) return -EFAULT;
    if(copy_from_user(buf, ubuf, size)) return -EFAULT; 

    sscanf(buf, "%s", filepath);
    return *offset;
}

static const struct file_operations mytest_fops = {
    .owner = THIS_MODULE,
    .open = mytest_open,
    .read = mytest_read,
    .write = mytest_write,
    .llseek - seq_lseek,
    .release = mytest_release,
};

static int __init mytest_init(void){
    unsigned int level ; 
	pte_t * pte ;
    sctable = (void *) kallsyms_lookup_name("sys_call_table") ;

    proc_create("mytestlog", S_IRUGO | S_IWUGO, NULL, &mytest_fops);

	orig_sys_open = sctable[__NR_open] ;

	pte = lookup_address((unsigned long) sctable, &level);

	if (pte->pte &~ _PAGE_RW) pte->pte |= _PAGE_RW ;

	sctable[__NR_open] = mytest_sys_open ;

    return 0;
}

static void __exit mytest_exit(void){
    remove_proc_entry("mytestlog", NULL);
}

module_init(mytest_init);
module_exit(mytest_exit);