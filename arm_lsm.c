#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/lsm_hooks.h>
#include <linux/security.h>
#include <linux/binfmts.h>
#include <linux/fs.h>
#include <linux/moduleparam.h>
#include <linux/sched.h>
#include <linux/kthread.h>
#include <linux/err.h>
#include <linux/elf.h>
#include <linux/string.h>
#include <linux/module.h>
#include <linux/mm.h>
#include <linux/kallsyms.h>


struct security_hook_heads *my_hook_head;

struct 
{
	unsigned short size;
	unsigned int addr; // 高32位为idt表地址
}__attribute__((packed)) idtr; // idtr是48位6字节寄存器

unsigned long clear_and_return_cr0(void);
void setback_cr0(unsigned long val);
void my_init_security_hook_list(void);
static void my_add_hooks(struct security_hook_list *hooks, int count, char *lsm);
static void my_del_hooks(struct security_hook_list *hooks, int count);


int my_file_open(struct file *file)
{
	if(file != NULL){
		//printk("The file opened is %s\n", file->f_path.dentry->d_iname);
	}
		
	return 0;
}


int my_bprm_check_security(struct linux_binprm *bprm)
{

	if(bprm != NULL){
		//printk("bprm file  %s\n", bprm->file->f_path.dentry->d_iname);
	}

	return 0;
}


int my_kernel_read_file(struct file *file, enum kernel_read_file_id id,
			      bool contents)
{
	if(file != NULL){
		//printk("User add module file pointer {%p}\n",  file); 
		//printk("User add module {%s}\n",  file->f_path.dentry->d_name.name); 
	}
	
	return 0;
}

int my_mmap_file(struct file *file, unsigned long reqprot, unsigned long prot, unsigned long flags)
{
	if(file != NULL)
	{
		//printk("Process mmap file {%s}\n",  file->f_path.dentry->d_name.name); 
	}
	
	return 0;
}

int check_MMU(void *pvoid)
{
	int sctlr_el1, st_mmu=0;

	asm volatile("mrs %0, SCTLR_EL1 \n\t" //读sctlr系统寄存器
				//"asr %0, %0, #31 \n\t"  //sctlr系统寄存器逻辑右移31位
				//"bic %0,%0,#0x7fffffff  \n\t"  //sctlr寄存器后31位置0
				//"orr %0,%0,#0x80000000  \n\t" //sctlr寄存器第0位置1
		: "=r" (sctlr_el1)
	);
	st_mmu = (unsigned int)sctlr_el1 >> 31;
	printk("MMU status: %x\n", st_mmu);

	return 0;  
}

int check_PageRW(void *pvoid)
{
	int kernel_pagetable_base, user_pagetable_base=0;

	asm volatile("mrs %0, TTBR1_EL1" 
		: "=r" (kernel_pagetable_base)
	);
	printk("kernel_pagetable_base: 0x%x\n", kernel_pagetable_base);

	return 0;
}

int check_idt(void *pvoid)
{
	int vbar_el1 = 0;

	asm volatile("mrs %0, VBAR_EL1" 
		: "=r" (vbar_el1)
	);
	printk("r_vbar_el1: 0x%x\n", vbar_el1);

	return 0;
}

int check_syscall(void *pvoid)
{
	unsigned long *sys_call_table = 0;

	sys_call_table = (unsigned long *)kallsyms_lookup_name("sys_call_table");
	printk("sys_call_table_addr:%lx \n"); 

	return 0;  
}

int check_SELinux(void *pvoid)
{
	return 0;
}

int my_task_alloc(struct task_struct *task,unsigned long clone_flags)
{
	void * pvoid;
	check_MMU(pvoid);
	//check_PageRW(pvoid);
	//check_idt(pvoid);
	//check_syscall(pvoid);
	//check_SELinux(pvoid);

    return 0;
}


struct security_hook_list hooks[]; //----security_hook_list是哈希节点

void my_init_security_hook_list(void)
{
	union security_list_options my_hook;
	hooks[0].head = &my_hook_head->task_alloc;  //----hooks[0].head要指向链表头节点，作为尾插法参数，也就是security_hook_heads->task_alloc,也就是&my_hook_head->task_alloc
	my_hook.task_alloc = my_task_alloc;   //----替换security_list_options中的函数指针
	hooks[0].hook = my_hook;  //---将security_list_options注册到security_hook_list中
							  

	hooks[1].head = &my_hook_head->mmap_file;
	my_hook.mmap_file = my_mmap_file;
	hooks[1].hook = my_hook;

	hooks[2].head = &my_hook_head->kernel_read_file;
	my_hook.kernel_read_file = my_kernel_read_file;
	hooks[2].hook = my_hook;

	hooks[3].head = &my_hook_head->bprm_check_security;
	my_hook.bprm_check_security = my_bprm_check_security;
	hooks[3].hook = my_hook;
}


static void my_add_hooks(struct security_hook_list *hooks, int count, char *lsm){
	int i;
	for(i = 0; i < count; i++){
		hooks[i].lsm = lsm;
		hlist_add_tail_rcu(&hooks[i].list, hooks[i].head);    //---hlist_add_tail是把一个哈希链表的节点插入到哈希链表的头节点的前边，也就是尾插法。已经设置hooks[i].head是头节点指针，&hooks[i].list是新list_head节点。将list_head节点插入哈希表后，可以通过list_head指针访问security_hook_list，调用钩子函数。
															
		printk("***************add hooks[%d]*************\n", i);
	}
}

static void my_del_hooks(struct security_hook_list *hooks, int count){
	int i;
	for(i = 0; i < count; i++){
		hlist_del_rcu((struct hlist_node *)&hooks[i].list);
		printk("***************del hooks[%d]*************\n", i);
	}
}

static int __init my_init(void)
{
	printk("***************my security start*************\n");

	//unsigned long cr0;
	my_hook_head = (struct security_hook_heads *)kallsyms_lookup_name("security_hook_heads");
	//printk("***************kallsyms_lookup_name success*************\n");

	my_init_security_hook_list();   
	//printk("***************my_init_security_hook_list success*************\n");

	//cr0 = clear_and_return_cr0();  //---节点security_hook_list hooks[0]中已经有my_钩子函数，且节点尾指针指向
	my_add_hooks(hooks, 4,"arm_lsm");
	//printk("***************my_add_hooks success*************\n");
	//setback_cr0(cr0);

	return 0;
}

static void __exit my_exit(void)
{
	//unsigned long cr0;

	//cr0 = clear_and_return_cr0();
	my_del_hooks(hooks, 4);
	//setback_cr0(cr0);

	printk("***************my security exit*************\n");
}

module_init(my_init);
module_exit(my_exit);
MODULE_LICENSE("GPL");