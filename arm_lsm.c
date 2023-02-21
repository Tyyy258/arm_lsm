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

int check_syscall(void)
{
	unsigned long *sys_call_table = 0;
	sys_call_table = (unsigned long *)kallsyms_lookup_name("sys_call_table");
	printk("sys_call_table_addr:%lx \n"); 

	return 0;  
}

int check_mmu(void)
{
	int kernel_pagetable_base, user_pagetable_base, sctlr_el1=0;

	asm volatile("mrs %0, TTBR1_EL1" 
		: "=r" (kernel_pagetable_base)
	);
	printk("kernel_pagetable_base: 0x%x\n", kernel_pagetable_base);
	// asm volatile("mrs %0, TTBR0_EL0" 
	// 	: "=r" (user_pagetable_base)
	// );
	// printk("user_pagetable_base: 0x%x\n", user_pagetable_base);

	asm volatile("mrs %0, SCTLR_EL1" //读sctlr系统寄存器
		: "=r" (sctlr_el1)
	);
	printk("sctlr_el1: 0x%x\n", sctlr_el1);

	return 0;  
}

int check_idt(void)
{
	return 0;
}

int my_task_alloc(struct task_struct *task,unsigned long clone_flags)
{
	//check_syscall();
	check_mmu();
	//check_idt();

    return 0;
}


struct security_hook_list hooks[]; //目的是将这两个security_hook_list结构体中的list head指针插入到security_hook_heads结构体中对应的位置

void my_init_security_hook_list(void)
{
	union security_list_options my_hook;
	hooks[0].head = &my_hook_head->task_alloc;  //传递内核默认的task_alloc指针，my_hook_head是导出符号表里的地址
	my_hook.task_alloc = my_task_alloc;   //
	hooks[0].hook = my_hook;  //把我的task_alloc函数指针传给联合体，再传给securoty_hook_list实例，此实例既包含我的task_alloc函数指针（hook成员），
							  //也包含将被注册的head list结构体

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
		hlist_add_tail_rcu(&hooks[i].list, hooks[i].head);    //利用list_add_tail_rcu，将security_hook_list插入到security_hook_heads实例对应成员链表中，
															//该成员由security_hook_list.head成员指定，在security_hook_list初始化时已经初始化
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

	//cr0 = clear_and_return_cr0();
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