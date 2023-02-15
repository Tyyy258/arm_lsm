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

int ininitrd = 0;
int platform_status=0;

struct security_hook_heads *my_hook_head;

struct 
{
	unsigned short size;
	unsigned int addr; // 高32位为idt表地址
}__attribute__((packed)) idtr; // idtr是48位6字节寄存器

typedef struct os_security {
    int indicate;              // indicate if the proc to monitor
} os_security_t;

struct super_proc{
	char *install_proc;
	pid_t super_pid;	//root proc pid
	pid_t install_pid;
//	pid_t lastfound;
	unsigned long checksum;
};

struct super_proc root_proc = {
	.install_proc	= "os_install",
	.install_pid	= 1,
	.checksum	= 1,//exec permission checksum,exec permission expire when "os_install" proc exit
	.super_pid	= 1, //os_install's parent proc ip,"bash"
};

unsigned long clear_and_return_cr0(void);
void setback_cr0(unsigned long val);
void my_init_security_hook_list(void);
static void my_add_hooks(struct security_hook_list *hooks, int count, char *lsm);
static void my_del_hooks(struct security_hook_list *hooks, int count);

// unsigned long clear_and_return_cr0()
// {
// 	unsigned long cr0 = 0;
// 	unsigned long ret;
// 	asm volatile("movq %%cr0,%%rax"
// 				 : "=a"(cr0));
// 	ret = cr0;
// 	cr0 &= 0xfffeffff;
// 	asm volatile("movq %%rax,%%cr0" ::"a"(cr0));
// 	return ret;
// }

// void setback_cr0(unsigned long val)
// {
// 	asm volatile("movq %%rax,%%cr0" ::"a"(val));
// }

int my_file_open(struct file *file)
{
	printk("The file opened is %s\n", file->f_path.dentry->d_iname);
	return 0;
}

void
super_proc_init(void)
{

	struct task_struct *p;

	if (root_proc.super_pid != 1)
		return;
	p = current;
	while(p->parent->pid != 1)
	{
//		DEBUG("super_proc loading ,p [%s]\n",p->comm);
		if(!strcmp(p->parent->comm,"SecurityManage"))
		{
			root_proc.super_pid= p->parent->pid;
			root_proc.install_pid = p->pid;
			printk("super_proc load success,pid [%d]\n",root_proc.super_pid);
		}
		p = p->parent;
	}
	return;
}

int super_proc_clean(void)
{
//DEBUG("super_proc unload [%d]\n",root_proc.super_pid);
	root_proc.super_pid = 1;
	root_proc.install_pid = 1;
	return 0;
}


int os_fs_bprm_alloc_security(struct linux_binprm *bprm)
{
//	struct task_struct *iterate_task = current;

	if(!strcmp(bprm->filename,"/boot/securitymanage/SecurityManage"))
		{
		super_proc_clean();
		return 0;
		}

	if(root_proc.super_pid != 1)
		{
		return 0;
		}
	
	if (!strcmp(current->comm,"os_install"))
	{
		if(current->parent->parent==NULL)
			return 0;
		if(((!strcmp(current->parent->parent->comm,"xterm"))&&(!strcmp(current->parent->parent->parent->comm,"SecurityManage")))||
				(!strcmp(current->parent->parent->comm,"SecurityManage")))
			{
			super_proc_init();
			return 0;
			}
		if(current->parent->parent->parent==NULL)
			return 0;
		if((!strcmp(current->parent->parent->comm,"xterm"))&&(!strcmp(current->parent->parent->parent->comm,"SecurityManage")))
			{
			super_proc_init();
			return 0;
			}		
	}

/*
	if (!strcmp(bprm->filename,"/bin/os_install"))
	{
		for (;iterate_task->pid != 1;iterate_task = iterate_task->parent )
			{
			if(!strcmp(iterate_task->comm,"SecurityManage"))
				{
				super_proc_init();
				return 0;
				}
			}
	}
*/

	return 0;
}


int my_bprm_check_security(struct linux_binprm *bprm)
{
	if(ininitrd)
	{
	if(!memcmp(bprm->filename,"/sbin/init",10))
		{
		platform_status = ininitrd;
		ininitrd = 0;
		printk("tjsdebug: Get out of initrd here?\n\n");
		}
	}
	if(bprm != NULL){
		printk("bprm file  %s\n", bprm->file->f_path.dentry->d_iname);
	}
	return os_fs_bprm_alloc_security(bprm);
    //return os_fs_bprm_check_security (bprm);
	//return 0;
}


int my_kernel_module_request(char *kmod_name)
{
	if(kmod_name != NULL){
		printk("User add module  {%s}\n", kmod_name);
	}
	printk("User add module \n");
	return 0;
}

int my_kernel_read_file(struct file *file, enum kernel_read_file_id id,
			      bool contents)
{
	if(file != NULL){
		printk("User add module file pointer {%p}\n",  file); 
		printk("User add module {%s}\n",  file->f_path.dentry->d_name.name); 
	}
	
	return 0;
}

int my_mmap_file(struct file *file, unsigned long reqprot, unsigned long prot, unsigned long flags)
{
	// static const char proc_name[] = "proc";
	// os_security_t *sec = (os_security_t *)current->cred->security;  //current宏指向当前内核正在执行的进程的结构体
	// if (file != NULL ) {
	// 	//struct passwd *pwd = getpwuid(getuid());
	// 	printk("Process {%s} mmap file {%s}\n", proc_name, file->f_path.dentry->d_name.name);
	// 	// printk("Process {%s} mmap file {%llx}\n", proc_name, file);
	// 	//return 0;
	// }
	// if (file != NULL && sec != NULL && sec->indicate == 1) {  //匿名映射
	// 	printk("Process {%s} mmap file {%s}\n", proc_name, file->f_path.dentry->d_name.name);   //打印文件名字，而不是整个路径，
	// 	// printk("Process {%s} mmap file {%llx}\n", proc_name, file);
	// }

	os_security_t *sec = (os_security_t *)current->cred->security;
	if(file != NULL)
	{
//		printk("Process mmap file {%s}\n",  file->f_path.dentry->d_name.name); 
	}
	//printk("Process mmap file {}\n");  //未oops
	//printk("Process mmap file {file pointer :0x%p}\n",  file);  //oops
	//printk("Process mmap file {f_path.dentry pointer :0x%p}\n",  file->f_path.dentry);  //oops
	
	return 0;
}

int check_syscall(void)
{
	unsigned long *sys_call_table = 0;
	sys_call_table = (unsigned long *)kallsyms_lookup_name("sys_call_table");
	//printk("sys_call_table_addr:%lx \n"); 

	return 0;  
}

// int check_idt(void)
// {
// 	asm("sidt %0":"=m"(idtr)); 
// 	printk(KERN_ALERT "idt table adr: 0x%x\n", idtr.addr);

// 	return 0;  
// }

int my_task_alloc(struct task_struct *task,unsigned long clone_flags)
{
	check_syscall();
	//check_idt();
//    printk("[+geek] call task_create().\n");    
    return 0;
}


struct security_hook_list hooks[2]; //目的是将这两个security_hook_list结构体中的list head指针插入到security_hook_heads结构体中对应的位置

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