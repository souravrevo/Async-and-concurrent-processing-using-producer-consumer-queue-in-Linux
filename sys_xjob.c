#include <linux/linkage.h>
#include <linux/moduleloader.h>
#include <linux/buffer_head.h>
#include <linux/slab.h>
#include <linux/proc_fs.h>
#include <linux/kthread.h>
#include <linux/delay.h>
#include <linux/wait.h>
#include <linux/crypto.h>
#include <linux/types.h>
#include <linux/signal.h>
#include "common.h"
#include "utils.h"

int Producer(void *data);
int Consumer(void *data);

asmlinkage extern long (*sysptr)(void *arg,unsigned int length);

asmlinkage long xjob(void *arg,unsigned int length){

	char *temp = kmalloc(sizeof(char*),__GFP_WAIT);
	//char *temp = kmem_cache_alloc(kcache, GFP_KERNEL);
	//struct node *q;
	bool valid = false;
	long remove_id = 0;	
 	int err = 0, i = 0;
	ptr = kmalloc(length,__GFP_WAIT);
	myfiles = kmalloc(sizeof(char *)*(((struct job*)arg)->count), __GFP_WAIT);
	//ptr = kmem_cache_alloc(kcache, GFP_KERNEL);

	if(!ptr){
		printk(KERN_ALERT "ptr allocation failed \n");
		err = - ENOMEM;
		goto end_xjob;
	}
	if(!temp){
		printk(KERN_ALERT "temp allocation failed \n");
		err = -ENOMEM;
		goto end_xjob;
	}	
	if(arg==NULL){
		printk("Arg is NULL \n");
		err = -EINVAL;
		goto end_xjob;
	}
	/*if(length != 24){
		printk("Invalid length from User_Space \n");
		ret = -EFAULT;
		goto end_xcat;
	}*/
	if(access_ok(VERIFY_READ,arg,length)>0){ // User address validation

		if(copy_from_user(ptr,arg,length)==0)
		{

			((struct job*)ptr)->files = myfiles;
		// User arguments validation
			valid = true;
	
			for(i=0;i<(((struct job*)ptr)->count);i++)
			{
				temp = getname(((struct job*)arg)->files[i]);
				((struct job*)ptr)->files[i] = temp;
			}
		}
	
	else{
		printk(KERN_ALERT "EFAULT in copy_from_user \n");
		err = -EFAULT;
		goto end_xjob;
	}	
	if(valid){
		mutex_init(&my_mutex);	
		if((((struct job*)ptr)->type) == Display){
			//printk("Display all elements only\n");
			display();
			display_wait();
			goto end_xjob;
		}
		if((((struct job*)ptr)->type) == Remove_All){
			//printk("Remove All\n");
			mutex_lock(&my_mutex);
			deinit_queue();
       		 	deinit_queue_wait();
			mutex_unlock(&my_mutex);	
			goto end_xjob;
		}
		if((((struct job*)ptr)->type) == Remove){
			//printk("Remove one\n");
			err = kstrtol((((struct job*)ptr)->files[0]), 10, &remove_id);
			if(err !=0){
				goto end_xjob;
			}
			mutex_lock(&my_mutex);
			err = remove_job(remove_id);
			mutex_unlock(&my_mutex);	
			goto end_xjob;
		}		
		err = Producer(NULL);
	}
	}
	else{
		printk(KERN_ALERT "EFAULT in access_ok \n");
		err = -EFAULT;
		goto end_xjob;
	}
	
end_xjob:
	//Free all resources start

	if(temp){
		kfree(temp);
	}
	if(ptr){
		kfree(ptr);
	}	
	//Free all resources end
	return err;
}


int Producer(void *data)
{    	
	void *jobq = NULL;
	int ret = 0;

	((struct job*)ptr)->id = id;
	id++;	

begin:
	if(ptr == NULL){
		goto wake_consumer;
	}

	mutex_lock(&my_mutex);
	if((qlen >= QMAX) && (qlen_wait >= QMAX_WAIT)){

		//printk("producer wait goto begin \n");
		pwait = false;
		qfull = true;
		mutex_unlock(&my_mutex);
		wait_event_interruptible(wqp, pwait);
		goto begin;
		//ret = 0;
		//goto out;
	}
	jobq = ptr;
	//printk("p3 \n");
	if(qlen < QMAX){
		ret = enQueue(jobq);
		//printk("producer qlen before %d \n",qlen);
       		qlen++;
        	//printk("producer qlen after %d \n",qlen);
	}
	else{
		ret = enQueue_wait(jobq);
		//printk("producer qlen_wait before %d \n",qlen_wait);
        	qlen_wait++;
        	//printk("producer qlen_wait after %d \n",qlen_wait);
	}	
	
	if(ret != 0){
		printk("Error in enQueue \n");
		goto out;
	}
	display();
	display_wait(); 
	mutex_unlock(&my_mutex);

wake_consumer:
	if(qlen > 0){
		//printk("Before consumer wake \n");
		cwait = true;
		wake_up_all(&wqc);
		//printk("After consumer wake \n"); 
	}
	
out:
	//printk("producer end \n");
	//goto begin;  
	return ret; 
}

int Consumer(void *data){	

	int ret = 0;
	struct node *element = NULL, *element_wait = NULL;
begin:	
	wait_event_interruptible(wqc, cwait);

	printk("After cwait \n");
	mutex_lock(&my_mutex);
	if (qlen == 0) {
    		mutex_unlock(&my_mutex);
    		ret = 0;
		goto out;
  	}
	//msleep(10000);
	element = deQueue(); // pull first job
	if(!element){
		printk("deQueue failed \n");
		ret = -ENOMEM;
		goto out;
	}
        qlen--; 

	if(qlen_wait > 0){
		element_wait = deQueue_wait();
		if(!element_wait){
			printk("deQueue wait failed \n");
			ret = -ENOMEM;
			goto out;
		}
		ret = enQueue((void *)element_wait);
		qlen++;
		if(ret != 0){
			printk("Error in enQueue \n");
			goto out;
		}
        	qlen_wait--;
	}	

	display();
	display_wait();
	if(qfull){
		qfull = false;
		pwait = true;
		wake_up_all(&wqp); //  	To be implemented for multiple comsumer threads
	}
	mutex_unlock(&my_mutex);

	ret = perform_task(element);

	sig_user(element);                //Signale user back on success after checking error	
	//process job end

out:
	if(element){
		kfree(element);
	}

	mutex_lock(&my_mutex);	

	if(qlen != 0){
		printk("consumer qlen != 0 goto begin \n");
		cwait = true;
	}
	else if(qlen == 0){
		printk("consumer qlen == 0 goto out_final \n");
		cwait = false;
		//goto out_final;
	}
	mutex_unlock(&my_mutex);
	//cwait = false;
	goto begin;	

	return ret;  
}

static int __init init_sys_xjob(void)
{
	printk("installed new sys_xjob module\n");
	init_queue();
	init_queue_wait();
	pwait = false;
	cwait = false;	
	qfull = false;
	qlen = 0;
	qlen_wait = 0;
	id = 1;
	//pmax = false;
	//cmin = false;
	init_waitqueue_head (&wqp);
	init_waitqueue_head (&wqc);			
	//Producer(NULL);
	//producer = kthread_run(&Producer,NULL,"producer");
   	consumer1 = kthread_run(&Consumer,NULL,"consumer1");
	//consumer2 = kthread_run(&Consumer,NULL,"consumer2");

	if (sysptr == NULL)
		sysptr = xjob;

	return 0;
}
static void  __exit exit_sys_xjob(void)
{
	if (sysptr != NULL)
		sysptr = NULL;

	deinit_queue();
	deinit_queue_wait();
	kfree(myfiles);
	//kthread_stop(producer);
	//kthread_should_stop();
	printk("removed sys_xjob module\n");
}
module_init(init_sys_xjob);
module_exit(exit_sys_xjob);
MODULE_LICENSE("GPL");
