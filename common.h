
static struct task_struct *consumer1;
//static struct task_struct *consumer2;
static unsigned int qlen;
static unsigned int qlen_wait;
struct mutex my_mutex;
char **myfiles;
void *ptr;
bool pwait; 			//Producer wait flag
bool cwait;			//Consumer wait flag
u32 cs_ret;
//bool pmax;			//Producer qlen > QMAX
//bool cmin;			//Consumer qlen <= 0
bool qfull;
static int id;
static int global_err;
wait_queue_head_t wqp;		//Wait queue producer
wait_queue_head_t wqc;		//Wait queue consumer

#define QMAX 5
#define QMAX_WAIT 5
#define AES_BLOCK_SIZE 16
#define ALG_CCMP_KEY_LEN 16
#define Checksum 0
#define Compress 1
#define Decompress 2
#define Encrypt 3
#define Decrypt 4
#define Display 5
#define Overwrite 6
#define Rename 7
#define Remove 8
#define Remove_All 9
#define EXTRA_CREDIT_MD5 10
#define EXTRA_CREDIT_SHA1 11
#define UDBG printk(KERN_DEFAULT "DBG:%s:%s:%d\n", __FILE__, __func__, __LINE__)

struct job{
__user char **files;
int id;
int pid;
int type;
int count;
int out_ind;
__user void *sig_area;
int sig;
};

struct node{
struct job job;
struct node *next;
}*tail, *head, *tail_wait, *head_wait;


void init_queue(void){

	head = NULL;
	tail = NULL;
}

void deinit_queue(void){
	struct node *temp, *buf;

	while(head != NULL){
		temp = head;
		buf = head->next;
		kfree(temp);
		head = buf;
	}
}

struct node* deQueue(void){
	struct node *var=head, *ret = NULL;
	if(var==head)
        {
		head = head->next;
		ret = var;	
		goto out;
	}

out:
	return ret;
}


int enQueue(void *job)
{
     	struct node *temp = NULL;
	int err = 0;	
	temp=kmalloc(sizeof(struct node), GFP_KERNEL);
	if(!temp){
                printk(KERN_ALERT "ptr allocation failed \n");
                err = - ENOMEM;
                goto out;
        }
	temp->job.id = ((struct job*)job)->id;	
	temp->job.type = ((struct job*)job)->type;
	temp->job.count = ((struct job*)job)->count;
	temp->job.out_ind = ((struct job*)job)->out_ind;
	temp->job.sig_area = ((struct job*)job)->sig_area;
	temp->job.pid = ((struct job*)job)->pid;
	temp->job.files = ((struct job*)job)->files;
     if(head == NULL)
     {
           tail=temp;
           tail->next=NULL;
           head=tail;
     }
     else
     {
           tail->next=temp;
           tail=temp;
           tail->next=NULL;
     }

out:

	return err;
}

void display(void)
{
     struct node *var=head;
     if(var!=NULL)
     {
	   printk("**********Queue*********\n");	
           printk("Job ID");
	   //printk("\t \tTotal Files");
	   printk("\t \tJob Type \n");
           while(var!=NULL)
           {
                //printk("\t fname %s \n",var->job.files[0]);
		printk("%d",var->job.id);
		if(var->job.type == Checksum){
			//printk("\t \t %d",var->job.count);
			printk("\t \t %s \n","Checksum");
		}
		else if(var->job.type == Encrypt){
			//printk("\t \t %d",var->job.count - 1);
			printk("\t \t %s \n","Encrypt");
		}
		else if(var->job.type == Decrypt){
			//printk("\t \t %d",var->job.count - 1);
                        printk("\t \t %s \n","Decrypt");
		}
		else if(var->job.type == EXTRA_CREDIT_MD5){
                        //printk("\t \t %d",var->job.count);
                        printk("\t \t %s \n","Extra Credit MD5");
                }
		else if(var->job.type == EXTRA_CREDIT_SHA1){
                        //printk("\t \t %d",var->job.count);
                        printk("\t \t %s \n","Extra Credit SHA1");
                }


                var=var->next;
           }
     printk("\n");
     printk("**********Queue*********\n");
     } 
     else
     	printk("\nQueue is Empty \n");
}

void init_queue_wait(void){

	head_wait = NULL;
	tail_wait = NULL;
}

void deinit_queue_wait(void){
	struct node *temp, *buf;

	while(head_wait != NULL){
		temp = head_wait;
		buf = head_wait->next;
		kfree(temp);
		head_wait = buf;
	}
}

struct node* deQueue_wait(void){
	struct node *var=head_wait, *ret = NULL;
	if(var==head_wait)
        {
		printk("dque wait var: %d \n", var->job.count);
		
		head_wait = head_wait->next;
		ret = var;	
		goto out;
	}

out:
	return ret;
}


int enQueue_wait(void *job)
{
     	struct node *temp = NULL;
	int err = 0;
	
	temp=kmalloc(sizeof(struct node), GFP_KERNEL);
	if(!temp){
                printk(KERN_ALERT "waitq ptr allocation failed \n");
                err = - ENOMEM;
                goto out;
        }
	temp->job.id = ((struct job*)job)->id;	
	temp->job.type = ((struct job*)job)->type;
	temp->job.count = ((struct job*)job)->count;
	temp->job.out_ind = ((struct job*)job)->out_ind;
	temp->job.sig_area = ((struct job*)job)->sig_area;
	temp->job.pid = ((struct job*)job)->pid;
	temp->job.files = ((struct job*)job)->files;	

     if(head_wait == NULL)
     {
           tail_wait=temp;
           tail_wait->next=NULL;
           head_wait=tail_wait;
     }
     else
     {
           tail_wait->next=temp;
           tail_wait=temp;
           tail_wait->next=NULL;
     }

out:

	return err;
}

void display_wait(void)
{
     struct node *var=head_wait;
     if(var!=NULL)
     {
	   printk("*******Wait Queue**********\n");
            printk("Job ID");
	   //printk("\t \tTotal Files");
	   printk("\t \t Job Type\n");
           while(var!=NULL)
           {
		printk("%d",var->job.id);

		if(var->job.type == Checksum){
                        //printk("\t \t %d",var->job.count);
                        printk("\t \t %s \n","Checksum");
                }
                else if(var->job.type == Encrypt){
                        //printk("\t \t %d",var->job.count - 1);
                        printk("\t \t %s \n","Encrypt");
                }
                else if(var->job.type == Decrypt){
                        //printk("\t \t %d",var->job.count - 1);
                        printk("\t \t %s \n","Decrypt");
                }
		else if(var->job.type == EXTRA_CREDIT_MD5){
                        //printk("\t \t %d",var->job.count);
                        printk("\t \t %s \n","Extra Credit MD5");
                }
                else if(var->job.type == EXTRA_CREDIT_SHA1){
                        //printk("\t \t %d",var->job.count);
                        printk("\t \t %s \n","Extra Credit SHA1");
                }

                var=var->next;
           }
     printk("\n");
     printk("*******Wait Queue**********\n");
     } 
     else
     	printk("\nWait Queue is Empty \n");
}


int remove_job(long remove_id){

	struct node *var=head, *previous = NULL, *var_wait = head_wait, *previous_wait = NULL;
	bool found = false;
	int err = 0;

	if(var != NULL){
		if(var->job.id == remove_id){
			head = head->next;
			kfree(var);
			found = true;
			if(qlen_wait > 0){
				enQueue((void *)deQueue_wait());
				qlen_wait--;
			}
			else{
				qlen--;
			}
			
			goto out;
		}
		else{
			previous = var;
			var = var->next;
		}
	}
	

	while((var != NULL))
        {
		if(var->job.id == remove_id){
			previous->next = var->next;
			kfree(var);
			found = true;
			if(qlen_wait > 0){
				enQueue((void *)deQueue_wait());
				qlen_wait--;
			}
			else{
				qlen--;
			}

			goto out;
		}
		else{
			previous = var;
			var = var->next;
		}
	}
		
	if(var_wait != NULL){
		if(var_wait->job.id == remove_id){
			head_wait = head_wait->next;
			kfree(var_wait);
			found = true;
			qlen_wait--;
			goto out;
		}
		else{
			previous_wait = var_wait;
			var_wait = var_wait->next;
		}
	}

	while((var_wait != NULL))
        {
		if(var_wait->job.id == remove_id){
			previous_wait->next = var_wait->next;
			kfree(var_wait);
			found = true;
			qlen_wait--;		
			goto out;
		}
		else{
			previous_wait = var_wait;
			var_wait = var_wait->next;
		}
	}
	
	if(!found){
		err = -ENOENT;
	}

out:
	return err;
}


