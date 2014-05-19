#include <linux/ctype.h>
#include <linux/crypto.h>
#include <linux/scatterlist.h>
#include <crypto/compress.h>
#include <linux/crc32.h>

#define SHA1_LENGTH 20
#define MD5_LENGTH 20

int sig_user(struct node *element){

	struct siginfo info;
	struct task_struct *t;
	int err = 0, job_id = 0;
	info.si_signo=SIGIO;
	info.si_int=1;
	info.si_code = SI_QUEUE;
	job_id = element->job.id;
	
	
	t= pid_task(find_vpid(((struct job*)ptr)->pid),PIDTYPE_PID);
	if(t == NULL){
		//printk("<1>no such pid, cannot send signal\n");
	} else {
       		//printk("<1>found the task, sending signal\n");
		info.si_code = job_id;
		if((global_err) < 0 && (global_err > -131)){
			info.si_errno = global_err;
		}
		else{
			info.si_errno = 0;
		}
		send_sig_info(SIGIO, &info, t);
		err = -ENOMEM;
	}

	return err;

}


u32 checksum(char *infile)
{
	u32 crc = 0;
	char *out_file;
	int pend, bytes, curmax, curpos, err = 0;
	struct file *infilp, *outfilp;
	char *buf;
	char mystr[20];
	mm_segment_t oldfs;
	
	out_file = kmalloc(sizeof(char)*(strlen(infile) + 5), GFP_KERNEL);
	strcpy(out_file, infile);
	strcat(out_file, ".crc");

	infilp = filp_open(infile, O_RDONLY, 0);
	outfilp = filp_open(out_file, O_CREAT | O_TRUNC, 700);
	if (!infilp || IS_ERR(infilp))
		{
		err = IS_ERR(infilp) ? IS_ERR(infilp) : -EPERM;
		goto out;
		}
	if (!outfilp || IS_ERR(outfilp))
		{
		err = IS_ERR(outfilp) ? IS_ERR(outfilp) : -EPERM;
		goto out;
		}

	oldfs = get_fs();
	set_fs(KERNEL_DS);

	pend = infilp->f_op->llseek(infilp, 0, SEEK_END);
	infilp->f_pos = 0;
	curmax = PAGE_SIZE;
	crc = crc32(0U, 0, 0);

	if (pend > PAGE_SIZE)
		buf = kmalloc(curmax, GFP_KERNEL);
	else
		buf = kmalloc(pend, GFP_KERNEL);

	while (pend > curmax)
		{
		curpos = curpos + curmax;	 
		bytes = infilp->f_op->read(infilp, buf, curmax, &infilp->f_pos);
		pend = pend - curmax;
		crc = crc32(crc, buf, curmax);
		}
	bytes = infilp->f_op->read(infilp, buf, pend, &infilp->f_pos);
	crc = crc32(crc, buf, pend);
	sprintf(mystr, "%u", crc);

	infilp->f_op->write(outfilp, mystr, strlen(mystr), &outfilp->f_pos);
	filp_close(infilp, NULL);
	filp_close(outfilp, NULL);
	set_fs(oldfs);
	kfree(out_file);

	return crc;
out:
	return err;
}

//Extra Credit SHA1 Checksum
int sha1_checksum(char *infile){

	char *out_file;
	int pend, bytes;
	struct file *infilp, *outfilp;
	mm_segment_t oldfs;
	struct scatterlist sg;
    	struct crypto_hash *tfm;
    	struct hash_desc desc;
    	unsigned char output[SHA1_LENGTH];
    	unsigned char *buf = NULL;
	unsigned char *temp = NULL;
	unsigned char *result = NULL;
    	int i;
	int err = 0;

	out_file = kmalloc(sizeof(char)*(strlen(infile) + 5), GFP_KERNEL);
	strcpy(out_file, infile);
	strcat(out_file, ".sha1");
	temp = kmalloc(sizeof(output), GFP_KERNEL);
        result = kmalloc(sizeof(output),GFP_KERNEL);
	memset(temp, 0, sizeof(output));
	memset(result, 0, sizeof(output));
	
	infilp = filp_open(infile, O_RDONLY, 0);
	outfilp = filp_open(out_file, O_CREAT | O_TRUNC, 700);
	if (!infilp || IS_ERR(infilp))
		{
		err = IS_ERR(infilp) ? IS_ERR(infilp) : -EPERM;
		goto out;
		}
	if (!outfilp || IS_ERR(outfilp))
		{
		err = IS_ERR(outfilp) ? IS_ERR(outfilp) : -EPERM;
		goto out;
		}

	oldfs = get_fs();
	set_fs(KERNEL_DS);

	pend = infilp->f_op->llseek(infilp, 0, SEEK_END);
	infilp->f_pos = 0;
	buf = kmalloc(pend*2, GFP_KERNEL);
	bytes = infilp->f_op->read(infilp, buf, pend, &infilp->f_pos);

    	memset(output, 0x00, SHA1_LENGTH);
    	tfm = crypto_alloc_hash("sha1", 0, CRYPTO_ALG_ASYNC);
    	desc.tfm = tfm;
    	desc.flags = 0;
    	sg_init_one(&sg, buf, pend);
    	err =  crypto_hash_init(&desc);
	if(err != 0){
		printk("error in sha1 hash \n");
		goto out;
	}
    	err = crypto_hash_update(&desc, &sg, pend);
	if(err != 0){
                printk("error in sha1 hash \n");
                goto out;
        }
    	err = crypto_hash_final(&desc, output);
	if(err != 0){
                printk("error in sha1 hash \n");
                goto out;
        }
    	for (i = 0; i < 20; i++) {
        	//printk(KERN_ERR "%x", output[i]);
		sprintf(temp,"%x",output[i]);
                strcat(result,temp);
    	}
	
	infilp->f_op->write(outfilp, result, strlen(result), &outfilp->f_pos);
	filp_close(infilp, NULL);
	filp_close(outfilp, NULL);
	set_fs(oldfs);
	kfree(out_file);
    	crypto_free_hash(tfm);

out:
	if(temp){
                kfree(temp);
        }
        if(buf){
                kfree(buf);
        }
        if(result){
                kfree(result);
        }

	return err;
}

//Extra Credit MD5 Checksum
int md5_checksum(char *infile){

	char *out_file;
	int pend, bytes;
	struct file *infilp, *outfilp;
	mm_segment_t oldfs;
	struct scatterlist sg;
    	struct crypto_hash *tfm;
    	struct hash_desc desc;
    	unsigned char output[MD5_LENGTH];
    	unsigned char *buf = NULL;
    	int i;
	unsigned char *temp = NULL;
	unsigned char *result = NULL;
	int err = 0;

	out_file = kmalloc(sizeof(char)*(strlen(infile) + 5), GFP_KERNEL);
	temp = kmalloc(sizeof(output), GFP_KERNEL);
	result = kmalloc(sizeof(output),GFP_KERNEL);
	memset(temp, 0, sizeof(output));
	memset(result, 0, sizeof(output));
	strcpy(out_file, infile);
	strcat(out_file, ".md5");

	infilp = filp_open(infile, O_RDONLY, 0);
	outfilp = filp_open(out_file, O_CREAT | O_TRUNC, 700);
	if (!infilp || IS_ERR(infilp))
		{
		err = IS_ERR(infilp) ? IS_ERR(infilp) : -EPERM;
		goto out;
		}
	if (!outfilp || IS_ERR(outfilp))
		{
		err = IS_ERR(outfilp) ? IS_ERR(outfilp) : -EPERM;
		goto out;
		}

	oldfs = get_fs();
	set_fs(KERNEL_DS);

	pend = infilp->f_op->llseek(infilp, 0, SEEK_END);
	infilp->f_pos = 0;
	buf = kmalloc(pend*2, GFP_KERNEL);
	bytes = infilp->f_op->read(infilp, buf, pend, &infilp->f_pos);

    	memset(output, 0x00, MD5_LENGTH);
    	tfm = crypto_alloc_hash("md5", 0, CRYPTO_ALG_ASYNC);
    	desc.tfm = tfm;
    	desc.flags = 0;
    	sg_init_one(&sg, buf, pend);
    	err =  crypto_hash_init(&desc);
	if(err != 0){
		printk("error in md5 hash \n");
		goto out;
	}
    	err = crypto_hash_update(&desc, &sg, pend);
	if(err != 0){
                printk("error in md5 hash \n");
                goto out;
        }
    	err = crypto_hash_final(&desc, output);
	if(err != 0){
                printk("error in md5 hash \n");
                goto out;
        }
    	for (i = 0; i < 20; i++) {
        	//printk(KERN_ERR "%x", output[i]);
		sprintf(temp,"%x",output[i]);
		strcat(result,temp);
    	}

	infilp->f_op->write(outfilp, result, strlen(result), &outfilp->f_pos);
	filp_close(infilp, NULL);
	filp_close(outfilp, NULL);
	set_fs(oldfs);
	kfree(out_file);
    	crypto_free_hash(tfm);

out:
	if(temp){
		kfree(temp);
	}
	if(buf){
		kfree(buf);
	}
	if(result){
		kfree(result);
	}
	return err;
}


int read_file(const char *filename, void *buf, int len, int pos){
//This function reads file data to a buffer and returns number of bytes read 
	struct file *filp;
	mm_segment_t oldfs;
	int bytes;

// Check for partial read in case files gets corrupted before reading start
	//filp=filp_open(filename,O_RDONLY,0);
	filp=filp_open(filename,O_RDONLY,0);

	if(!filp || IS_ERR(filp)){
		printk(KERN_ALERT "No such file! %s\n",filename);
		bytes = -ENOENT;
		goto end_read;
	}

	if(!filp->f_op->read){
		printk(KERN_ALERT "%s donot have read permission !\n",filename);
		bytes = - EACCES;
		goto end_read;
	}
	// partial read check end 
	filp->f_pos=pos;
	oldfs=get_fs();
	set_fs(KERNEL_DS);
	bytes = filp->f_op->read(filp,buf,len,&filp->f_pos);
	set_fs(oldfs);

	if(bytes==0){
		printk(KERN_ALERT "No data available in file: %s \n",(char *)
								filename);
		printk(KERN_ERR "errno : %d \n",-ENODATA);
	}	

	end_read:
	if(filp && !IS_ERR(filp)){
		filp_close(filp,NULL);
	}	
	return bytes;
}

int write_file(struct file *filp,void *buf,int len){
//This function writes data to a file from buffer of PAGE_SIZE length
	mm_segment_t oldfs;
	int ret;

	if(!filp->f_op->write){
		printk(KERN_ALERT "Syscall don't allow writing file");
		ret = -EACCES;
		goto end;
	}	
	
	oldfs=get_fs();
	set_fs(KERNEL_DS);
	ret=vfs_write(filp,buf,len,&filp->f_pos);	
	set_fs(oldfs);
	
	if(ret < 0){
		printk("Outfile partially written \n");
		ret = -EIO;
	}

	end:
	return ret;
}

char *aes_encrypt(const void *key, int key_length, const char *plain_text, size_t size)
{
        struct crypto_blkcipher *tfm = crypto_alloc_blkcipher("ctr(aes)", 0, CRYPTO_ALG_ASYNC);
        struct scatterlist sg_input[1], sg_output[1];
        struct blkcipher_desc desc = {.tfm = tfm, .flags = 0};
        int ret = 0;
        char *cipher_text = kmalloc(PAGE_SIZE, GFP_KERNEL);

        if (IS_ERR(tfm) || !tfm){
                printk("Error allocating cipher memory\n");
                ret = PTR_ERR(tfm);
                goto out;
        }

        ret = crypto_blkcipher_setkey(tfm, key, key_length);
        if (ret){
                printk("Error setting key\n");
                goto out;
        }
        sg_init_table(sg_input, 1);
        sg_set_buf(sg_input, plain_text, size);
        sg_init_table(sg_output, 1);
        sg_set_buf(sg_output, cipher_text, size);
        ret = crypto_blkcipher_encrypt(&desc, sg_output, sg_input, size);
        crypto_free_blkcipher(tfm);
      
	  if (ret < 0){
                printk("Encryption failed with %d\n", ret);
                goto out;
        }
        ret = 0;
out:
        return cipher_text;
}

char *aes_decrypt(const void *key, int key_length, const char *cipher_text, size_t size)
{
        struct crypto_blkcipher *tfm = crypto_alloc_blkcipher("ctr(aes)", 0, CRYPTO_ALG_ASYNC);
        struct scatterlist sg_input[1], sg_output[1];
        struct blkcipher_desc desc = {.tfm = tfm, .flags = 0};
        int ret = 0;
        char *plain_text = kmalloc(PAGE_SIZE, GFP_KERNEL);

        UDBG;
        if (IS_ERR(tfm) || !tfm){
                printk("Error in allocating cipher memory\n");
                ret = PTR_ERR(tfm);
                goto out;
        }

        ret = crypto_blkcipher_setkey(tfm, key, key_length);
        if (ret){
                printk("Error in setting key\n");
                goto out;
        }
        sg_init_table(sg_input, 1);
        sg_set_buf(sg_input, cipher_text, size);
        sg_init_table(sg_output, 1);
        sg_set_buf(sg_output, plain_text, size);
        ret = crypto_blkcipher_decrypt(&desc, sg_output, sg_input, size);
        crypto_free_blkcipher(tfm);
        if (ret < 0){
                printk("Decryption failed with %d\n", ret);
                goto out;
        }
        ret = 0;
out:
        UDBG;
        return plain_text;
}





int perform_task(struct node *element){

	int byte_read = 0, exceedFactor = 0, byte_write = 0;
	int j = 0, pos = 0, ret = 0, i = 0;
	int len = PAGE_SIZE;
	struct file *ren_file = NULL;
	struct file *infile = NULL;
	struct file *out_file = NULL;
	void *buf = NULL;
	char *text = NULL;
	char *rename_name = NULL;
	mm_segment_t oldfs;
	struct kstat fileStat;

	ren_file = NULL;
	out_file = NULL; 
	oldfs = get_fs();
	set_fs(KERNEL_DS);
	
	if(element->job.type == Encrypt || element->job.type == Decrypt){

        UDBG;
        buf = kmalloc(PAGE_SIZE,GFP_KERNEL);
	memset(buf, 0, PAGE_SIZE);

	printk("count: %d \n",element->job.count);
        for(i = 1; i < element->job.count; i++){
		UDBG;
                infile = filp_open(element->job.files[i],O_RDONLY,0);
                if(IS_ERR(infile)){
                        printk("file cannot be opened for read \n");
                        ret = -ENOENT;
                        continue;
                }else{
                        UDBG;
                        vfs_stat(element->job.files[i],&fileStat);
                        exceedFactor=((int)fileStat.size/len);
                }

                if(exceedFactor==0){
                        UDBG;
                        //printk("exceed factor == 0 \n");
			//printk("key: %s \n",element->job.files[0]);
                        byte_read=read_file(element->job.files[i],buf,len,0);
                        UDBG;
			if(element->job.type == Encrypt){
                        	text = aes_encrypt(element->job.files[0], 16,buf, fileStat.size);
			}
			else if(element->job.type == Decrypt){
				UDBG;
				text = aes_decrypt(element->job.files[0], 16,buf, fileStat.size);
				//printk("decrypt: %s \n",text);
			}
                    
		        if(element->job.out_ind == Overwrite){
                               out_file = filp_open(element->job.files[i],O_WRONLY | O_TRUNC,0);	
                               byte_write=write_file(out_file,text,byte_read);
                        }
                        else if(element->job.out_ind == Rename){
                        
				UDBG;	
                                rename_name = kmalloc(sizeof(char)*(strlen(element->job.files[i]) + 5), GFP_KERNEL);;
                                strcpy(rename_name, element->job.files[i]);
                     		UDBG;
				if(element->job.type == Encrypt){
			        	strcat(rename_name, ".Enc");
				}
				else if(element->job.type == Decrypt){
					UDBG;
					strcat(rename_name, ".Dec");
				}
				out_file = filp_open(element->job.files[i],O_WRONLY | O_TRUNC,0);
                                byte_write=write_file(out_file,text,byte_read);
                                ren_file = filp_open(rename_name,O_CREAT | O_WRONLY,0);
                                UDBG;
                                vfs_rename(out_file->f_path.dentry->d_parent->d_inode, out_file->f_path.dentry,
                                ren_file->f_path.dentry->d_parent->d_inode, ren_file->f_path.dentry);
                                UDBG;   
                        }
 		}
                else{
			out_file = filp_open(element->job.files[i],O_WRONLY | O_TRUNC,0);
                        for(j=0,pos=0;j<exceedFactor;j++){
                        //printk("exceed factor != 0 \n");
                        byte_read=read_file(element->job.files[i],buf,len,pos);
                        pos+=len;
                       
			UDBG;
			if(element->job.type == Encrypt){
                        	text = aes_encrypt(element->job.files[0], 16,buf, fileStat.size);
			}
			else if(element->job.type == Decrypt){
				UDBG;
				text = aes_decrypt(element->job.files[0], 16,buf, fileStat.size);
				//printk("decrypt: %s \n",text);
			}
                    
		        if(element->job.out_ind == Overwrite){
                               out_file = filp_open(element->job.files[i],O_WRONLY | O_APPEND,0);	
                               byte_write=write_file(out_file,text,byte_read);
                        }
                        else if(element->job.out_ind == Rename){
                        
				UDBG;	
                                rename_name = kmalloc(sizeof(char)*(strlen(element->job.files[i]) + 5), GFP_KERNEL);;
                                strcpy(rename_name, element->job.files[i]);
                     		UDBG;
				if(element->job.type == Encrypt){
			        	strcat(rename_name, ".Enc");
				}
				else if(element->job.type == Decrypt){
					UDBG;
					strcat(rename_name, ".Dec");
				}
				out_file = filp_open(element->job.files[i],O_WRONLY | O_APPEND,0);
                                byte_write=write_file(out_file,text,byte_read);
                                ren_file = filp_open(rename_name,O_CREAT | O_WRONLY | O_APPEND,0);
                                UDBG;
                                vfs_rename(out_file->f_path.dentry->d_parent->d_inode, out_file->f_path.dentry,
                                ren_file->f_path.dentry->d_parent->d_inode, ren_file->f_path.dentry);
                                UDBG;   
                        }
 
			
                        }
                }
        }
        }

	

	if((element->job.type == Checksum) || (element->job.type == EXTRA_CREDIT_MD5) || (element->job.type == EXTRA_CREDIT_SHA1)){
	for(j = 0; j < element->job.count; j++){
		infile = filp_open(element->job.files[j],O_RDONLY,0);
		if(IS_ERR(infile)){
                	printk("file cannot be opened for read \n");
			ret = -ENOENT;
                	continue;
        	}

		if(element->job.type == Checksum){
	 		ret = checksum(element->job.files[j]);
		}
		else if(element->job.type == EXTRA_CREDIT_MD5){
			ret = md5_checksum(element->job.files[j]);
		}
		else if(element->job.type == EXTRA_CREDIT_SHA1){
                        ret = sha1_checksum(element->job.files[j]);
                }

		if(infile){
                	filp_close(infile,NULL);
        	}
	}
	}

	global_err = ret;
	
	if(ren_file){
		filp_close(ren_file,NULL);
        }

	if(out_file){
                filp_close(out_file,NULL);
        }	
	if(buf){
		kfree(buf);
	}
	if(text){
		kfree(text);
	}
	if(rename_name){
                kfree(rename_name);
        }
		
	set_fs(oldfs);

	return ret;
}

