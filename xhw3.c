#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <ctype.h>
#include <math.h>
#include <stdbool.h>
#include <sys/types.h>
#include <signal.h>

#define __NR_xconcat	349	/* our private syscall number */
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

struct job{
char **files;
int id;
int pid;
int type;
int count;
int out_ind;
void *sig_area;
};

static int status;
static int err_no;
struct sigaction act;

void signal_received(int sig, siginfo_t *info, void *ptr){

	printf("Signal Received \n");
	status = info->si_code;
	err_no = info->si_errno;
}

int main(int argc, char *argv[]){

	int rc = 0;
	void *param = NULL;
	struct job job;
	int i = 0, j = 0;
	char ch = ' ';
	bool callback = false;	
	status = 0;

	job.id = 0;
	job.type = Checksum;
	job.out_ind = Overwrite;
	job.pid = getpid();
	job.sig_area = (void *)malloc(sizeof(void *)*10);	
	memset(job.sig_area, 0, sizeof(void *)*10);

	memset(&act, 0, sizeof(act));

    	act.sa_sigaction = signal_received;
    	act.sa_flags = SA_SIGINFO;

    	sigaction(SIGIO, &act, NULL);

	static const char *opstring = "edMSClxORra"; // values of allowed flags	
	
	if((argc >= 1) && (argc <= 6)){	
		while((ch=getopt(argc, argv, opstring))!=-1){
			switch(ch){
			case 'C': 
			{
				callback = true;			
				break;
			}
			case 'x':
                        {       if(job.type !=0){
					errno = EINVAL;
                                        perror("");
                                        exit(1);
                                }
                                job.type = Checksum;
                                break;
                        }
			case 'l':
                        {       if(job.type !=0){
					errno = EINVAL;
                                        perror("");
                                        exit(1);
                                }
                                job.type = Display;
                                break;
                        }
			case 'e':
                        {       if(job.type !=0){
					errno = EINVAL;
                                        perror("");
                                        exit(1);
                                }
                                job.type = Encrypt;
                                break;
                        }

			case 'd':
                        {       if(job.type !=0){
					errno = EINVAL;
                                        perror("");
                                        exit(1);
                                }
                                job.type = Decrypt;
                                break;
                        }
			case 'O':
                        {      
                                job.out_ind = Overwrite;
                                break;
                        }
			case 'R':
                        {      
                                job.out_ind = Rename;
                                break;
                        }
			case 'r':
                        {
				if(job.type !=0){
                                        errno = EINVAL;
                                        perror("");
                                        exit(1);
                                }
                                job.type = Remove;
                                break;

                        }	
			case 'a':
                        {
                                if(job.type !=0){
                                        errno = EINVAL;
                                        perror("");
                                        exit(1);
                                }
                                job.type = Remove_All;
                                break;
                        }
			case 'M':
                        {
                                if(job.type !=0){
                                        errno = EINVAL;
                                        perror("");
                                        exit(1);
                                }
                                job.type = EXTRA_CREDIT_MD5;
                                break;
                        }
			case 'S':
                        {
                                if(job.type !=0){
                                        errno = EINVAL;
                                        perror("");
                                        exit(1);
                                }
                                job.type = EXTRA_CREDIT_SHA1;
                                break;
                        }

			case '?': //Error on unknown command line arguments
			{
				errno = EINVAL;
				perror("");
				exit(1);
			}
			default:				
			{
	 			break;
			}	
			}
		}

		if((argc - optind) >= 0){
			job.count = 0;	
			job.files = malloc((argc-optind)*sizeof(char *));
			
			for(i = optind,j = 0 ; i < argc ; i++,j++){
				job.files[j]=argv[i];	
				job.count++;
				job.id++;
			}
		}
		else{
			errno = EINVAL;
			perror("");
			exit(1);
		}

		
		//printf("optind %d \n",optind);
		if((job.type == Display) && ((argc - optind) != 0)){
			goto invalid_arg;
		}
		else if((job.type != Remove_All) && (job.type != Remove) && (job.type != Display) && ((argc - optind) == 0)){
			goto invalid_arg;
		}
		else if((job.type == Remove) && ((argc - optind) != 1)){
			goto invalid_arg;
		}
		else if((job.type == Remove_All) && ((argc - optind) != 0)){
			goto invalid_arg;
		}
		else if(((job.type == Encrypt) || (job.type == Decrypt)) && ((argc - optind) < 2)){
			goto invalid_arg;
		}


	param = (void *)&job;
	rc = syscall(__NR_xconcat, param, sizeof(job));	

	if (rc >= 0){
		printf("%d\n", rc);	

		if(callback){
			sleep(2);
		}

		printf("Job Id No %d \n",status);
		printf("Job error status %d \n",err_no);

		if(job.sig_area){
			free(job.sig_area);
		}	
	} 
	else{		
		printf("syscall returned%d (errno=%d)\n", rc , errno);
		perror(""); 
	}
	}
	else{
	invalid_arg:
		errno = EINVAL;
		perror("");
	}	

	exit(rc);
}
