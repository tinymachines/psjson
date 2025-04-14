#include <stdio.h>
#include <stdlib.h>
#include <stddef.h>  /* Added for size_t */
#include <string.h>
#include <dirent.h>
#include <ctype.h>
#include <unistd.h>  /* For readlink() */

/* Structure to store process information */
typedef struct {
    int pid;
    char state;
    char comm[256];
    int ppid;
    unsigned long utime;
    unsigned long stime;
    long priority;
    long nice;
    unsigned long start_time;
    unsigned long vsize;
    long rss;
    char exe_path[1024]; /* Path to the executable */
} ProcessInfo;

/* Function prototypes */
int is_pid_dir(const char *name);
int read_process_info(int pid, ProcessInfo *pinfo);
void print_json_output(ProcessInfo *processes, int count);
void print_json_string(const char *str);

int main() {
    DIR *procdir;
    struct dirent *entry;
    ProcessInfo *processes = NULL;
    int count = 0;
    int max_processes = 100;  /* Initial size */
    
    /* Allocate initial memory */
    processes = (ProcessInfo *)malloc(max_processes * sizeof(ProcessInfo));
    if (processes == NULL) {
        perror("Failed to allocate memory");
        return 1;
    }
    
    /* Open /proc directory */
    procdir = opendir("/proc");
    if (procdir == NULL) {
        perror("Cannot open /proc");
        free(processes);
        return 1;
    }
    
    /* Scan all directories in /proc */
    while ((entry = readdir(procdir)) != NULL) {
        /* Check if the directory name is a PID (i.e., a number) */
        if (is_pid_dir(entry->d_name)) {
            int pid = atoi(entry->d_name);
            
            /* If we need more space, reallocate */
            if (count >= max_processes) {
                max_processes *= 2;
                ProcessInfo *new_processes = (ProcessInfo *)realloc(processes, 
                                                           max_processes * sizeof(ProcessInfo));
                if (new_processes == NULL) {
                    perror("Failed to reallocate memory");
                    free(processes);
                    closedir(procdir);
                    return 1;
                }
                processes = new_processes;
            }
            
            /* Read process information */
            if (read_process_info(pid, &processes[count])) {
                count++;
            }
        }
    }
    
    /* Close the directory */
    closedir(procdir);
    
    /* Output the process information as JSON */
    print_json_output(processes, count);
    
    /* Free allocated memory */
    free(processes);
    
    return 0;
}

/* Check if a directory name represents a PID (i.e., is a number) */
int is_pid_dir(const char *name) {
    while (*name) {
        if (!isdigit(*name))
            return 0;
        name++;
    }
    return 1;
}

/* Read process information for a given PID */
int read_process_info(int pid, ProcessInfo *pinfo) {
    char path[256];
    FILE *fp;
    char buffer[1024];
    
    /* Initialize the process info structure */
    pinfo->pid = pid;
    pinfo->state = '?';
    strcpy(pinfo->comm, "unknown");
    pinfo->ppid = 0;
    pinfo->utime = pinfo->stime = 0;
    pinfo->priority = pinfo->nice = 0;
    pinfo->start_time = 0;
    pinfo->vsize = 0;
    pinfo->rss = 0;
    strcpy(pinfo->exe_path, ""); /* Initialize to empty string */
    
    /* Read process stat file */
    snprintf(path, sizeof(path), "/proc/%d/stat", pid);
    fp = fopen(path, "r");
    if (fp == NULL) {
        return 0;  /* Can't read stat file, possibly process has terminated */
    }
    
    if (fgets(buffer, sizeof(buffer), fp) != NULL) {
        /* Parse the stat file */
        char *comm_start = strchr(buffer, '(');
        char *comm_end = strrchr(buffer, ')');
        
        if (comm_start && comm_end) {
            int comm_len = comm_end - comm_start - 1;
            if (comm_len > 0 && comm_len < sizeof(pinfo->comm)) {
                strncpy(pinfo->comm, comm_start + 1, comm_len);
                pinfo->comm[comm_len] = '\0';
            }
            
            /* Move pointer past the comm field */
            char *stats = comm_end + 2;  /* Skip ") " */
            
            /* Parse the remaining stats */
            sscanf(stats, "%c %d %*d %*d %*d %*d %*u %*u %*u %*u %*u %lu %lu "
                          "%ld %ld %*d %*d %*d %*d %*u %lu %lu %ld",
                   &pinfo->state, &pinfo->ppid, 
                   &pinfo->utime, &pinfo->stime,
                   &pinfo->priority, &pinfo->nice,
                   &pinfo->start_time, &pinfo->vsize, &pinfo->rss);
        }
    }
    
    fclose(fp);
    
    /* Read the executable path */
    snprintf(path, sizeof(path), "/proc/%d/exe", pid);
    ssize_t len = readlink(path, pinfo->exe_path, sizeof(pinfo->exe_path) - 1);
    if (len != -1) {
        pinfo->exe_path[len] = '\0'; /* Null-terminate the string */
    }
    
    return 1;
}

/* Helper function to properly escape JSON strings */
void print_json_string(const char *str) {
    printf("\"");
    while (*str) {
        if (*str == '\"' || *str == '\\') {
            printf("\\%c", *str);
        } else if (*str == '\b') {
            printf("\\b");
        } else if (*str == '\f') {
            printf("\\f");
        } else if (*str == '\n') {
            printf("\\n");
        } else if (*str == '\r') {
            printf("\\r");
        } else if (*str == '\t') {
            printf("\\t");
        } else {
            printf("%c", *str);
        }
        str++;
    }
    printf("\"");
}

/* Print process information as JSON */
void print_json_output(ProcessInfo *processes, int count) {
    int i;
    
    printf("{\n");
    printf("  \"processes\": [\n");
    
    for (i = 0; i < count; i++) {
        ProcessInfo *p = &processes[i];
        
        printf("    {\n");
        printf("      \"pid\": %d,\n", p->pid);
        printf("      \"comm\": ");
        print_json_string(p->comm);
        printf(",\n");
        printf("      \"state\": \"%c\",\n", p->state);
        printf("      \"ppid\": %d,\n", p->ppid);
        printf("      \"priority\": %ld,\n", p->priority);
        printf("      \"nice\": %ld,\n", p->nice);
        printf("      \"utime\": %lu,\n", p->utime);
        printf("      \"stime\": %lu,\n", p->stime);
        printf("      \"start_time\": %lu,\n", p->start_time);
        printf("      \"vsize\": %lu,\n", p->vsize);
        printf("      \"rss\": %ld,\n", p->rss);
        printf("      \"exe_path\": ");
        print_json_string(p->exe_path);
        printf("\n");
        
        if (i == count - 1) {
            printf("    }\n");
        } else {
            printf("    },\n");
        }
    }
    
    printf("  ]\n");
    printf("}\n");
}
