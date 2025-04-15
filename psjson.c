#include <stdio.h>
#include <stdlib.h>
#include <stddef.h>  /* Added for size_t */
#include <string.h>
#include <dirent.h>
#include <ctype.h>
#include <unistd.h>  /* For readlink() */
#include <netinet/in.h>  /* For network structures */
#include <arpa/inet.h>   /* For network functions */

/* Port information structure */
typedef struct {
    int port;
    char protocol[8];  /* "tcp", "tcp6", "udp", "udp6" */
    char local_addr[INET6_ADDRSTRLEN];
    char remote_addr[INET6_ADDRSTRLEN];
    char state[32];
} PortInfo;

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
    
    /* Port information */
    PortInfo *ports;          /* Array of ports used by the process */
    int port_count;           /* Number of ports used */
    int max_ports;            /* Allocated size of ports array */
    
    /* Child processes */
    int *children;            /* Array of child PIDs */
    int child_count;          /* Number of children */
    int max_children;         /* Allocated size of children array */
} ProcessInfo;

/* Function prototypes */
int is_pid_dir(const char *name);
int read_process_info(int pid, ProcessInfo *pinfo);
void print_json_output(ProcessInfo *processes, int count);
void print_json_string(const char *str);
void init_process_ports(ProcessInfo *pinfo);
void init_process_children(ProcessInfo *pinfo);
void free_process_resources(ProcessInfo *pinfo);
void read_process_ports(ProcessInfo *pinfo);
void collect_child_processes(ProcessInfo *processes, int count);
void add_port_to_process(ProcessInfo *pinfo, int port, const char *protocol,
                        const char *local_addr, const char *remote_addr, const char *state);
void add_child_to_process(ProcessInfo *pinfo, int child_pid);

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
    
    /* Collect child process information */
    collect_child_processes(processes, count);
    
    /* Output the process information as JSON */
    print_json_output(processes, count);
    
    /* Free allocated memory */
    for (int i = 0; i < count; i++) {
        free_process_resources(&processes[i]);
    }
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

/* Initialize port arrays in ProcessInfo */
void init_process_ports(ProcessInfo *pinfo) {
    pinfo->port_count = 0;
    pinfo->max_ports = 10;  /* Initial allocation */
    pinfo->ports = (PortInfo *)malloc(pinfo->max_ports * sizeof(PortInfo));
    if (pinfo->ports == NULL) {
        pinfo->max_ports = 0;
        perror("Failed to allocate memory for ports");
    }
}

/* Initialize children array in ProcessInfo */
void init_process_children(ProcessInfo *pinfo) {
    pinfo->child_count = 0;
    pinfo->max_children = 10;  /* Initial allocation */
    pinfo->children = (int *)malloc(pinfo->max_children * sizeof(int));
    if (pinfo->children == NULL) {
        pinfo->max_children = 0;
        perror("Failed to allocate memory for children");
    }
}

/* Free resources allocated for a process */
void free_process_resources(ProcessInfo *pinfo) {
    if (pinfo->ports) {
        free(pinfo->ports);
        pinfo->ports = NULL;
    }
    if (pinfo->children) {
        free(pinfo->children);
        pinfo->children = NULL;
    }
}

/* Add a port to the process's ports list */
void add_port_to_process(ProcessInfo *pinfo, int port, const char *protocol, 
                        const char *local_addr, const char *remote_addr, const char *state) {
    /* If we need more space, reallocate */
    if (pinfo->port_count >= pinfo->max_ports) {
        pinfo->max_ports *= 2;
        PortInfo *new_ports = (PortInfo *)realloc(pinfo->ports, 
                                               pinfo->max_ports * sizeof(PortInfo));
        if (new_ports == NULL) {
            perror("Failed to reallocate memory for ports");
            return;
        }
        pinfo->ports = new_ports;
    }
    
    /* Add the port information */
    PortInfo *port_info = &pinfo->ports[pinfo->port_count];
    port_info->port = port;
    strncpy(port_info->protocol, protocol, sizeof(port_info->protocol) - 1);
    port_info->protocol[sizeof(port_info->protocol) - 1] = '\0';
    
    strncpy(port_info->local_addr, local_addr, sizeof(port_info->local_addr) - 1);
    port_info->local_addr[sizeof(port_info->local_addr) - 1] = '\0';
    
    strncpy(port_info->remote_addr, remote_addr, sizeof(port_info->remote_addr) - 1);
    port_info->remote_addr[sizeof(port_info->remote_addr) - 1] = '\0';
    
    strncpy(port_info->state, state, sizeof(port_info->state) - 1);
    port_info->state[sizeof(port_info->state) - 1] = '\0';
    
    pinfo->port_count++;
}

/* Add a child PID to the process's children list */
void add_child_to_process(ProcessInfo *pinfo, int child_pid) {
    /* If we need more space, reallocate */
    if (pinfo->child_count >= pinfo->max_children) {
        pinfo->max_children *= 2;
        int *new_children = (int *)realloc(pinfo->children, 
                                        pinfo->max_children * sizeof(int));
        if (new_children == NULL) {
            perror("Failed to reallocate memory for children");
            return;
        }
        pinfo->children = new_children;
    }
    
    /* Add the child PID */
    pinfo->children[pinfo->child_count++] = child_pid;
}

/* Read port information from /proc/net/tcp and related files */
void read_process_ports(ProcessInfo *pinfo) {
    /* Files to check for network connections */
    const char *net_files[] = {
        "/proc/net/tcp",
        "/proc/net/tcp6",
        "/proc/net/udp",
        "/proc/net/udp6"
    };
    const char *protocols[] = {"tcp", "tcp6", "udp", "udp6"};
    const int num_files = sizeof(net_files) / sizeof(net_files[0]);
    
    /* We'll need to correlate socket inodes with the process's file descriptors */
    char path[256];
    char fd_path[1024];
    char target[1024];
    DIR *fd_dir;
    struct dirent *fd_entry;
    int i;
    
    /* Check each network file */
    for (i = 0; i < num_files; i++) {
        FILE *fp = fopen(net_files[i], "r");
        if (!fp) continue;
        
        char line[1024];
        /* Skip header line */
        if (fgets(line, sizeof(line), fp) == NULL) {
            fclose(fp);
            continue;
        }
        
        /* Read each connection line */
        while (fgets(line, sizeof(line), fp) != NULL) {
            unsigned int local_port;
            unsigned long inode;
            char local_addr_hex[128], remote_addr_hex[128], state_str[32];
            
            /* Parse the line - format varies slightly between files */
            /* Format: sl local_address rem_address st ... inode */
            int fields = sscanf(line, "%*d: %64[0-9A-Fa-f]:%x %64[0-9A-Fa-f]:%*x %s %*x %*x:%*x %*x:%*x %*x %*d %*d %lu",
                          local_addr_hex, &local_port, remote_addr_hex, state_str, &inode);
            
            if (fields < 5) continue;
            
            /* Map TCP state numbers to names - simplified */
            const char *tcp_states[] = {
                "UNKNOWN", "ESTABLISHED", "SYN_SENT", "SYN_RECV", "FIN_WAIT1", 
                "FIN_WAIT2", "TIME_WAIT", "CLOSE", "CLOSE_WAIT", "LAST_ACK", 
                "LISTEN", "CLOSING"
            };
            int state_num = strtol(state_str, NULL, 16);
            const char *state = (state_num >= 0 && state_num < 12) ? 
                              tcp_states[state_num] : "UNKNOWN";
            
            /* Now check if this socket belongs to our process */
            snprintf(path, sizeof(path), "/proc/%d/fd", pinfo->pid);
            fd_dir = opendir(path);
            if (!fd_dir) continue;
            
            /* Check each file descriptor */
            while ((fd_entry = readdir(fd_dir)) != NULL) {
                if (!isdigit(fd_entry->d_name[0])) continue;
                
                snprintf(fd_path, sizeof(fd_path), "/proc/%d/fd/%s", 
                       pinfo->pid, fd_entry->d_name);
                
                ssize_t len = readlink(fd_path, target, sizeof(target) - 1);
                if (len == -1) continue;
                target[len] = '\0';
                
                /* Check if this fd points to the socket we're looking at */
                /* Socket links look like "socket:[12345]" where 12345 is the inode */
                char inode_str[32];
                snprintf(inode_str, sizeof(inode_str), "socket:[%lu]", inode);
                
                if (strcmp(target, inode_str) == 0) {
                    /* This socket belongs to our process! */
                    /* Convert hex addresses to readable format */
                    char local_addr[INET6_ADDRSTRLEN] = {0};
                    char remote_addr[INET6_ADDRSTRLEN] = {0};
                    
                    /* Simplified conversion - would need more work for proper IPv6 */
                    if (strncmp(protocols[i], "tcp6", 4) == 0 || 
                        strncmp(protocols[i], "udp6", 4) == 0) {
                        /* IPv6 format */
                        strcpy(local_addr, "IPv6");  /* Simplified */
                        strcpy(remote_addr, "IPv6");
                    } else {
                        /* IPv4 format - convert from hex */
                        struct in_addr addr;
                        addr.s_addr = strtoul(local_addr_hex, NULL, 16);
                        inet_ntop(AF_INET, &addr, local_addr, sizeof(local_addr));
                        
                        addr.s_addr = strtoul(remote_addr_hex, NULL, 16);
                        inet_ntop(AF_INET, &addr, remote_addr, sizeof(remote_addr));
                    }
                    
                    add_port_to_process(pinfo, local_port, protocols[i], 
                                      local_addr, remote_addr, state);
                    break;
                }
            }
            closedir(fd_dir);
        }
        fclose(fp);
    }
}

/* Build relationships between processes and identify children */
void collect_child_processes(ProcessInfo *processes, int count) {
    int i, j;
    
    /* Loop through all processes to build the parent-child relationships */
    for (i = 0; i < count; i++) {
        for (j = 0; j < count; j++) {
            /* If process j's parent is process i, add j to i's children */
            if (i != j && processes[j].ppid == processes[i].pid) {
                add_child_to_process(&processes[i], processes[j].pid);
            }
        }
    }
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
    
    /* Initialize the new arrays */
    init_process_ports(pinfo);
    init_process_children(pinfo);
    
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
    
    /* Read port information */
    read_process_ports(pinfo);
    
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
        printf(",\n");
        
        /* Print ports information */
        printf("      \"ports\": [\n");
        for (int j = 0; j < p->port_count; j++) {
            PortInfo *port = &p->ports[j];
            printf("        {\n");
            printf("          \"port\": %d,\n", port->port);
            printf("          \"protocol\": \"%s\",\n", port->protocol);
            printf("          \"local_addr\": \"%s\",\n", port->local_addr);
            printf("          \"remote_addr\": \"%s\",\n", port->remote_addr);
            printf("          \"state\": \"%s\"\n", port->state);
            if (j == p->port_count - 1) {
                printf("        }\n");
            } else {
                printf("        },\n");
            }
        }
        printf("      ],\n");
        
        /* Print children PIDs information */
        printf("      \"children\": [");
        for (int j = 0; j < p->child_count; j++) {
            printf("%d", p->children[j]);
            if (j < p->child_count - 1) {
                printf(", ");
            }
        }
        printf("]\n");
        
        if (i == count - 1) {
            printf("    }\n");
        } else {
            printf("    },\n");
        }
    }
    
    printf("  ]\n");
    printf("}\n");
}