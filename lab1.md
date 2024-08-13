# Lab 1 
Command Injection and TOCTOU resilient program

## Command Injection Vulnerability
'''c
#include <stdio.h>
#include <stdlib.h>

int main() {
    char filename[100];
    printf("Enter a filename: ");
    scanf("%s", filename);
    char command[200];
    sprintf(command, "cat %s", filename);
    printf("Executing command: %s\n", command);
    system(command);
    return 0;
}


When this program is executed, the sprintf function concatenates the user input into the command string and the system() function then executes this command in a shell. Since the filename includes ;date, the shell interprets this as two separate commands:

*cat /etc/hosts
*date

This causes the program to output the content of /etc/hosts and after displating that, executes the date command which displays current date.

### Code without vulnerability
Using the fopen() function.
'''c
#include <stdio.h>
#include <stdlib.h>

int main() {
    char filename[100];
    printf("Enter a filename: ");
    scanf("%99s", filename);

    FILE *file = fopen(filename, "r");
    if (!file) {
        perror("Error opening file");
        return 1;
    }

    char line[256];
    while (fgets(line, sizeof(line), file)) {
        printf("%s", line);
    }

    fclose(file);
    return 0;
}
'''

## TOCTOU Resilient Program
The TOCTOU Program:
'''c
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/stat.h>

// Function to check if the file is writable by the current user
int is_writable(const char *filename) {
    struct stat file_stat;

    if (stat(filename, &file_stat) == -1) {
        perror("Error in stat");
        return 0;
    }

    if (file_stat.st_uid == getuid()) {
        if (file_stat.st_mode & S_IWUSR)
            return 1;
    }

    return 0;
}

// Function to write a message to the file
void write_to_file(const char *filename, const char *message) {
    FILE *file = fopen(filename, "w");
    if (file == NULL) {
        perror("Error opening file");
        return;
    }

    fprintf(file, "%s\n", message);
    fclose(file);
}

int main(int argc, char *argv[]) {
    if (argc != 3) {
        fprintf(stderr, "Usage: %s <filename> <message>\n", argv[0]);
        return 1;
    }

    const char *filename = argv[1];
    const char *message = argv[2];

    // Check if the file is writable by the current user
    if (is_writable(filename)) {
        printf("User has permission to write to the file %s.\n", filename);
        sleep(40); // Simulate delay

        // Write message to the file
        write_to_file(filename, message);
        printf("Written given message to the file %s\n", filename);
    } else {
        printf("The user does not have permission to write to the file %s\n", filename);
    }

    return 0;
}
'''

The TOCTOU Resilient Program:
'''
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/stat.h>
#include <fcntl.h>

void write_to_file(int fd, const char *message) {
    FILE *file = fdopen(fd, "w");
    if (file == NULL) {
        perror("Error converting file descriptor to FILE pointer");
        close(fd);  
        return;
    }

    fprintf(file, "%s\n", message);
    fclose(file);
}

int main(int argc, char *argv[]) {
    if (argc != 3) {
        fprintf(stderr, "Usage: %s <filename> <message>\n", argv[0]);
        return 1;
    }

    const char *filename = argv[1];
    const char *message = argv[2];

    int fd = open(filename, O_WRONLY);
    if (fd == -1) {
        perror("Error opening file");
        return 1;
    }

    struct stat file_stat;
    if (fstat(fd, &file_stat) == -1) {
        perror("Error in fstat");
        close(fd);
        return 1;
    }

    if (file_stat.st_uid == getuid() && (file_stat.st_mode & S_IWUSR)) {
        printf("User has permission to write to the file %s.\n", filename);
        sleep(40); 

        write_to_file(fd, message);
        printf("Written given message to the file %s\n", filename);
    } else {
        printf("The user does not have permission to write to the file %s\n", filename);
        close(fd);
    }
    return 0;
}
'''