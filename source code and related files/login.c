/* Name : Chandrawanshi Mangesh Shivaji
Roll No. : 1801cs16
SSD CS392 Assignment 2 
FileName : login.c */

#include <stdlib.h>
#include <stdio.h>
#include <time.h>
#include <string.h>
#include <ctype.h>
#include <arpa/inet.h>
#include <unistd.h>

#define T 1000		// Number of honeypot accounts
#define N 1000000	// Max number of total accounts
#define k 6			// Size of honeyindexset (Can be altered from here, but ensure to update in all source code files)
#define MAX 1024

// Store details of a user
typedef struct userDetails {
    char username[21];
    int honeyindexset[k];
}
userDetails;

// Function to calculate md5 hash of input string
void computeMD5(char * str, char * md5) {
    char cmd[105] = {0};

    strcpy(cmd, "echo -n \"");
    strcat(cmd, str);
    strcat(cmd, "\" | md5sum");

    FILE * fp = popen(cmd, "r");
    fscanf(fp, "%s", md5);
    pclose(fp);
}

// Get hash value corresponding to passed sweetindex value
void get_hash_for_sweetindex(char * hash_at_sweetindex, int sweetindex) {

    FILE * fp2 = fopen("F2.txt", "r");
    char buffer[MAX];
    while (fgets(buffer, MAX, fp2)) {

        int i = 0, itr;
        char num[10];
        for (itr = 0;; i++, itr++) {
            if (buffer[i] == ' ')
                break;
            num[itr] = buffer[i];
        }
        num[itr] = '\0';

        hash_at_sweetindex[0] = 0;
        if (sweetindex == atoi(num)) {
            i++;
            for (itr = 0;; i++, itr++) {
                if (buffer[i] == ' ' || buffer[i] == '\n')
                    break;
                hash_at_sweetindex[itr] = buffer[i];
            }
            hash_at_sweetindex[itr] = '\0';
            return;
        }
    }
    fclose(fp2);
}

// driver code
int main(int argc, char const * argv[]) {

    // Get login details from user as input
    printf("\n\tLogin:\n\n");

    char UserName[21], password[15];
    printf("Enter username (Max 21 characters) : ");
    scanf("%s", UserName);
    printf("Enter password (Min length : 8, Max Length : 12) : ");
    scanf("%s", password);

    // F1 and F2 same as paper
    FILE * fp1 = fopen("F1.txt", "r");

    // to store matched index with entered password, if any
    int match_index = -1;

    // FLAGS
    int flag = 0, loginfailed = 0, honeypot = 0;
    char buffer[MAX];
    
    // Match the UserName from F1.txt and get corressponding honeyindexset
    while (fgets(buffer, MAX, fp1)) {
        char FileUserName[21];
        int i;
        for (i = 0;; i++) {
            if (buffer[i] == ' ')
                break;
            FileUserName[i] = buffer[i];
        }
        FileUserName[i] = '\0';

        if (strncmp(FileUserName, UserName, 21) == 0) {

            flag = 1;
            userDetails currentUser;
            strncpy(currentUser.username, UserName, 21);

            int itr;
            for (int j = 0; j < k; j++) {
                i++;
                char num[10];
                for (itr = 0;; i++, itr++) {
                    if (buffer[i] == ' ')
                        break;
                    num[itr] = buffer[i];
                }
                num[itr] = '\0';
                currentUser.honeyindexset[j] = atoi(num);
            }

            char hash_password[105];
            computeMD5(password, hash_password);

            // Check if any entry in honeyindexset corressponds to entered password
            for (int j = 0; j < k; j++) {

                char hash_at_sweetindex[105];
                get_hash_for_sweetindex(hash_at_sweetindex, currentUser.honeyindexset[j]);

                if (strcmp(hash_at_sweetindex, hash_password) == 0) {
                    match_index = currentUser.honeyindexset[j];
                    break;
                }
            }

            if (match_index == -1) {
                loginfailed = 1;
            } else if (match_index < 5000) {
                honeypot = 1;
            }
        }
    }

    // Output according to findings 
    if (honeypot == 1) {
        printf("Honeypot account accessed! System Security Policy Implemented!\n");
    } else if (loginfailed == 1) {
        printf("Login Failed!\n");
    } else if (flag == 0) {
        printf("NO SUCH USER EXITS! INVALID USERNAME\n");
    } else {

    	// to find Honeyword or Correct Password
        // First establish TCP connection between main server and honeychecker
        // Send match_index to honeychecker
        // honeychecker will respond accordingly
        // print the response

        char * ip = "127.0.0.1";
        int port = 8080;
        int e;

        int sockfd;
        struct sockaddr_in server_addr;

        sockfd = socket(AF_INET, SOCK_STREAM, 0);
        if (sockfd < 0) {
            perror("[-]Error in socket");
            exit(1);
        }
        printf("[+]Server socket created successfully.\n");

        server_addr.sin_family = AF_INET;
        server_addr.sin_port = port;
        server_addr.sin_addr.s_addr = inet_addr(ip);

        e = connect(sockfd, (struct sockaddr * ) & server_addr, sizeof(server_addr));
        if (e == -1) {
            perror("[-]Error in socket");
            exit(1);
        }
        printf("[+]Connected to Server.\n");

        // Send (Username, match_index) to honeychecker
        memset(buffer, '\0', sizeof(buffer));
        strcat(buffer, UserName);
        strcat(buffer, " ");
        char tmp[10];
        sprintf(tmp, "%d", match_index);
        strcat(buffer, tmp);
        strcat(buffer, "\n");

        if (send(sockfd, buffer, sizeof(buffer), 0) == -1) {
            perror("[-]Error in sending data.");
            exit(1);
        }
        bzero(buffer, MAX);

        // Receive Response from honeychecker
        int n = recv(sockfd, buffer, sizeof(buffer), 0);

        if (n <= 0) {
            printf("Error in receiving data!\n");
        }

        printf("%s\n", buffer);

        printf("[+]Closing the connection.\n\n");
        close(sockfd);
    }

    // Close open files to avoid memory leak
    fclose(fp1);

    return 0;
}