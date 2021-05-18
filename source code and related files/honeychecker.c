/* Name : Chandrawanshi Mangesh Shivaji
Roll No. : 1801cs16
SSD CS392 Assignment 2 
FileName : honeychecker.c */

// Note : honeychecker should be running before any login attempt	

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
#define MAX 2048

// driver code
int main(int argc, char const * argv[]) {
    
    printf("\n\tVerification:\n\n");

    // First, establish a connection with main server 
    // receive (UserName, match_index) pair from it
    // respond accordingly

    char * ip = "127.0.0.1";
    int port = 8080;
    int e;

    int sockfd, new_sock;
    struct sockaddr_in server_addr, new_addr;
    socklen_t addr_size;
    char buffer[MAX];

    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0) {
        perror("[-]Error in socket");
        exit(1);
    }
    printf("[+]Server socket created successfully.\n");

    server_addr.sin_family = AF_INET;
    server_addr.sin_port = port;
    server_addr.sin_addr.s_addr = inet_addr(ip);

    e = bind(sockfd, (struct sockaddr * ) & server_addr, sizeof(server_addr));
    if (e < 0) {
        perror("[-]Error in bind");
        exit(1);
    }
    printf("[+]Binding successfull.\n");

    if (listen(sockfd, 10) == 0) {
        printf("[+]Listening....\n");
    } else {
        perror("[-]Error in listening");
        exit(1);
    }

    addr_size = sizeof(new_addr);
    new_sock = accept(sockfd, (struct sockaddr * ) & new_addr, & addr_size);

    printf("Waiting for matching index along with username from main server...\n");

    int n = recv(new_sock, buffer, sizeof(buffer), 0);

    if (n <= 0) {
        printf("Error in receiving data!\n");
    }

    // Extract UserName and match_index from server message
    char UserName[21];
    int match_index;

    int i, itr;
    for (i = 0, itr = 0;; i++, itr++) {
        if (buffer[i] == ' ')
            break;
        UserName[itr] = buffer[i];
    }
    UserName[itr] = '\0';

    char num[10];
    i++;
    for (itr = 0;; i++, itr++) {
        if (buffer[i] == ' ' || buffer[i] == '\n')
            break;
        num[itr] = buffer[i];
    }
    num[itr] = '\0';
    match_index = atoi(num);

    // F3.txt stores (UserName, Sugarindex) pairs
    FILE * fp3 = fopen("F3.txt", "r");

    // Check if match_index corresponds to Sugarindex or not for any of the accounts
    int loginSuccess = 0;
    while (fgets(buffer, MAX, fp3)) {
        char FileUserName[21];
        int i;
        for (i = 0;; i++) {
            if (buffer[i] == ' ')
                break;
            FileUserName[i] = buffer[i];
        }
        FileUserName[i] = '\0';

        if (strncmp(FileUserName, UserName, 21) == 0) {

            i++;
            char Filenum[10];
            for (itr = 0;; i++, itr++) {
                if (buffer[i] == ' ')
                    break;
                Filenum[itr] = buffer[i];
            }
            Filenum[itr] = '\0';

            if (match_index == atoi(Filenum)) {
                loginSuccess = 1;
                break;
            }
        }

    }

    // close open files to avoid memory leak
    fclose(fp3);

    // Sent appropriate response to main server 
    bzero(buffer, MAX);
    if (loginSuccess == 1) {
        sprintf(buffer, "%s", "login successful");
    } else {
        sprintf(buffer, "%s", "Honeyword Use Detected,  System Security Policy Implement!ed");
    }
    if (send(new_sock, buffer, sizeof(buffer), 0) == -1) {
        perror("[-]Error in sending data.");
        exit(1);
    }
    printf("Check Complete!, Results sent to main server.\n\n");
    close(new_sock);

    return 0;
}