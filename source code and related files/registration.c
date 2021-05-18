/* Name : Chandrawanshi Mangesh Shivaji
Roll No. : 1801cs16
SSD CS392 Assignment 2 
FileName : registration.c */

#include <stdlib.h>
#include <stdio.h>
#include <time.h>
#include <string.h>
#include <ctype.h>

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

// To avoid repetitions of username and correct indices
int used_idx[N] = {0};

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

// Using F2.txt initialize all used indices
void initialize_used_indices(FILE * fp) {
    char buffer[MAX];
    while (fgets(buffer, MAX, fp)) {
        char num[10];
        int i;
        for (i = 0;; i++) {
            if (buffer[i] == ' ')
                break;
            num[i] = buffer[i];
        }
        num[i] = '\0';
        used_idx[atoi(num)] = 1;
    }
}

// Check if entered username is already used or not
int check_duplicate(char * UserName) {
    FILE * fp3 = fopen("F3.txt", "r");

    char buffer[MAX];
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
            return 1;
        }
    }
    return 0;
}

// driver code
int main(int argc, char const * argv[]) {

	// Get Details from User
    printf("\n\tNew User Registration:\n\n");
    char UserName[21];
    char password[15];
    printf("Enter username (Max 21 characters) : ");
    scanf("%s", UserName);

    while (check_duplicate(UserName) != 0) {
        printf("username already exists, provide another!\n");
        printf("Enter username (Max 21 characters) : ");
        scanf("%s", UserName);
    }

    printf("Enter password (Min length : 8, Max Length : 12) : ");
    scanf("%s", password);

    // F1 and F2 same as paper
    FILE * fp1 = fopen("F1.txt", "a+");
    FILE * fp2 = fopen("F2.txt", "a+");

    // F3 is for honeychecker
    FILE * fp3 = fopen("F3.txt", "a+");

    srand((long) time(NULL)); //Seed the random number generator...	

    initialize_used_indices(fp2);

    userDetails newUser;
    char write_to_file[MAX];

    // Get random unused index to set as Sugarindex
    int correct_index;
    do {
        correct_index = 5000 + (rand() % (N - 5000));
    }
    while (used_idx[correct_index]);
    used_idx[correct_index] = 1;

    char hash_password[105];
    computeMD5(password, hash_password);
    //printf("%s\n", hash_password);

    // Write new user entry to F2.txt (Sugarindex, Hash(password))
    memset(write_to_file, '\0', sizeof(write_to_file));
    sprintf(write_to_file, "%d", correct_index);
    strcat(write_to_file, " ");
    strcat(write_to_file, hash_password);
    strcat(write_to_file, "\n");
    fputs(write_to_file, fp2);

    // Write new user entry to F3.txt (UserName, Sugarindex)
    memset(write_to_file, '\0', sizeof(write_to_file));
    strcat(write_to_file, UserName);
    strcat(write_to_file, " ");
    char tmp[10];
    sprintf(tmp, "%d", correct_index);
    strcat(write_to_file, tmp);
    strcat(write_to_file, "\n");
    fputs(write_to_file, fp3);

    // store in struct variable
    strncpy(newUser.username, UserName, 21);
    for (int j = 0; j < k; j++) {
        newUser.honeyindexset[j] = -1;
    }
    newUser.honeyindexset[rand() % k] = correct_index;

    // get other honeyindices
    int honeyindex;
    for (int j = 0; j < k; j++) {

        if (newUser.honeyindexset[j] != -1)
            continue;

        do {
            honeyindex = rand() % N;
        }
        while (used_idx[honeyindex] != 1);

        if (newUser.honeyindexset[j] == -1)
            newUser.honeyindexset[j] = honeyindex;
    }

    // Write to F1.txt (UserName, honeyindexset)
    memset(write_to_file, '\0', sizeof(write_to_file));
    strcat(write_to_file, newUser.username);
    strcat(write_to_file, " ");

    for (int j = 0; j < k; j++) {
        char tmp[10];
        sprintf(tmp, "%d", newUser.honeyindexset[j]);
        strcat(write_to_file, tmp);
        strcat(write_to_file, " ");
    }

    strcat(write_to_file, "\n");
    fputs(write_to_file, fp1);

    // Close all files to avoid memory leak
    fclose(fp1);
    fclose(fp2);
    fclose(fp3);

    return 0;
}