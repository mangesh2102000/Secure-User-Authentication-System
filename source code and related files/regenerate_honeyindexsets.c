/* Name : Chandrawanshi Mangesh Shivaji
Roll No. : 1801cs16
SSD CS392 Assignment 2 
FileName : regenerate_honeyindexsets.c */

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

// Details of all users
userDetails AllUsers[N];

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

// driver code
int main(int argc, char const * argv[]) {

    // F1 and F2 same as paper
    FILE * fp1 = fopen("F1.txt", "w+");   // As we want to overwrite in this case
    FILE * fp2 = fopen("F2.txt", "a+");

    // F3 is for honeychecker
    FILE * fp3 = fopen("F3.txt", "a+");

    srand((long) time(NULL)); //Seed the random number generator...	

    initialize_used_indices(fp2);

    char write_to_file[MAX];

    int idx = 0;
    char buffer[MAX];

    // Get User details from F3.txt (UserName, Sugarindex) line by line
    while (fgets(buffer, MAX, fp3)) {
        
        char UserName[21], num[10];
        int i, itr;
        for (i = 0;; i++) {
            if (buffer[i] == ' ')
                break;
            UserName[i] = buffer[i];
        }
        UserName[i] = '\0';
        strncpy(AllUsers[idx].username, UserName, 21);

        for (int j = 0; j < k; j++) {
            AllUsers[idx].honeyindexset[j] = -1;
        }
        i++;
        for (itr = 0;; i++, itr++) {
            if (buffer[i] == ' ')
                break;
            num[itr] = buffer[i];
        }
        num[itr] = '\0';
        AllUsers[idx].honeyindexset[rand() % k] = atoi(num);

        // Reconfigure other honeyindices from used index set
        int honeyindex;
        for (int j = 0; j < k; j++) {

            if (AllUsers[idx].honeyindexset[j] != -1)
                continue;

            do {
                honeyindex = rand() % N;
            }
            while (used_idx[honeyindex] != 1);

            if (AllUsers[idx].honeyindexset[j] == -1)
                AllUsers[idx].honeyindexset[j] = honeyindex;
        }

        // Write modified entry to F1.txt (UserName, honeyindexset)
        memset(write_to_file, '\0', sizeof(write_to_file));
        strcat(write_to_file, AllUsers[idx].username);
        strcat(write_to_file, " ");

        for (int j = 0; j < k; j++) {
            char tmp[10];
            sprintf(tmp, "%d", AllUsers[idx].honeyindexset[j]);
            strcat(write_to_file, tmp);
            strcat(write_to_file, " ");
        }

        strcat(write_to_file, "\n");
        fputs(write_to_file, fp1);

        idx++;
    }

    // Close all open files to avoid memory leak
    fclose(fp1);
    fclose(fp2);
    fclose(fp3);

    return 0;
}