/* Name : Chandrawanshi Mangesh Shivaji
Roll No. : 1801cs16
SSD CS392 Assignment 2 
FileName : initiliaze.c */

#include <stdlib.h>
#include <stdio.h>
#include <time.h>
#include <string.h>
#include <ctype.h>

#define T 1000		// Number of honeypot accounts
#define N 1000000	// Max number of total accounts
#define k 6			// Size of honeyindexset (Can be altered from here, but ensure to update in all source code files)
#define MAX 1024	

// To avoid repetitions of username and correct indices
int vis[7][25][20];
int used_idx[N] = {0};

char alphabet[26] = {
    'a','b','c','d','e','f','g','h','i',
    'j','k','l','m','n','o','p','q', 'r',
    's','t','u','v','w','x','y','z'
};

char digit[10] = {
    '0','1','2','3','4','5','6','7','8','9'
};

// Used to generate usernames for honeypot accounts
char NamePrefix[][5] = {
    "you","xani","bell","nato","eva","man","sam"
};

char NameSuffix[][5] = {
    "","us","ix","ox","ith","ath","y","123",
    "axia","imus","ais","itur","orex","o",
    "456","789","007","um","ator","or"
};

const char NameStems[][10] = {
    "adur","aes","anim","apoll","imac",
 	"educ","equis","extr","guius","hann",
    "equi","amora","hum","iace","ille",
    "inept","iuv","obe","ocul","orbis",
    "_","-","1234","5678","1007"
};

// Function to generate username
void NameGen(char * UserName, int pf, int stm, int sf) {
    UserName[0] = 0;
    strcat(UserName, NamePrefix[pf]);
    strcat(UserName, NameStems[stm]);
    strcat(UserName, NameSuffix[sf]);
    return;
}

// Function to generate password, format : a chars, b digits, c charss
void PassGen(char * password, int a, int b, int c) {
    int i = 0;

    while (a--) {
        password[i++] = alphabet[rand() % 26];
    }
    while (b--) {
        password[i++] = digit[rand() % 10];
    }
    while (c--) {
        password[i++] = alphabet[rand() % 26];
    }

    password[i] = '\0';
    if (rand() % 2 && password[0] >= 'a' && password[0] <= 'z')
        password[0] = toupper(password[0]);

    return;
}

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

// Store details of a user
typedef struct userDetails {
    char username[21];
    int honeyindexset[k];
}
userDetails;

// driver code
int main(int argc, char const * argv[]) {
    // F1 and F2 same as paper
    FILE * fp1 = fopen("F1.txt", "w+");
    FILE * fp2 = fopen("F2.txt", "w+");

    // F3 is for honeychecker, stores pair (username, correct index)
    FILE * fp3 = fopen("F3.txt", "w+");

    memset(vis, 0, sizeof(vis));
    int idx = 0;
    srand((long) time(NULL)); //Seed the random number generator...	

    int pf = 0, stm = 0, sf = 0;
    // Range for pf 0-6, stm 0-24, sf 0-19
    int a = 0, b = 0, c = 0;

    // Declare array to store all honeypot accounts' details
    userDetails F1_entity[T];

    char write_to_file[MAX];

    // Write each honeypot user details to F2.txt and F3.txt
    for (int i = 0; i < T; i++) {

    	// Username
        do {
            pf = rand() % 7;
            stm = rand() % 25;
            sf = rand() % 20;
        } while (vis[pf][stm][sf] != 0);

        char UserName[21];
        NameGen(UserName, pf, stm, sf);
        vis[pf][stm][sf] = 1;
        //printf("%s - ", UserName);

        // Password
        int passwordLength = 8 + (rand() % 5);
        char password[15];

        do {
            a = rand() % passwordLength;
            b = rand() % passwordLength;
            c = rand() % passwordLength;
        } while (a + b + c != passwordLength);
        PassGen(password, a, b, c);
        //printf("%s - ", password);

        // Sugarindex
        int correct_index;
        do {
            correct_index = (rand() % 5000);
        }
        while (used_idx[correct_index]);

        used_idx[correct_index] = 1;

        char hash_password[105];
        computeMD5(password, hash_password);
        //printf("%s\n", hash_password);

        // Write entry (Sugarindex, Hash(Passoword) to F2.txt 
        memset(write_to_file, '\0', sizeof(write_to_file));
        sprintf(write_to_file, "%d", correct_index);
        strcat(write_to_file, " ");
        strcat(write_to_file, hash_password);
        strcat(write_to_file, "\n");
        fputs(write_to_file, fp2);

        // Write entry (UserName, Sugarindex) to F3.txt 
        memset(write_to_file, '\0', sizeof(write_to_file));
        strcat(write_to_file, UserName);
        strcat(write_to_file, " ");
        char tmp[10];
        sprintf(tmp, "%d", correct_index);
        strcat(write_to_file, tmp);
        strcat(write_to_file, "\n");
        fputs(write_to_file, fp3);

        // Store user  details in struct array
        strncpy(F1_entity[i].username, UserName, 21);
        for (int j = 0; j < k; j++) {
            F1_entity[i].honeyindexset[j] = -1;
        }
        F1_entity[i].honeyindexset[rand() % k] = correct_index;
    }

    // Write F1.txt 
    for (int i = 0; i < T; i++) {

        int honeyindex;
        for (int j = 0; j < k; j++) {
            do {
                honeyindex = rand() % 5000;
            }
            while (used_idx[honeyindex] != 1);

            if (F1_entity[i].honeyindexset[j] == -1)
                F1_entity[i].honeyindexset[j] = honeyindex;
        }

        // Each entry (Username, honeyindexset)
        memset(write_to_file, '\0', sizeof(write_to_file));
        strcat(write_to_file, F1_entity[i].username);
        strcat(write_to_file, " ");

        for (int j = 0; j < k; j++) {
            char tmp[10];
            sprintf(tmp, "%d", F1_entity[i].honeyindexset[j]);
            strcat(write_to_file, tmp);
            strcat(write_to_file, " ");
        }

        strcat(write_to_file, "\n");
        fputs(write_to_file, fp1);
    }

    // Close all open files to avoid memory leak
    fclose(fp1);
    fclose(fp2);
    fclose(fp3);

    return 0;
}