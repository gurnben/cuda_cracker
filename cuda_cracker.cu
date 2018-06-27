#include <stdlib.h>
#include <stdio.h>
#include <openssl/md5.h>
#include "wrappers.h"
#include "d_cracker.h"
#include "config.h"

void parseCommandArgs(int argc, char * argv[], unsigned char ** password,
                      unsigned long * length);
void printUsage();

/*main
*
* Processes command line arguments, and if successful it calls the d_crack
* function to launch our CUDA kernal and crack the password.  When successful,
* it will print out the time in miliseconds and the resulting password.
*
* @params:
*   argc - # of arguments in argv
*   argv - command-line arguments
*
*   @authors: Gurney Buchanan <@gurnben>, Eric Cambel <@cambelem>, and adapted
*              from code and teaching by Dr. Cindy Norris <@cindyanorris>
*/
int main(int argc, char * argv[]) {
    unsigned char * password, * outpass, * hash;
    unsigned long length;
    float gpuTime;

    parseCommandArgs(argc, argv, &password, &length);

    outpass = (unsigned char *) Malloc(MAX_PASSWORD_LENGTH);

    hash = (unsigned char *)Malloc(16);

    // char * x = (char *) Malloc(7000000000ull);
    //
    // for (int i = 0; i < 7000000000; i++) {
    //   x[i] = 'A';
    // }

    MD5_CTX md5;
    MD5_Init(&md5);
    MD5_Update(&md5, password, length);
    MD5_Final(hash, &md5);
    gpuTime = d_crack(hash, 16, outpass);

    // printf("%s", outpass);

    free(outpass);
    free(hash);
    return EXIT_SUCCESS;
}

/*parseCommandArgs
*
* This function processes the command line arguments given to the program.
*
* the proper use is:
*   ./cud_cracker <password>
*
* the password entered will be hashed and then our kernal will use the hash to
* brute-force the password
*
* @params:
*   argc      - the number of arguments in argv
*   argv      - the arguments to the utility
*   password  - a pointer to the password variable to put the password in.
*/
void parseCommandArgs(int argc, char * argv[], unsigned char ** password,
                      unsigned long * length) {
    int passIdx = argc - 1;
    //Password Entered must be 1 character or longer
    int len = strlen(argv[passIdx]);
    if (len < 1) printUsage();
    if (len > 100) printUsage();
    (*password) = (unsigned char *) argv[passIdx];
    (*length) = (unsigned long) len;

    //     Examples from Dr. Norris' code for other arguments
    // for (int i = 1; i < argc - 1; i++)
    // {
    //     //mask width
    //     if (strncmp("-m", argv[i], 3) == 0) {
    //         mskW = atoi(argv[i+1]);
    //         if (mskW <= 0 || mskW > MAX_MASK_WIDTH) printUsage();
    //         if ((mskW % 2) != 1) printUsage();
    //         i++;
    //     }
    //     else if (strncmp("-s", argv[i], 3) == 0) {
    //         strd = atoi(argv[i+1]);
    //         if (strd != 1 && strd != 32 && strd != 64 && strd != 128) printUsage();
    //         i++;
    //     //save output files
    //     }
    //     else if (strncmp("-save", argv[i], 6) == 0) {
    //         save = 1;
    //     }
    //     else
    //         printUsage();
    // }
}

/*printUsage
*
* Prints the usage information for this application.
*/
void printUsage()
{
    printf("This application takes as input a password to 'crack'.\n");
    printf("\nusage: cuda_cracker <password>\n");
    printf("           <password> will be hashed, and the kernal will find the password from the hash");
    printf("           <password> must be between 1 and 100 characters");
    printf("Examples:\n");
    printf("./cuda_cracker password123\n");
    exit(EXIT_FAILURE);
}
