#include <stdio.h>
#include <stdlib.h>
#include <math.h>
#include <cuda_runtime.h>
#include <openssl/md5.h>
#include "d_cracker.h"
#include "CHECK.h"
#include "config.h"
#include "wrappers.h"

//prototype for the kernel
__global__ void d_crack_kernel(unsigned char * hash, int hashLen,
                                int length, unsigned char * d_result,
                                int d_result_size);

__device__ int d_powerOf(int val, int size);

//constant array containing all the possible characters in the password
__constant__ char VALID_CHARS[NUMCHARS];

/*malloccmp
* a compare like function that compares two strings of length.  It simply
* compares the elements at each location.
*
* @params:
*   str1   - an unsigned char pointer to the first character in string 1
*   str2   - an unsigned char pointer to the first character in string 2
*   length - the length of str1 and str2, the number of items compared.
*/
int malloccmp(unsigned char * str1, unsigned char * str2, int length) {
  for (int i = 0; i < length; i++) {
    if (str1[i] != str2[i]) {
      return 0;
    }
  }
  return 1;
}

/*printHash
* prints len items starting from hash as hexadecimal.  Used to print hashes as
* hex.
*
* @params:
*   hash  - a pointer to the start of the hash to print
*   len   - the number of items to print from hash.
*/
void printHash(unsigned char * hash, int len) {
  for (int k = 0; k < len; k++) {
    printf("%x", hash[k]);
    if (k == len - 1) {
      printf("\n");
    }
  }
}

/*printPassword
* prints len characters of a string starting at pass.  Used to print the result
* password.
*
* @params:
*   pass  - an unsigned char pointer to the first element in the string to print
*   len   - the number of items to print.
*/
void printPassword(unsigned char * pass, int len) {
  for (int k = 0; k < len; k++) {
    printf("%s", (unsigned char *) &pass[k]);
    if (k == len - 1) {
      printf("\n");
    }
  }
}

/*d_crack
*
* Sets up and calls the kernal to brute-force a password hash.
*
* @params
*   hash    - the password hash to brute-force
*   hashLen - the length of the hash
*   outpass - the result password to return
*/
float d_crack(unsigned char * hash, int hashLen, unsigned char * outpass) {

    cudaEvent_t start_cpu, stop_cpu;
    float cpuMsecTime = -1;

    //Use cuda functions to do the timing
    //create event objects
    CHECK(cudaEventCreate(&start_cpu));
    CHECK(cudaEventCreate(&stop_cpu));
    //record the starting time
    CHECK(cudaEventRecord(start_cpu));

    int passLength = 3;
    int size = hashLen * sizeof(char);
    int outsize = MAX_PASSWORD_LENGTH * sizeof(char);
    int passoutsize = pow(NUMCHARS, passLength) * (passLength + 1);

    unsigned char * d_hash;
    CHECK(cudaMalloc((void**)&d_hash, size));
    unsigned char * d_passwords;
    CHECK(cudaMalloc((void**)&d_passwords, passoutsize));
    unsigned char * d_result;
    CHECK(cudaMalloc((void**)&d_result, outsize));

    //build the const array of all lowercase characters
    char VALID_CHARS_CPU[NUMCHARS];
    for (int i = 0; i < NUMCHARS; i++) {
      VALID_CHARS_CPU[i] = (char)(i + 97);
    }
    CHECK(cudaMemcpyToSymbol(VALID_CHARS, VALID_CHARS_CPU, NUMCHARS * sizeof(char)));

    CHECK(cudaMemcpy(d_hash, hash, size, cudaMemcpyHostToDevice));

    dim3 block(NUMCHARS, 1, 1);
    dim3 grid(ceil(pow(NUMCHARS, passLength)/(float)(NUMCHARS)), 1);

    d_crack_kernel<<<grid, block>>>(d_hash, hashLen, passLength, d_passwords, passoutsize);

    CHECK(cudaDeviceSynchronize());

    unsigned char * passwords = (unsigned char *) Malloc(passoutsize);
    CHECK(cudaMemcpy(passwords, d_passwords, passoutsize, cudaMemcpyDeviceToHost));
    unsigned char * hashes = (unsigned char *) Malloc(pow(NUMCHARS, passLength) * hashLen);

    int j = 0;
    for (int i = 0; i < passoutsize; i+=(passLength + 1)) { //+ 1 corrects for null pointer
      //if (i < 17000)
    //    printf("i: %d, s: %s\n", i, (unsigned char *) &passwords[i]); // print out generated passwords for debugging
      // printf("%lu", (unsigned long) passLength);
      MD5_CTX md5;
      MD5_Init(&md5);
      MD5_Update(&md5, &(passwords[i]), (unsigned long) passLength);
      MD5_Final(&hashes[j], &md5);
      if (malloccmp(&passwords[i], (unsigned char *) "pas", passLength)) {
        printHash(&hashes[j], hashLen);
      }
      j += hashLen;
    }

    //NOTE: Hashes are forming correctly and we are getting the correct hash for input = 2

    unsigned char * ourHash = (unsigned char *) Malloc(hashLen);
    int numHashes = pow(NUMCHARS, passLength) * hashLen;
    int z = 0;
    for (int i = 0; i < numHashes; i+=hashLen) {
      // printHash(hash, hashLen);
      for (int j = 0; j < hashLen; j++) {
        ourHash[j] = hashes[i + j];
      }
      // printHash(&hashes[i], hashLen);
      // printf("%d\n", malloccmp(ourHash, hash, hashLen));
      if (malloccmp(ourHash, hash, hashLen)) {
        //TODO: Break here, we found the password
        printf("Password: ");
        printPassword(&passwords[z], 1);
      }
      for (int k = 0; k < hashLen; k++) {
        ourHash[k] = '\0';
      }
      z +=(passLength + 1);
    }
    // for (int i = 0; i < pow(NUMCHARS, passLength) * hashLen; i++) {
    //   ourHash[i % hashLen] = hashes[i];
    //   if (((i % hashLen) == 0) && malloccmp(ourHash, hashes, hashLen)) {
    //     printf("Hello");
    //     for (int j = 0; j < hashLen; j++) {
    //       printf("%x", ourHash[j]);
    //       if (j == hashLen - 1) {
    //         printf("\n");
    //       }
    //     }
    //     for (int k = 0; k < hashLen; k++) {
    //       ourHash[k] = '\0';
    //     }
    //   }
    // }

    CHECK(cudaMemcpy(outpass, d_result, outsize, cudaMemcpyDeviceToHost));

    CHECK(cudaFree(d_hash));
    CHECK(cudaFree(d_result));
    free(ourHash);
    free(passwords);
    free(hashes);

    //record the ending time and wait for event to complete
    CHECK(cudaEventRecord(stop_cpu));
    CHECK(cudaEventSynchronize(stop_cpu));
    //calculate the elapsed time between the two events
    CHECK(cudaEventElapsedTime(&cpuMsecTime, start_cpu, stop_cpu));
    return cpuMsecTime;
}

/*d_crack_kernel
*  Kernel code executed by each thread on its own data when the kernel is
*  launched. Constant memory is used for the set of all possible characters,
*  in this case, lowercase.
*  Threads cooperate to help build a possible password built from the Constant
*  character array.
*  @params:
*   hash     - array filled with characters to crack.
*   hashLen  - length of the given hash
*   length   - the length of the passwords to generate
*   d_result - array of possible passwords.
*/

__global__ void d_crack_kernel(unsigned char * hash, int hashLen, int length,
                                unsigned char * d_result, int d_result_size) {
  // printf("blockIdx: %d, blockDim: %d, threadIdx: %d, blockDim mod length: %d\n", blockIdx.x, blockDim.x, threadIdx.x, blockDim.x % length);

  int index = (blockIdx.x * blockDim.x + threadIdx.x) * (length + 1);
  int t = blockIdx.x * blockDim.x + threadIdx.x;
  int inner_index = gridDim.x;
//  if (index == 0 || index == 26 ||index == 52) {
//    printf("inner index: %d\n", inner_index);
//  }

  int powerSize = 0;
  for (int i = (length - 1); i >= 0; i--) {
    if ( i <= (length - 1) - 2) {
  //      printf("power of: %d", d_powerOf(NUMCHARS, powerSize));
        d_result[index] = VALID_CHARS[blockIdx.x / d_powerOf(NUMCHARS, powerSize)];
        powerSize++;
    } else if ( i == (length - 1) - 1) {
        d_result[index + i] = VALID_CHARS[blockIdx.x % NUMCHARS];
    } else {
    	d_result[index + i] = VALID_CHARS[threadIdx.x];
    }

  //  d_result[index + i] = VALID_CHARS[((blockIdx.x * (length - 1)) + (t % NUMCHARS)) % NUMCHARS];
  //  inner_index /= NUMCHARS;
  }

  // 4 characters
  //d_result[index]                = VALID_CHARS[blockIdx.x / (NUMCHARS * NUMCHARS)];
//  d_result[index]            = VALID_CHARS[blockIdx.x / NUMCHARS];
//  d_result[index + 1]            = VALID_CHARS[blockIdx.x % NUMCHARS];
//  d_result[index + (length - 1)] = VALID_CHARS[threadIdx.x];
  d_result[index + (length)] = '\0';
}

__device__ int d_powerOf(int val, int size) {
  for (int i = 0; i < size; i++) {
    val *= val;
  }


  return val;
}
