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

__global__ void d_generate_kernel(unsigned char * passwords, int length, unsigned long n,
                                    unsigned char * d_result);

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

int findPass(unsigned char * passwords, unsigned char * hash, unsigned long outsize, int passLength, int hashLen) {
  unsigned char * hashes = (unsigned char *) Malloc(pow(NUMCHARS, passLength) * hashLen);
  unsigned long j = 0;
  unsigned long x;
  for (x = 0; x < outsize; x+=(passLength + 1)) { //+ 1 corrects for null pointer
    //if (i < 17000)
      // printf("i: %d, s: %s\n", i, (unsigned char *) &passwords[i]); // print out generated passwords for debugging
    // printf("%lu", (unsigned long) passLength);
    MD5_CTX md5;
    MD5_Init(&md5);
    MD5_Update(&md5, &(passwords[x]), (unsigned long) passLength);
    MD5_Final(&hashes[j], &md5);
    j += hashLen;
  }

  printf("Last Iterated Password: %s\n", (char *) &passwords[x - (passLength + 1)]);

  unsigned char * ourHash = (unsigned char *) Malloc(hashLen);
  unsigned long numHashes = pow(NUMCHARS, passLength) * hashLen;
  unsigned long z = 0;
  for (unsigned long i = 0; i < numHashes; i+=hashLen) {
    // printHash(hash, hashLen);
    for (unsigned long j = 0; j < hashLen; j++) {
      ourHash[j] = hashes[i + j];
    }
    // printHash(&hashes[i], hashLen);
    // printf("%d\n", malloccmp(ourHash, hash, hashLen));
    if (malloccmp(ourHash, hash, hashLen)) {
      //TODO: Break here, we found the password
      printf("Password: ");
      printPassword(&passwords[z], 1);
      free(ourHash);
      free(hashes);
      return 1;
    }
    for (int k = 0; k < hashLen; k++) {
      ourHash[k] = '\0';
    }
    z +=(passLength + 1);
  }
  free(ourHash);
  free(hashes);
  return 0;
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

    unsigned long size = 2 * NUMCHARS * sizeof(unsigned char);
    unsigned long outsize = pow(NUMCHARS, 2) * 3;

    unsigned char * d_passwords;
    CHECK(cudaMalloc((void**)&d_passwords, size));
    unsigned char * d_result;
    CHECK(cudaMalloc((void**)&d_result, outsize));

    //build the const array of all lowercase characters
    char VALID_CHARS_CPU[NUMCHARS];
    for (int i = 0; i < NUMCHARS; i++) {
      VALID_CHARS_CPU[i] = (char)(i + 97);
    }

    /*****************************KERNAL FOR LENGTH 2**************************/
    char STARTING_PASSES[NUMCHARS * 2];
    for (int i = 0; i < NUMCHARS; i++) {
      STARTING_PASSES[i * 2] = VALID_CHARS_CPU[i];
      STARTING_PASSES[(i * 2) + 1] = '\0';
    }

    //Copy the starting passwords array and valid characters to the GPU
    CHECK(cudaMemcpyToSymbol(VALID_CHARS, VALID_CHARS_CPU, NUMCHARS * sizeof(char)));
    CHECK(cudaMemcpy(d_passwords, STARTING_PASSES, 2 * NUMCHARS, cudaMemcpyHostToDevice));

    dim3 block(BLOCKDIM, 1, 1);
    dim3 grid(1, 1, 1);

    d_generate_kernel<<<grid, block>>>(d_passwords, 1, NUMCHARS, d_result);

    CHECK(cudaDeviceSynchronize());

    unsigned char * passwords = (unsigned char *) Malloc(outsize);
    CHECK(cudaMemcpy(passwords, d_result, outsize, cudaMemcpyDeviceToHost));

    CHECK(cudaFree(d_passwords));
    CHECK(cudaFree(d_result));

    /**************passwords NOW HOLDS ALL LENGTH 2 PASSWORDS******************/

    for (int i = 3; i < MAX_PASSWORD_LENGTH; i++) {
      size = pow(NUMCHARS, (i - 1)) * i;
      outsize = pow(NUMCHARS, i) * (i + 1);

      printf("Size + Outsize: %lu\n", size + outsize);

      if ((size + outsize) >= GPUMEMORY) {
        printf("out of memory\n");
        for (unsigned long j = 0; j < size; j+=((unsigned long) ceil(GPUMEMORY * (size/(long double)outsize)))) {
          printf("j=%lu, passwords + j=%lu, j+=%lu\n", j, passwords + j, (unsigned long) ceil(GPUMEMORY * (size/(long double)outsize)));
          unsigned long itersize = GPUMEMORY * (size/outsize);
          unsigned long iteroutsize = GPUMEMORY * (1 - (size/outsize));

          CHECK(cudaMalloc((void**)&d_passwords, itersize));
          CHECK(cudaMalloc((void**)&d_result, iteroutsize));

          //Copy the starting passwords array and valid characters to the GPU
          CHECK(cudaMemcpy(d_passwords, (passwords + j), itersize, cudaMemcpyHostToDevice));

          dim3 block3(BLOCKDIM, 1, 1);
          dim3 grid3(ceil(pow(NUMCHARS, (i - 1))/(float)BLOCKDIM), 1, 1);

          d_generate_kernel<<<grid3, block3>>>(d_passwords, (i - 1), (itersize/(i-1)), d_result);

          CHECK(cudaDeviceSynchronize());

          printf("iteroutsize: %lu\n", iteroutsize);
          unsigned char * outpasswords = (unsigned char *) Malloc(iteroutsize);
          CHECK(cudaMemcpy(outpasswords, d_result, iteroutsize, cudaMemcpyDeviceToHost));

          CHECK(cudaFree(d_passwords));
          CHECK(cudaFree(d_result));

          int found = findPass(outpasswords, hash, iteroutsize, i, hashLen);

          if (found) {
            break;
          }
        }
      }
      else {
        CHECK(cudaMalloc((void**)&d_passwords, size));
        CHECK(cudaMalloc((void**)&d_result, outsize));

        //Copy the starting passwords array and valid characters to the GPU
        CHECK(cudaMemcpy(d_passwords, passwords, size, cudaMemcpyHostToDevice));

        free(passwords);

        dim3 block3(BLOCKDIM, 1, 1);
        dim3 grid3(ceil(pow(NUMCHARS, (i - 1))/(float)BLOCKDIM), 1, 1);

        d_generate_kernel<<<grid3, block3>>>(d_passwords, (i - 1), pow(NUMCHARS, i - 1), d_result);

        CHECK(cudaDeviceSynchronize());

        passwords = (unsigned char *) Malloc(outsize);
        CHECK(cudaMemcpy(passwords, d_result, outsize, cudaMemcpyDeviceToHost));

        CHECK(cudaFree(d_passwords));
        CHECK(cudaFree(d_result));

        int found = findPass(passwords, hash, outsize, i, hashLen);

        if (found) {
          break;
        }
      }
    }
    free(passwords);
    //
    // // for (int i = 0; i < outsize; i += 3) {
    // //   printf("%s\n", &passwords[i]);
    // // }
    //
    // /*****************************KERNAL FOR LENGTH 3**************************/
    //
    // size = pow(NUMCHARS, 2) * 3;
    // outsize = pow(NUMCHARS, 3) * 4;
    //
    // CHECK(cudaMalloc((void**)&d_passwords, size));
    // CHECK(cudaMalloc((void**)&d_result, outsize));
    //
    // //Copy the starting passwords array and valid characters to the GPU
    // CHECK(cudaMemcpy(d_passwords, passwords, (size), cudaMemcpyHostToDevice));
    //
    // dim3 block1(BLOCKDIM, 1, 1);
    // dim3 grid1(ceil(pow(NUMCHARS, 2)/(float)BLOCKDIM), 1, 1);
    //
    // d_generate_kernel<<<grid1, block1>>>(d_passwords, 2, pow(NUMCHARS, 3), d_result);
    //
    // CHECK(cudaDeviceSynchronize());
    //
    // passwords = (unsigned char *) Malloc(outsize);
    // CHECK(cudaMemcpy(passwords, d_result, outsize, cudaMemcpyDeviceToHost));
    //
    // CHECK(cudaFree(d_passwords));
    // CHECK(cudaFree(d_result));
    //
    // /**************passwords NOW HOLDS ALL LENGTH 3 PASSWORDS******************/
    //
    // for (int i = 0; i < outsize; i += 4) {
    //   printf("%s\n", &passwords[i]);
    // }
    //
    // /*****************************KERNAL FOR LENGTH 4**************************/
    //
    // size = pow(NUMCHARS, 3) * 4;
    // outsize = pow(NUMCHARS, 4) * 5;
    //
    // CHECK(cudaMalloc((void**)&d_passwords, size));
    // CHECK(cudaMalloc((void**)&d_result, outsize));
    //
    // //Copy the starting passwords array and valid characters to the GPU
    // CHECK(cudaMemcpy(d_passwords, passwords, size, cudaMemcpyHostToDevice));
    //
    // free(passwords);
    //
    // dim3 block2(BLOCKDIM, 1, 1);
    // dim3 grid2(ceil(pow(NUMCHARS, 3)/(float)BLOCKDIM), 1, 1);
    //
    // d_generate_kernel<<<grid2, block2>>>(d_passwords, 3, pow(NUMCHARS, 4), d_result);
    //
    // CHECK(cudaDeviceSynchronize());
    //
    // passwords = (unsigned char *) Malloc(outsize);
    // CHECK(cudaMemcpy(passwords, d_result, outsize, cudaMemcpyDeviceToHost));
    //
    // CHECK(cudaFree(d_passwords));
    // CHECK(cudaFree(d_result));
    //
    // /**************passwords NOW HOLDS ALL LENGTH 4 PASSWORDS******************/
    //
    // /*****************************KERNAL FOR LENGTH 5**************************/
    //
    // size = pow(NUMCHARS, 4) * 5;
    // outsize = pow(NUMCHARS, 5) * 6;
    //
    // CHECK(cudaMalloc((void**)&d_passwords, size));
    // CHECK(cudaMalloc((void**)&d_result, outsize));
    //
    // //Copy the starting passwords array and valid characters to the GPU
    // CHECK(cudaMemcpy(d_passwords, passwords, size, cudaMemcpyHostToDevice));
    //
    // free(passwords);
    //
    // dim3 block3(BLOCKDIM, 1, 1);
    // dim3 grid3(ceil(pow(NUMCHARS, 4)/(float)BLOCKDIM), 1, 1);
    //
    // d_generate_kernel<<<grid3, block3>>>(d_passwords, 4, pow(NUMCHARS, 5), d_result);
    //
    // CHECK(cudaDeviceSynchronize());
    //
    // passwords = (unsigned char *) Malloc(outsize);
    // CHECK(cudaMemcpy(passwords, d_result, outsize, cudaMemcpyDeviceToHost));
    //
    // CHECK(cudaFree(d_passwords));
    // CHECK(cudaFree(d_result));
    //
    // /**************passwords NOW HOLDS ALL LENGTH 5 PASSWORDS******************/

    // unsigned char * hashes = (unsigned char *) Malloc(pow(NUMCHARS, passLength) * hashLen);
    // int j = 0;
    // for (int i = 0; i < outsize; i+=(passLength + 1)) { //+ 1 corrects for null pointer
    //   //if (i < 17000)
    //     // printf("i: %d, s: %s\n", i, (unsigned char *) &passwords[i]); // print out generated passwords for debugging
    //   // printf("%lu", (unsigned long) passLength);
    //   MD5_CTX md5;
    //   MD5_Init(&md5);
    //   MD5_Update(&md5, &(passwords[i]), (unsigned long) passLength);
    //   MD5_Final(&hashes[j], &md5);
    //   j += hashLen;
    // }
    //
    // unsigned char * ourHash = (unsigned char *) Malloc(hashLen);
    // int numHashes = pow(NUMCHARS, passLength) * hashLen;
    // int z = 0;
    // for (int i = 0; i < numHashes; i+=hashLen) {
    //   // printHash(hash, hashLen);
    //   for (int j = 0; j < hashLen; j++) {
    //     ourHash[j] = hashes[i + j];
    //   }
    //   // printHash(&hashes[i], hashLen);
    //   // printf("%d\n", malloccmp(ourHash, hash, hashLen));
    //   if (malloccmp(ourHash, hash, hashLen)) {
    //     //TODO: Break here, we found the password
    //     printf("Password: ");
    //     printPassword(&passwords[z], 1);
    //   }
    //   for (int k = 0; k < hashLen; k++) {
    //     ourHash[k] = '\0';
    //   }
    //   z +=(passLength + 1);
    // }
    //
    // free(ourHash);
    // free(passwords);
    // free(hashes);

    //record the ending time and wait for event to complete
    CHECK(cudaEventRecord(stop_cpu));
    CHECK(cudaEventSynchronize(stop_cpu));
    //calculate the elapsed time between the two events
    CHECK(cudaEventElapsedTime(&cpuMsecTime, start_cpu, stop_cpu));
    return cpuMsecTime;
}

/*d_generate_kernel
*  Kernal code executed by each thread to generate a list of all possible
*  passwords of length n + 1.  To do this, each thread will work on one element
*  in passwords and append all characters in VALID_CHARS to it. This kernal
*  works in place, so it will alter the input array.
*
*  @params:
*   passwords - array filled with current passwords to build off of.
*   length    - length of the given passwords
*   n         - number of items currently in passwords array
*   d_result  - location to place newly generated passwords.
*/
__global__ void d_generate_kernel(unsigned char * passwords, int length, unsigned long n,
                                    unsigned char * d_result) {
  unsigned long index = blockIdx.x * blockDim.x + threadIdx.x;
  if (index < n) {
    unsigned long r_index = index * (length + 2) * NUMCHARS;
    unsigned long p_index = index * (length + 1);
    // printf("%d\n", p_index);
    // printf("%d\n", r_index);
    for (int i = 0; i < NUMCHARS; i++, r_index += (length + 2)) {
      for (int j = 0; j < length; j++) {
        d_result[r_index + j] = passwords[p_index + j];
      }
      d_result[r_index + length] = VALID_CHARS[i];
      d_result[r_index + length + 1] = '\0';
    }
  }
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
  // int t = blockIdx.x * blockDim.x + threadIdx.x;
  // int inner_index = gridDim.x;
//  if (index == 0 || index == 26 ||index == 52) {
//    printf("inner index: %d\n", inner_index);
//  }

  int powerSize = 0;
  for (int i = (length - 1); i >= 0; i--) {
    if ( i <= (length - 1) - 2) {
//         if (blockIdx.x == 676 && threadIdx.x == 0)
// {
//
//
// printf("threadIdx: %d, blockIdx.x: %d, powersize: %d, modval: %d, powerof: %d, col %d: %c \n", threadIdx.x, blockIdx.x, powerSize, (blockIdx.x % NUMCHARS),  d_powerOf(NUMCHARS, powerSize) , index + i, VALID_CHARS[(blockIdx.x % NUMCHARS)/ d_powerOf(NUMCHARS, powerSize)]);
// }
       d_result[index + i] = VALID_CHARS[blockIdx.x / d_powerOf(NUMCHARS, powerSize)];
        powerSize++;
    } else if ( i == (length - 1) - 1) {


//         if (blockIdx.x == 676 && threadIdx.x == 0)
// {
// printf("threadIdx: %d, blockIdx.x: %d, col %d: %c \n", threadIdx.x, blockIdx.x, index + i, VALID_CHARS[blockIdx.x % NUMCHARS]);
// }


       d_result[index + i] = VALID_CHARS[blockIdx.x % NUMCHARS];
    } else {


//          if (blockIdx.x == 676 && threadIdx.x == 0)
// {
// printf("threadIdx: %d, blockIdx.x: %d, col %d: %c \n", threadIdx.x, blockIdx.x, index + i, VALID_CHARS[threadIdx.x]);
// }


   	d_result[index + i] = VALID_CHARS[threadIdx.x];
    }

  //  d_result[index + i] = VALID_CHARS[((blockIdx.x * (length - 1)) + (t % NUMCHARS)) % NUMCHARS];
  //  inner_index /= NUMCHARS;
  }
//
//   // 4 characters
// //  d_result[index]                = VALID_CHARS[blockIdx.x / (NUMCHARS * NUMCHARS)];
  // d_result[index]                 = VALID_CHARS[blockIdx.x / NUMCHARS];
  // d_result[index + 1]            = VALID_CHARS[blockIdx.x % NUMCHARS];
  // d_result[index + (length - 1)] = VALID_CHARS[threadIdx.x];
  d_result[index + (length)] = '\0';
}

__device__ int d_powerOf(int val, int size) {
  for (int i = 0; i < size; i++) {
    val *= val;
  }


  return val;
}
