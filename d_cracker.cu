#include <stdio.h>
#include <stdlib.h>
#include <math.h>
#include <cuda_runtime.h>
#include "d_cracker.h"
#include "CHECK.h"
#include "config.h"
#include "wrappers.h"

//prototype for the kernel
__global__ void d_crack_kernel(unsigned char * hash, int hashLen,
                                int length, unsigned char * d_result);

//constant array containing all the possible characters in the password
__constant__ char VALID_CHARS[NUMCHARS];

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

    int passLength = 2;
    int size = hashLen * sizeof(char);
    int outsize = MAX_PASSWORD_LENGTH * sizeof(char);

    unsigned char * d_hash;
    CHECK(cudaMalloc((void**)&d_hash, size));
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

    d_crack_kernel<<<grid, block>>>(d_hash, hashLen, passLength, d_result);

    CHECK(cudaDeviceSynchronize());

    CHECK(cudaMemcpy(outpass, d_result, outsize, cudaMemcpyDeviceToHost));

    CHECK(cudaFree(d_hash));
    CHECK(cudaFree(d_result));

    //record the ending time and wait for event to complete
    CHECK(cudaEventRecord(stop_cpu));
    CHECK(cudaEventSynchronize(stop_cpu));
    //calculate the elapsed time between the two events
    CHECK(cudaEventElapsedTime(&cpuMsecTime, start_cpu, stop_cpu));
    return cpuMsecTime;
}

/*
   d_crack_kernel
   Kernel code executed by each thread on its own data when the kernel is
   launched. Constant memory is used for the set of all possible characters,
   in this case, lowercase.
   Threads cooperate to help build a possible password built from the Constant
   character array.

   Hash - array filled with characters to crack.
   HashLen - length of the given hash
   d_result - potential password result.

*/

__global__ void d_crack_kernel(unsigned char * hash, int hashLen, int length,
                                unsigned char * d_result) {
  int blockIndex = blockIdx.x * blockDim.x;
}
