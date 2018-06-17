#include <stdio.h>
#include <stdlib.h>
#include <math.h>
#include <cuda_runtime.h>
#include "d_cracker.h"
#include "CHECK.h"
#include "config.h"
#include "wrappers.h"

//prototype for the kernel
__global__ void d_crack_kernel(char * hash, int hashLen, char * d_result);

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
float d_crack(char * hash, int hashLen, char * outpass) {

    cudaEvent_t start_cpu, stop_cpu;
    float cpuMsecTime = -1;

    //Use cuda functions to do the timing
    //create event objects
    CHECK(cudaEventCreate(&start_cpu));
    CHECK(cudaEventCreate(&stop_cpu));
    //record the starting time
    CHECK(cudaEventRecord(start_cpu));

    int size = hashLen * sizeof(char);
    int outsize = MAX_PASSWORD_LENGTH * sizeof(char);

    char * d_hash;
    CHECK(cudaMalloc((void**)&d_hash, size));
    char * d_result;
    CHECK(cudaMalloc((void**)&d_result, outsize));

    //build the const array of all lowercase characters
    char VALID_CHARS_CPU[NUMCHARS];
    for (int i = 0; i < 24; i++) {
      VALID_CHARS_CPU[i] = (char)(i + 97);
    }
    CHECK(cudaMemcpyToSymbol(VALID_CHARS, VALID_CHARS_CPU, NUMCHARS * sizeof(char)));

    CHECK(cudaMemcpy(d_hash, hash, size, cudaMemcpyHostToDevice));

    dim3 block(BLOCKDIM, 1, 1);
    dim3 grid(ceil(NUMCHARS/(float)(BLOCKDIM)), 1);

    d_crack_kernel<<<grid, block>>>(d_hash, hashLen, d_result);

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
   d_blurKernel
   Kernel code executed by each thread on its own data when the kernel is
   launched. Shared memory is used for both the mask and the pixels.
   Threads cooperate in loading the shared memory.  After the
   shared memor is filled, the convolution is performed.

   Pout - array that is filled with the blur of each pixel.
   Pin - array contains the color pixels to be blurred.
   width and height -  dimensions of the image.
   pitch - size of each row.
   maskWidth - dimensions of the mask to be used.
   mask - contains mask used for the convolution.

*/

__global__ void d_crack_kernel(char * hash, int hashLen, char * d_result) {

}
