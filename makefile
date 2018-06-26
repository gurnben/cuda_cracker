NVCC = /usr/local/cuda-8.0/bin/nvcc
CC = g++
GENCODE_FLAGS = -arch=sm_30
CC_FLAGS = -c
NVCCFLAGS = -m64 -O3 -Xptxas -v
#uncomment NVCCFLAGS below and comment out above, if you want to use cuda-gdb
#NVCCFLAGS = -g -G -m64 --compiler-options -Wall
OBJS = cuda_cracker.o wrappers.o d_cracker.o
.SUFFIXES: .cu .o .h
.cu.o:
	$(NVCC) $(CC_FLAGS) $(NVCCFLAGS) $(GENCODE_FLAGS) -lcrypto $< -o $@

all: cuda_cracker

cuda_cracker: $(OBJS)
	$(CC) $(OBJS) -L/usr/local/cuda/lib64 -lcuda -lcudart -lcrypto -o cuda_cracker

cuda_cracker.o: cuda_cracker.cu wrappers.h d_cracker.h

d_cracker.o: d_cracker.cu d_cracker.h CHECK.h

wrappers.o: wrappers.cu wrappers.h

clean:
	rm cuda_cracker *.o
