# Basic Cryptography - RSA Implementation with and without using CRT
Calculating the time difference in decrytion algorithm of RSA with and without Chineese Remainder Theorem

# Steps to compile/execute
1. To perform arithmetic operation on large numbers (1024 bits) MPIR Library was used. 
   If the library is already present in your system please skip to step : 2.
   1.1. Please find the installation details in https://www.cs.sjsu.edu/~mak/tutorials/InstallMPIR.pdf 
   1.2. Download source files from http://mpir.org/downloads.html .Choose the latest version from "Old versions".
   1.3. Unzip and cd to this folder from terminal window
   1.4. Enter the following cmds
        1.4.1 ./configure --enable-cxx
        1.4.2 make
        1.4.3 If make is not successful, ensure yasm and m4 are installed
              sudo apt install yasm
              sudo apt install m4
       1.4.4  make check
       1.4.5  sudo make install
       1.4.6 sudo ldconfig
2. Download the file RSA.cpp
3. Use the following cmd to compile
   g++ -std=gnu++11 RSA.cpp -o rsa -lmpir
4. To execute the program use the following cmd
   ./rsa


# Submission Details
Name     : Nileena P C
RollNo   : CS21M519
Email-ID : nileena.pc98@gmail.com
