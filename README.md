# Basic Cryptography - RSA Implementation with and without using CRT
Calculating the time difference in decrytion algorithm of RSA with and without Chineese Remainder Theorem

# Steps to compile/execute
1. To perform arithmetic operation on large numbers (1024 bits) MPIR Library was used. If the library is already present in your system please skip to step:15.
2. Please find the installation details in https://www.cs.sjsu.edu/~mak/tutorials/InstallMPIR.pdf 
3. Download source files from http://mpir.org/downloads.html .Choose the latest version from "Old versions".
4. Unzip and cd to this folder from terminal window
5. Enter the following cmds
6. ./configure --enable-cxx
7. make
8. If make is not successful, ensure yasm and m4 are installed
9. sudo apt install yasm
10. sudo apt install m4
11. make check
12. sudo make install
13. sudo ldconfig
14. Download the file RSA.cpp
15. Use the following cmd to compile => g++ -std=gnu++11 RSA.cpp -o rsa -lmpir
16. To execute the program use the following cmd => ./rsa


# Submission Details
Name     : Nileena P C
RollNo   : CS21M519
Email-ID : nileena.pc98@gmail.com
