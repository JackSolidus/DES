#ifndef DES_H
#define DES_H

#include <string>
#include <vector>
#include <iostream>
#include <bitset>
#include <bit>

#include <Types.h>


#define BUFF_SIZE 1024

static INT8 initial_permutation[] = { 58, 50, 42, 34, 26, 18, 10, 2, 60, 52, 44, 36, 28, 20, 12, 4,
                                      62, 54, 46, 38, 30, 22, 14, 6, 64, 56, 48, 40, 32, 24, 16, 8,
                                      57, 49, 41, 33, 25, 17, 9,  1, 59, 51, 43, 35, 27, 19, 11, 3,
                                      61, 53, 45, 37, 29, 21, 13, 5, 63, 55, 47, 39, 31, 23, 15, 7 };

static INT8 left_key_permutation[] = { 57, 49, 41, 33, 25, 17, 9, 1, 58, 50, 42, 34, 26, 18,
                                       10, 2, 59, 51, 43, 35, 27, 19, 11, 3, 60, 52, 44, 36 };

static INT8 right_key_permutation[] = { 63, 55, 47, 39, 31, 23, 15, 7, 62, 54, 46, 38, 30, 22,
                                        14, 6, 61, 53, 45, 37, 29, 21, 13, 5, 28, 20, 12, 4 };

static UINT8 key_expansion[] = { 14, 17, 11, 24, 1, 5, 3, 28, 15, 6, 21, 10, 23, 19, 12, 4,
                                 26, 8, 16, 7, 27, 20, 13, 2, 41, 52, 31, 37, 47, 55, 30, 40,
                                 51, 45, 33, 48, 44, 49, 39, 56, 34, 53, 46, 42, 50, 36, 29, 32 };

static UINT8 key[8] = { 'A', 'n', 'a', 'k', 'o', 'n', 'd', 'a' };

static UINT16 block_size = 64;

static std::vector<INT8> encrypted, decrypted;

static UINT64 dedicated_bits_key = 0;

static UINT32 key_part_right = 0, key_part_left = 0;

static UINT64 prepared_keys[16];

static std::vector<UINT64> bufferedBlocks, encrypted_blocks;


UINT64 CreateInitialVector();

void CompleteBlockTo64b(std::string &block);

void AllocationOfSegnificantBits();

void FillBlocks(std::string &block);

void GenerateSetOfKeys();

void PerformInitialPermuatation(UINT64 &current_block);

void Encrypt(std::string& entryBlock, std::string &output_block);

void PerformKeyModification();

void ExpandKeyStage(UINT64 &prepared_key, UINT8 n);

#endif // !DES_H