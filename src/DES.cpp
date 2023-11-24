#include <DES.hpp>


INT64 CreateInitialVector()
{
	INT64 vector = 0;

	srand(time(NULL));

	vector = rand();
	vector <<= 32;
	vector += rand();

	return vector;
}

void CompleteStringTo64b(std::string &block)
{
	while (true)
	{	
		if ((block.size() * 8) % block_size == false)
			break;
		block += (char)0;
	}
}

// переделать, так как нету заполнения buffer blocks
void TransformStringToBlocks(std::string& data_to_encrypt)
{
	bufferedBlocks.clear();
	bufferedBlocks.push_back(0);
	
	INT64 block_to_write = 0;

	for (int i = 0; i < data_to_encrypt.size(); i++) {
		if ((i > 0) && ((i % 8) == 0)) {
			bufferedBlocks.push_back(0);
			block_to_write++;
		}
		if (i > 0) {
			bufferedBlocks[block_to_write] <<= 8;
		}
		UINT8 buff = data_to_encrypt[i];
		bufferedBlocks[block_to_write] += buff;
	}
}

void GenerateSetOfKeys()
{
	// Подготовка массивов к заполнению
	memset(prepared_keys, 0, sizeof(prepared_keys));

	AllocationOfSegnificantBits();

	PerformKeyModification();

}

void AllocationOfSegnificantBits()
{
	dedicated_bits_key = 0;

	for (int i = 0; i < sizeof(key); i++) {
		int kkey = std::popcount((UINT8)key[i]);
		INT64 buff = 0;
		if (std::popcount((UINT8)key[i]) % 2 == 0) {
			buff = key[i] | 0b10000000;
		}
		else {
			buff = key[i];
		}
		dedicated_bits_key += buff << (56 - 8 * i);
	}
	
}

INT64 PerformInitialPermuatation(INT64& current_block)
{
	INT64 encryptedContainter = 0;

	for (int i = 0; i < 63; i++) {
		encryptedContainter |= (INT64)((current_block >> (64 - initial_permutation[i])) & 0x01) << (63 - i);
	}

	return encryptedContainter;
}

INT64 PerformFinalPermutation(INT64& block)
{
	INT64 buff = 0;
	for (int i = 0; i < 64; i++) {
		buff |= (INT64)((block >> (64 - final_permutation[i])) & 0x01) << (63 - i);
	}
	return buff;
}

std::vector<INT64> Encrypt(std::string &string_to_encrypt)
{
	CompleteStringTo64b(string_to_encrypt);

	TransformStringToBlocks(string_to_encrypt);

	GenerateSetOfKeys();

	initial_vector = CreateInitialVector();

	saved_vector = initial_vector;

	encrypted_blocks.clear();

	for (int i = 0; i < bufferedBlocks.size(); i++) {
		initial_vector = PerformFeistelNet(initial_vector);
		encrypted_blocks.push_back(bufferedBlocks[i] ^ initial_vector);
	}

	return encrypted_blocks;
}

std::vector<INT64> Decrypt(std::vector<INT64> block_to_decrypt)
{
	GenerateSetOfKeys();
	initial_vector = saved_vector;

	for (int i = 0; i < block_to_decrypt.size(); i++) {
		initial_vector = PerformFeistelNet(initial_vector);
		block_to_decrypt[i] ^= initial_vector;
	}

	return block_to_decrypt;
}

void PerformKeyModification()
{
	for (int i = 0; i < 28; i++) {
		key_part_left |= (dedicated_bits_key >> (64 - left_key_permutation[i]) & 0x01) << (27 - i);
		key_part_right |= (dedicated_bits_key >> (64 - right_key_permutation[i]) & 0x01) << (27 - i);
	}
	for (int i = 0; i < 16; i++) {
		switch (i)
		{
		case 0:case 1:case 8:case 15:
			ExpandKeyStage(prepared_keys[i], 1);
			break;
		default:
			ExpandKeyStage(prepared_keys[i], 2);
			break;
		}
	}
}

void ExpandKeyStage(INT64& prepared_key, INT8 n)
{
	LeftShift28Bits(key_part_left, n);

	UINT64 unexpended_key = key_part_left;

	unexpended_key <<= 28;

	LeftShift28Bits(key_part_right, n);

	unexpended_key += key_part_right;

	for (int i = 0; i < (sizeof(key_expansion) / sizeof(INT8)); i++) {
		prepared_key |= ((unexpended_key >> (56 - key_expansion[i])) & 0x01) << (47 - i);
	}
}

void LeftShift28Bits(INT32& set_of_bits, INT8& n)
{
	INT32 buff = 0;
	for (int i = 0; i < n; i++) {
		buff <<= 1;
		if (((set_of_bits >> (27 - i)) & 0x01) == 1) {
			buff += 1;
		}
	}
	set_of_bits <<= n;
	set_of_bits &= 0x0fffffff;
	set_of_bits |= buff;
}

INT64 PerformFeistelNet(INT64& block_to_encrypt)
{
	PerformInitialPermuatation(block_to_encrypt);

	SeparateBlockTo32Part(block_to_encrypt, block_left_part, block_right_part);

	for (INT8 i = 0; i < 16; i++) {
		FFuncEncrypting(block_left_part, block_right_part, i);
	}

	INT64 buff = Combine32To64Bit(block_left_part, block_right_part);

	INT64 final_block = PerformFinalPermutation(buff);

	return final_block;
}

void FFuncEncrypting(INT32 &left_part, INT32 &right_part, INT8 &n)
{
	INT64 expanded_block = Expand32Block(right_part);
	expanded_block ^= prepared_keys[n];
	INT32 proceded_right_part = PerformSPermutation(expanded_block);
	left_part ^= proceded_right_part;

	INT32 buff = right_part;
	right_part = left_part;
	left_part = buff;
}

void SeparateBlockTo32Part(INT64& block, INT32& left_part, INT32& right_part)
{
	right_part = block & 0x0ffffffff;
	left_part = block >> 32;
}

INT64 Combine32To64Bit(INT32& left, INT32& right)
{
	INT64 buff = left;
	buff <<= 32;
	buff += right;
	return buff;
}

INT64 Expand32Block(INT32 &block)
{
	INT64 buff = block;
	INT64 expended_key = 0;

	// Расширение блока
	for (int i = 0; i < 48; i++) {
		expended_key |= ((buff >> (32 - block_expansion[i])) & 0x01) << (47 - i);
	}

	return expended_key;
}

INT32 PerformSPermutation(INT64 &xored_block)
{
	INT8 block_6bit[8];
	memset(block_6bit, 0, sizeof(block_6bit));

	Write48BitTo6bit(xored_block, block_6bit);
	
	INT32 sorted_right = 0;
	for (int i = 0; i < 8; i++) {
		sorted_right <<= 4;
		sorted_right += SBox[i][(block_6bit[i] & 0x03)][((block_6bit[i] >> 2) & 0x0f)];
	}

	return sorted_right;
}

void Write48BitTo6bit(INT64 &xored_block, INT8 *blocks_6bit)
{
	for (int i = 0; i < 8; i++) {
		blocks_6bit[i] = ((xored_block >> (42 - 6 * i)) & 0x03f);
	}
}

void PrintData(std::string str)
{
	std::cout << "[ ";
	for (int i = 0; i < str.size(); i++) {
		if (i == (str.size() - 1)) {
			std::cout << (UINT16)str[i] << " ]" << std::endl;
		}
		else {
			std::cout << (UINT16)str[i] << ", ";
		}
	}
}

std::string ConvertBlocksToStr(std::vector<INT64> blocks)
{
	std::string buff = "";
	for (int i = 0; i < blocks.size(); i++) {
		for (int pos = 0; pos < 8; pos++) {
			buff += (char)((blocks[i] >> (56 - (8 * pos))) & 0x0ff);
		}
	}
	return buff;
}
