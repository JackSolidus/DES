#include <DES.hpp>


UINT64 CreateInitialVector()
{
	return UINT64();
}

void CompleteBlockTo64b(std::string &block)
{
	while (true)
	{	
		if ((block.size() * 8) % block_size == false)
			break;
		block += (INT8)0;
	}
}

// переделать, так как нету заполнения buffer blocks
void FillBlocks(UINT64 &vector)
{
	UINT32 blockTracker = 0; // отслеживает в какой блок необходимо писать биты
	INT8 rankTracker = 7;	// отслеживает в какую часть блока необходимо записать 8 бит текста

	bufferedBlocks.clear();
	bufferedBlocks.push_back(0);

	/*for (int i = 0; i < sizeof(vector); i++) {
		if (rankTracker < 0 && i != vector.size()) {
			bufferedBlocks.push_back(0);
			blockTracker++;
			rankTracker = 7;
			continue;
		}

		UINT64 temporary = block[i];
		bufferedBlocks[blockTracker] += temporary << rankTracker * 8;

		rankTracker--;
	}*/
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
	for (int i = 0; i < sizeof(key); i++) {
		int kkey = std::popcount((UINT8)key[i]);
		UINT64 buff = 0;
		if (std::popcount((UINT8)key[i]) % 2 == 0) {
			buff = key[i] | 0b10000000;
		}
		else {
			buff = key[i];
		}
		dedicated_bits_key += buff << (56 - 8 * i);
	}
	
}

UINT64 PerformInitialPermuatation(UINT64& current_block)
{
	UINT64 encryptedContainter = 0;

	for (int i = 0; i < 63; i++) {
		encryptedContainter |= (UINT64)((current_block >> (64 - initial_permutation[i])) & 0x01) << (63 - i);
	}

	return encryptedContainter;
}

UINT64 PerformFinalPermutation(UINT64& block)
{
	UINT64 buff = 0;
	for (int i = 0; i < 64; i++) {
		buff |= (UINT64)((block >> (64 - final_permutation[i])) & 0x01) << (63 - i);
	}
	return buff;
}

void Encrypt(std::string &entry_block, std::string &output_block)
{
	CompleteBlockTo64b(entry_block);

	GenerateSetOfKeys();

	bufferedBlocks.clear();

	encrypted_blocks.clear();

	initial_vector = CreateInitialVector();

	for (int i = 0; i < bufferedBlocks.size(); i++) {

		FillBlocks(initial_vector);
		initial_vector = PerformFeistelNet(initial_vector);
		encrypted_blocks.push_back(entry_block[i] ^ initial_vector);
	}
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

void ExpandKeyStage(UINT64& prepared_key, UINT8 n)
{
	LeftShift28Bits(key_part_left, n);

	UINT64 unexpended_key = key_part_left;

	unexpended_key <<= 28;

	LeftShift28Bits(key_part_right, n);

	unexpended_key += key_part_right;

	for (int i = 0; i < (sizeof(key_expansion) / sizeof(UINT8)); i++) {
		prepared_key |= ((unexpended_key >> (56 - key_expansion[i])) & 0x01) << (47 - i);
	}
}

void LeftShift28Bits(UINT32& set_of_bits, UINT8& n)
{
	UINT32 buff = 0;
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

UINT64 PerformFeistelNet(UINT64& block_to_encrypt)
{
	PerformInitialPermuatation(block_to_encrypt);

	SeparateBlockTo32Part(block_to_encrypt, block_left_part, block_right_part);

	for (UINT8 i = 0; i < 16; i++) {
		FFuncEncrypting(block_left_part, block_right_part, i);
	}

	UINT64 buff = Combine32To64Bit(block_left_part, block_right_part);

	UINT64 final_block = PerformFinalPermutation(buff);

	return final_block;
}

void FFuncEncrypting(UINT32 &left_part, UINT32 &right_part, UINT8 &n)
{
	UINT64 expanded_block = Expand32Block(right_part);
	expanded_block ^= prepared_keys[n];
	UINT32 proceded_right_part = PerformSPermutation(expanded_block);
	left_part ^= proceded_right_part;

	UINT32 buff = right_part;
	right_part = left_part;
	left_part = buff;
}

void SeparateBlockTo32Part(UINT64& block, UINT32& left_part, UINT32& right_part)
{
	right_part = block & 0x0ffffffff;
	left_part = block >> 32;
}

UINT64 Combine32To64Bit(UINT32& left, UINT32& right)
{
	UINT64 buff = left;
	buff <<= 32;
	buff += right;
	return buff;
}

UINT64 Expand32Block(UINT32 &block)
{
	UINT64 buff = block;
	UINT64 expended_key = 0;

	// Расширение блока
	for (int i = 0; i < 48; i++) {
		expended_key |= ((buff >> (32 - block_expansion[i])) & 0x01) << (47 - i);
	}

	return expended_key;
}

UINT32 PerformSPermutation(UINT64 &xored_block)
{
	UINT8 block_6bit[8];
	memset(block_6bit, 0, sizeof(block_6bit));

	Write48BitTo6bit(xored_block, block_6bit);
	
	UINT32 sorted_right = 0;
	for (int i = 0; i < 8; i++) {
		sorted_right <<= 4;
		sorted_right += SBox[i][(block_6bit[i] & 0x03)][((block_6bit[i] >> 2) & 0x0f)];
	}

	return sorted_right;
}

void Write48BitTo6bit(UINT64 &xored_block, UINT8 *blocks_6bit)
{
	for (int i = 0; i < 8; i++) {
		blocks_6bit[i] = ((xored_block >> (42 - 6 * i)) & 0x03f);
	}
}
