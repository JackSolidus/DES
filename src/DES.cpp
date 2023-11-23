#include <DES.h>

#define LSHIFT_28BIT(x, L) ((((x) << (L)) | ((x) >> (-(L) & 27))) & (((uint64_t)1 << 32) - 1))

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

void FillBlocks(std::string &block)
{
	UINT32 blockTracker = 0; // отслеживает в какой блок необходимо писать биты
	INT8 rankTracker = 7;	// отслеживает в какую часть блока необходимо записать 8 бит текста

	bufferedBlocks.clear();
	bufferedBlocks.push_back(0);

	for (int i = 0; i < block.size(); i++) {
		if (rankTracker < 0 && i != block.size()) {
			bufferedBlocks.push_back(0);
			blockTracker++;
			rankTracker = 7;
			continue;
		}

		UINT64 temporary = block[i];
		bufferedBlocks[blockTracker] += temporary << rankTracker * 8;

		rankTracker--;
	}
}

void GenerateSetOfKeys()
{
	// ѕодготовка массивов к заполнению
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

void PerformInitialPermuatation(UINT64 &current_block)
{
	UINT64 encryptedContainter = 0;
	for (int i = 0; i < 63; i++) {
		encryptedContainter |= (UINT64)(current_block >> (64 - initial_permutation[i]) & 0x01) << (63 - i);
	}
}

void Encrypt(std::string &entry_block, std::string &output_block)
{
	CompleteBlockTo64b(entry_block);

	GenerateSetOfKeys();

	FillBlocks(entry_block);
	
	for (int i = 0; i < bufferedBlocks.size(); i++) {

		PerformInitialPermuatation(bufferedBlocks[i]);
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
		case 0:
			ExpandKeyStage(prepared_keys[i], 1);
			break;
		case 1:
			ExpandKeyStage(prepared_keys[i], 1);
			break;
		case 8:
			ExpandKeyStage(prepared_keys[i], 1);
			break;
		case 15:
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
	key_part_left = LSHIFT_28BIT(key_part_left, n);
	UINT64 unexpended_key = key_part_left;
	unexpended_key <<= 28;
	key_part_right = LSHIFT_28BIT(key_part_right, n);
	UINT32 buff = key_part_right & 0x0FFFFFFF;
	unexpended_key += buff;

	for (int i = 0; i < (sizeof(key_expansion) / sizeof(UINT8)); i++) {
		prepared_key |= ((unexpended_key >> 56 - key_expansion[i]) & 0x01) << (47 - i);
	}
	std::cout << std::bitset<64>(prepared_key) << " = " <<
		std::popcount(prepared_key) << std::endl;
}
