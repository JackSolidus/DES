#include<DES.hpp>
#include<clocale>
#include<Windows.h>
#include<algorithm>

using namespace std;

int main()
{
	setlocale(LC_ALL, "UTF-8");


	string input_text = "";
	string output_text = "";

	getline(cin, input_text);

	vector <INT64> encrypted_data;

	PrintData(input_text);

	encrypted_data = Encrypt(input_text);

	PrintData(ConvertBlocksToStr(encrypted_data));

	encrypted_data = Decrypt(encrypted_data);

	output_text = ConvertBlocksToStr(encrypted_data);

	PrintData(output_text);

	cout << output_text << endl;

	return 0;
}
