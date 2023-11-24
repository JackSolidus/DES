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

	cout << endl;

	vector <INT64> encrypted_data;

	PrintData(input_text);

	cout << endl;

	encrypted_data = Encrypt(input_text);

	cout << ConvertBlocksToStr(encrypted_data) << endl;

	PrintData(ConvertBlocksToStr(encrypted_data));

	cout << endl;

	encrypted_data = Decrypt(encrypted_data);

	output_text = ConvertBlocksToStr(encrypted_data);

	cout << output_text << endl;

	cout << endl;

	PrintData(output_text);

	return 0;
}
