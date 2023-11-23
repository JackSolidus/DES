#include<DES.hpp>

int main()
{
	std::string inputText = "";
	std::string outputText = "";
	std::cin >> inputText;

	Encrypt(inputText, outputText);

	std::cout << outputText << std::endl;
	return 0;
}
