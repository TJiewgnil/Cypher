#include "AES.h"

int main()
{
	int op;
	while (1) {
		cout << "-----------------------------------------------------------------------" << endl;
		cout << "进行AES加密请输入0，进行AES解密请输入1" << "   （按其余任意键退出）" << endl;
		cin >> op;	// 输入标识符
		if (cin.fail())
			break;
		cout << endl;
		if (op == 0 || op == 1) {
			string text, key;
			if (op == 0) {
				cout << "请输入明文（长度必须为16字节）" << "   示例：cryptography1234" << endl;
				cout << "明文为：" << endl;//对应密文：8b0cde2e9c976648eae8b6cb7c23ccaf
			}
			else {
				cout << "请输入密文（长度必须为32字节）" << "   示例：4723a1eb685e0e1332561fdc8bd94ca4" << endl;
				cout << "（实际上密文为16字节，为了显示出可见字符，将每个字节用16进制表示,故长度变为2倍）" << endl;
				cout << "密文为：" << endl;//对应明文：ilovetaylorswift
			}
			
			cin >> text;
			cout << endl;

			cout << "请输入密钥（长度必须为16个字符）" << "   示例：8i39c5t2b97ja1bz" << endl;
			cout << "密钥为：" << endl;
			cin >> key;

			cout << endl;

			// 根据标识符，决定加密还是解密
			if (op == 0) {
				cout << "（实际上密文为16字节，为了显示出可见字符，将每个字节用16进制表示,故长度变为2倍）" << endl;
				cout << "加密结果为：" << endl;
				aes(text, key);
			}
			else {
				cout << "解密结果为：" << endl;
				in_aes(text, key);
			}
			cout << "-----------------------------------------------------------------------" << endl;
			cout << endl << endl << endl << endl << endl << endl << endl << endl;
		}
		else {
			cout << "-----------------------------------------------------------------------" << endl;
			break;
		}
	}
	return 0;
}