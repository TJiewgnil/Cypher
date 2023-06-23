#include "AES-CBC.h"
string key_read();
string iv_read();

int main()
{
	int op = -1;

	while (1) {
		cout << "-----------------------------------------------------------------------" << endl;
		cout << "CBC模式的AES：进行加密请输入0，进行解密请输入1" << "   （按其余任意键退出）" << endl;
		cin >> op;
		if (cin.fail())
			break;
		if (op == encrypt || op == decrypt) {
			string infilename;
			ifstream infile;
			while (1) {
				if (op == encrypt)
					cout << "请输入待加密文件的文件名" << "   示例：plaintext.txt  /  pic.jpg" << endl;
				else
					cout << "请输入待解密文件的文件名" << "   示例：cyphertext.txt  /  pic-cy.jpg" << endl;
				cin >> infilename;
				infile.open(infilename, ios::in|ios::binary);
				if (!infile.is_open())
					cout << "文件打开失败" << endl;
				else
					break;
			}

			//读取密钥
			string key;
			key = key_read();
		
			//读取初始向量
			string iv;
			iv = iv_read();

			string outfilename;
			ofstream outfile;
			while (1) {
				if (op == encrypt)
					cout << "请输入存放加密结果的文件的文件名" << "   示例：cyphertext.txt  /  pic-cy.jpg" << endl;
				else
					cout << "请输入存放解密结果的文件的文件名" << "   示例：res.txt  /  pic-res.jpg" << endl;
				cin >> outfilename;

				outfile.open(outfilename, ios::out | ios::binary);
				if (!outfile.is_open()) {
					cout << "文件打开失败" << endl;
					outfile.clear();
				}
				else
					break;
			}

			string pre = iv, x;
			char packet[17];
			packet[16] = '\0';

			if (op == encrypt) {//加密
				while (1) {
					//按16个为1组读取数据
					int loc = -1;
					bool last = false, full = false;
					for (int i = 0; i < 16; i++) {
						if (infile.eof()) {
							infile.close();
							//记录最后1组的字节数，方便后续填充
							loc = i - 1;
							last = true;							
							break;
						}
						unsigned char uc_var;
						infile.read((char*)&uc_var, 1);
						packet[i] = uc_var;
						if (!last && i == 15)
							full = true;
					}
					if (full) {
						if (infile.eof()) {
							infile.close();
							//记录最后1组的字节数，方便后续填充
							loc = 15;
							last = true;
						}
					}
					string text(16, ' ');
					for (int i = 0; i < 16; i++)
						text[i] = packet[i];
					//PKCS#7填充
					if (last) { //最后一组
						if (loc == 16) {//正好是16字节的倍数
							x = cbc(text, key, pre);
							outfile << x;
							for (int i = 0; i < 16; i++)
								text[i] = char(16);
							x = cbc(text, key, pre);//补充16字节
							outfile << x;
						}
						else if (loc == -1)
							break;
						else {//最后一组只有loc个字节，不足16字节，进行补充
							for (int i = loc; i < 16; i++)//补充16-loc个字节
								text[i] = char(16 - loc);//每个字节用char(16-loc)填充
							x = cbc(text, key, pre);
							outfile << x;
						}
						break;
					}
					else { //不是最后一组，直接加密输出
						x = cbc(text, key, pre);
						outfile << x;
					}
					pre = x;
				}
			}
			else {//解密
				while (1) {
					//按16个为1组读取数据
					bool last = false, full = false;
					for (int i = 0; i < 16; i++) {
						if (infile.peek() == EOF) {
							infile.close();
							last = true;
							break;
						}
						unsigned char uc_var;
						infile.read((char*)&uc_var, 1);
						packet[i] = uc_var;
						//infile >> packet[i];
						if (i == 15)
							full = true;
					}
					if (full) {
						if (infile.peek() == EOF) {
							infile.close();
							//记录最后1组的字节数，方便后续填充
							last = true;
						}
					}
					string text(16, ' ');
					for (int i = 0; i < 16; i++)
						text[i] = packet[i];


					x = in_cbc(text, key, pre);
					pre = text;

					if (last) {//最后一组
						char tag = x[15];
						//识别出补充的字节，不进行输出
						if (tag != char(16)) {
							//if (tag > 0)
								for (int i = 0; i < 16 - tag; i++)
									outfile << x[i];
						}
						break;
					}
					else//不是最后一组，直接输出
						outfile << x;
				}
			}
			outfile.close();
			cout << "-----------------------------------------------------------------------" << endl;
			cout << endl << endl << endl << endl << endl << endl << endl << endl;
		}
		else {
			cout << "-----------------------------------------------------------------------" << endl;
			break;
		}
	}
}

string key_read()
{
	string keyname;
	fstream key_info;
	while (1) {
		cout << "请输入密钥文件名" << "   示例：key.txt" << endl;
		cin >> keyname;
		key_info.open(keyname, ios::in | ios::binary);
		if (!key_info.is_open()) {
			cout << "文件打开失败" << endl;
			key_info.clear();
		}
		else if (key_info.eof())
			cout << "文件为空" << endl;
		else
			break;
	}
	string key(16, ' ');
	unsigned char u_key;
	for (int i = 0; i < 16; i++) {
		key_info.read((char*)&u_key, 1);
		key[i] = u_key;
	}
	key_info.close();
	return key;
}

string iv_read()
{
	string ivname;
	fstream iv_info;
	while (1) {
		cout << "请输入初始向量iv文件名" << "   示例：iv.txt" << endl;
		cin >> ivname;
		iv_info.open(ivname, ios::in | ios::binary);
		if (!iv_info.is_open()) {
			cout << "文件打开失败" << endl;
			iv_info.clear();
		}
		else if (iv_info.eof())
			cout << "文件为空" << endl;
		else
			break;
	}
	string iv(16, ' ');
	unsigned char u_iv;
	for (int i = 0; i < 16; i++) {
		iv_info.read((char*)&u_iv, 1);
		iv[i] = u_iv;
	}
	iv_info.close();
	return iv;
}
