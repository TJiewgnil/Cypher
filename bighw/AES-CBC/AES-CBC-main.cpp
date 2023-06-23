#include "AES-CBC.h"
string key_read();
string iv_read();

int main()
{
	int op = -1;

	while (1) {
		cout << "-----------------------------------------------------------------------" << endl;
		cout << "CBCģʽ��AES�����м���������0�����н���������1" << "   ��������������˳���" << endl;
		cin >> op;
		if (cin.fail())
			break;
		if (op == encrypt || op == decrypt) {
			string infilename;
			ifstream infile;
			while (1) {
				if (op == encrypt)
					cout << "������������ļ����ļ���" << "   ʾ����plaintext.txt  /  pic.jpg" << endl;
				else
					cout << "������������ļ����ļ���" << "   ʾ����cyphertext.txt  /  pic-cy.jpg" << endl;
				cin >> infilename;
				infile.open(infilename, ios::in|ios::binary);
				if (!infile.is_open())
					cout << "�ļ���ʧ��" << endl;
				else
					break;
			}

			//��ȡ��Կ
			string key;
			key = key_read();
		
			//��ȡ��ʼ����
			string iv;
			iv = iv_read();

			string outfilename;
			ofstream outfile;
			while (1) {
				if (op == encrypt)
					cout << "�������ż��ܽ�����ļ����ļ���" << "   ʾ����cyphertext.txt  /  pic-cy.jpg" << endl;
				else
					cout << "�������Ž��ܽ�����ļ����ļ���" << "   ʾ����res.txt  /  pic-res.jpg" << endl;
				cin >> outfilename;

				outfile.open(outfilename, ios::out | ios::binary);
				if (!outfile.is_open()) {
					cout << "�ļ���ʧ��" << endl;
					outfile.clear();
				}
				else
					break;
			}

			string pre = iv, x;
			char packet[17];
			packet[16] = '\0';

			if (op == encrypt) {//����
				while (1) {
					//��16��Ϊ1���ȡ����
					int loc = -1;
					bool last = false, full = false;
					for (int i = 0; i < 16; i++) {
						if (infile.eof()) {
							infile.close();
							//��¼���1����ֽ���������������
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
							//��¼���1����ֽ���������������
							loc = 15;
							last = true;
						}
					}
					string text(16, ' ');
					for (int i = 0; i < 16; i++)
						text[i] = packet[i];
					//PKCS#7���
					if (last) { //���һ��
						if (loc == 16) {//������16�ֽڵı���
							x = cbc(text, key, pre);
							outfile << x;
							for (int i = 0; i < 16; i++)
								text[i] = char(16);
							x = cbc(text, key, pre);//����16�ֽ�
							outfile << x;
						}
						else if (loc == -1)
							break;
						else {//���һ��ֻ��loc���ֽڣ�����16�ֽڣ����в���
							for (int i = loc; i < 16; i++)//����16-loc���ֽ�
								text[i] = char(16 - loc);//ÿ���ֽ���char(16-loc)���
							x = cbc(text, key, pre);
							outfile << x;
						}
						break;
					}
					else { //�������һ�飬ֱ�Ӽ������
						x = cbc(text, key, pre);
						outfile << x;
					}
					pre = x;
				}
			}
			else {//����
				while (1) {
					//��16��Ϊ1���ȡ����
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
							//��¼���1����ֽ���������������
							last = true;
						}
					}
					string text(16, ' ');
					for (int i = 0; i < 16; i++)
						text[i] = packet[i];


					x = in_cbc(text, key, pre);
					pre = text;

					if (last) {//���һ��
						char tag = x[15];
						//ʶ���������ֽڣ����������
						if (tag != char(16)) {
							//if (tag > 0)
								for (int i = 0; i < 16 - tag; i++)
									outfile << x[i];
						}
						break;
					}
					else//�������һ�飬ֱ�����
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
		cout << "��������Կ�ļ���" << "   ʾ����key.txt" << endl;
		cin >> keyname;
		key_info.open(keyname, ios::in | ios::binary);
		if (!key_info.is_open()) {
			cout << "�ļ���ʧ��" << endl;
			key_info.clear();
		}
		else if (key_info.eof())
			cout << "�ļ�Ϊ��" << endl;
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
		cout << "�������ʼ����iv�ļ���" << "   ʾ����iv.txt" << endl;
		cin >> ivname;
		iv_info.open(ivname, ios::in | ios::binary);
		if (!iv_info.is_open()) {
			cout << "�ļ���ʧ��" << endl;
			iv_info.clear();
		}
		else if (iv_info.eof())
			cout << "�ļ�Ϊ��" << endl;
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
