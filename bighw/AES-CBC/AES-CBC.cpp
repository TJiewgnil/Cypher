#include"AES-CBC.h"
#include"AES.h"


string cbc(string& text, string& key, string& pre)
{
	//����
	string res(16, ' ');
	for (int i = 0; i < 16; i++)
		res[i] = text[i] ^ pre[i];
	
	ofstream data;
	data.open("data.txt", ios::out||ios::binary);
	data << res;
	data.close();
	
	res = aes(res, key);//����������ͬʱҲ�����ģ�
	return res;
}

string in_cbc(string& text, string& key, string& pre)
{
	//����

	string res;
	res = in_aes(text, key);
	
	for (int i = 0; i < 16; i++)
		res[i] = res[i] ^ pre[i];
	return res;
	//����������ͬʱҲ�����ģ�
}