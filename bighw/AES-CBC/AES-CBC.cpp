#include"AES-CBC.h"
#include"AES.h"


string cbc(string& text, string& key, string& pre)
{
	//加密
	string res(16, ' ');
	for (int i = 0; i < 16; i++)
		res[i] = text[i] ^ pre[i];
	
	ofstream data;
	data.open("data.txt", ios::out||ios::binary);
	data << res;
	data.close();
	
	res = aes(res, key);//更新向量（同时也是密文）
	return res;
}

string in_cbc(string& text, string& key, string& pre)
{
	//解密

	string res;
	res = in_aes(text, key);
	
	for (int i = 0; i < 16; i++)
		res[i] = res[i] ^ pre[i];
	return res;
	//更新向量（同时也是密文）
}