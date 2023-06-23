#include "AES.h"

//  aes ���ܺ���
string aes(string& plain_text, string& key)
{
	// ����չ��Կ
	string hex_key = "";
	for (char ch : key)
		hex_key += int_to_chs(ch);
	vector<string> keys = extend_key(hex_key);

	int index = 0;
	// Ȼ�����10�ֵ���
	// ��Ҫ֪��������ʵ��32λ��������Ҫ��4��
	// �����Ȱ�����Ҳ����

	//char��Ϊ8bit��1��char���ݷָ�Ϊ2��char��ʹ��ÿ��char���ݶ�����1λ16���Ʊ�ʾ
	string hex_text = "";
	for (char ch : plain_text)
		hex_text += int_to_chs(ch);

	//תΪ16���Ʊ�ʾ
	//vector<string> texts = group_key(plain_text);
	vector<string> texts = group_key(hex_text);

	// ����һ������Կ��
	for (int i = 0; i < 4; ++i)
		texts[i] = string_xor(texts[i], keys[i]);
	index += 4;
	// ʮ�ε���
	for (int k = 0; k < 10; ++k) {
		//S������
		for (int j = 0; j < 4; ++j)
			texts[j] = SubByte(texts[j]);
		//����λ
		texts = ShiftRow(texts);
		//�л��
		if (k < 9)
			texts = MixColumn(texts);
		//����Կ��
		for (int i = 0; i < 4; ++i)
			texts[i] = string_xor(texts[i], keys[i + index]);
		index += 4;
	}

	string ans = "";
	for (auto t : texts)
		for (int i = 0; i < (int)t.length(); i++) {
			int t1 = ch_to_int(t[i]), t2 = ch_to_int(t[++i]);
			ans += char(t1 * 16 + t2);
			t1 = 0;
		}
	return ans;
}

// aes ���ܺ���
string in_aes(string& text, string& key)
{
	string hex_key = "";
	for (char ch : key)
		hex_key += int_to_chs(ch);

	// ��չ��Կ
	auto keys = extend_key(hex_key);

	// ��ʼ�±�
	int index = 40;

	string hex_text = "";
	for (char ch : text)
		hex_text += int_to_chs(ch);

	// ���ķ���
	vector<string> texts = group_key(hex_text);

	// ��������Կ��
	for (int i = 0; i < 4; ++i)
		texts[i] = string_xor(texts[i], keys[index + i]);
	index -= 4;

	// ʮ�ε���
	for (int i = 0; i < 10; ++i) {
		// ������λ
		texts = in_ShiftRow(texts);

		// S�����������
		for (int j = 0; j < 4; ++j)
			texts[j] = in_SubByte(texts[j]);

		// ����Կ��
		for (int j = 0; j < 4; ++j)
			texts[j] = string_xor(texts[j], keys[index + j]);

		// �������һ�֣���Ҫ�л����任
		if (i < 9)
			texts = in_MixColumn(texts);

		index -= 4;
	}

	string ans = "";
	for (auto t : texts)
		for (int i = 0; i < (int)t.length(); i++) {
			int t1 = ch_to_int(t[i]), t2 = ch_to_int(t[++i]);
			ans += char(t1 * 16 + t2);
			t1 = 0;
		}

	return ans;
}

// ��16�����ַ���תΪ����
long long str_long(string str)
{
	long long ans = 0;
	// �����ַ��������ַ��������ݱ�Ϊ16��������
	for (char ch : str)
		ans = ans * 16 + ch_to_int(ch);
	return ans;
}

// �ַ�ת�����ֵĺ���
int ch_to_int(char& ch)
{
	int ans = 0;
	// ���ֵ�ʱ��
	if (ch >= 48 && ch <= 57)
		ans = ch - '0';
	// 16������a �� f
	else if (ch >= 'a' && ch <= 'f')
		ans = ch - 'a' + 10;
	// ����ڱ�ʵ��������У���ʵ�������е���
	else if (ch >= 'A' && ch <= 'F')
		ans = ch - 'A' + 10;
	return ans;
}


// ����ת16�����ַ�����ֻ����Сд
// ��Ե��ǵ���16����
string int_to_chs(long long num)
{
	string ans = "";
	int t = 0;
	if (num == 0) {
		ans += '\x0';
		ans += '\x0';
	}
	else if (num < 0) {
		unsigned char unum = num;
		while (unum) {
			// ͨ��λ����õ�����λ
			int x = unum & 0xf;
			// ������ֵ��������
			if (x <= 9) {
				char ch = x + '0';
				ans += ch;
			}
			else {
				char ch = x - 10 + 'a';
				ans += ch;
			}
			// ��λ����ʵ�൱�� / 16
			unum >>= 4;
		}
	}
	else {
		bool onebit = false;
		if (num < 16)
			onebit = true;
		while (num) {
			// ͨ��λ����õ�����λ
			int x = num & 0xf;
			// ������ֵ��������
			if (x <= 9) {
				char ch = x + '0';
				ans += ch;
			}
			else {
				char ch = x - 10 + 'a';
				ans += ch;
			}
			// ��λ����ʵ�൱�� / 16
			num >>= 4;
		}
		if (onebit)
			ans += '\x0';
	}

	// ��ת�ַ�
	int left = 0, right = (int)ans.length() - 1;
	// ˫ָ��ʵ���ַ�����ת
	while (left < right) {
		char  ch = ans[left];
		ans[left] = ans[right];
		ans[right] = ch;
		left++;
		right--;
	}
	return ans;
}

// ƽ����Ϊ4��
vector<string> group_key(string& key)
{
	// ����
	vector<string> groups(4);
	// ��ʼ�±�
	int index = 0;
	// ����
	for (string& g : groups) {
		g = key.substr(index, 8);
		index += 8;
	}
	return groups;
}

// ��չ��ʱ���±�Ϊ4 �ı���ʱ����Ҫ�鷳һЩ����Ҫʹ��һ���任��T����
string T(string& wi_1, int round)
{
	// T �任��3���ֹ���
	// ��ѭ��
	string ans = loop_wordbyte(wi_1);
	// S������
	ans = SubByte(ans);
	// ����Կ���
	ans = AddRoundKey(ans, round);
	return ans;
}

// �ֽ�ѭ��ʵ��
string loop_wordbyte(string& wi_1)
{
	string ans = wi_1.substr(2) + wi_1.substr(0, 2);
	return ans;
}

// �ַ�����Ӧ��16���������
string string_xor(string s1, string s2)
{
	long long num1 = str_long(s1), num2 = str_long(s2);
	long long num = num1 ^ num2;
	// ������תΪ�ַ���
	string ans = int_to_chs(num);
	// ����8λ��ʱ��λ
	while (ans.length() < 8)
		ans = "0" + ans;
	return ans;
}


// ��Կ����չ
vector<string> extend_key(string& key)
{
	// ����
	vector<string> w_key = group_key(key);
	for (int i = 0; i < 40; ++i) {
		string w = "";
		int index = 4 + i;
		string temp = w_key[index - 1];
		// 4 �ı�����ʱ����Ҫ����T����
		if (index % 4 == 0)
			temp = T(temp, index / 4 - 1);
		w = string_xor(temp, w_key[index - 4]);

		// ѹ��������
		w_key.push_back(w);
	}

	return w_key;
}

// S������
string SubByte(string& wi_1)
{
	int len = (int)wi_1.length();
	string ans = "";
	for (int i = 0; i < len; i += 2) {
		// ��ȡ��ǰ���±�
		int x = ch_to_int(wi_1[i]), y = ch_to_int(wi_1[i + 1]);
		// ��ȡ��ǰ������
		int num = S[x][y];
		// ����ֵת��Ϊ�ַ���
		string s = int_to_chs(num);
		// ����Ļ���0
		while (s.length() < 2)
			s = "0" + s;
		// ������
		ans += s;
	}
	return ans;
}

// ����Կ���
string AddRoundKey(string& wi_1, int rounds)
{
	// ���ַ�����Ϊ����
	long long num = 0;
	for (int i = 0; i < 8; ++i) {
		char ch = wi_1[i];
		num = num * 16 + ch_to_int(ch);
	}
	// ���������
	num ^= Rcon[rounds];
	// ��numת��Ϊ�ַ���
	string res = int_to_chs(num);
	while (res.length() < 8) {
		res = "0" + res;
	}
	return res;
}

// ����λ����
vector<string> ShiftRow(vector<string>& s)
{
	vector<string> ans = s;
	// �����Ƚ��鷳�ĵط�
	// �ҵ��ַ���������ʵÿ���Ƕ�Ӧһ��, ������ʵ�Ƕ�Ӧ���н�����λ
	// һ�ж�Ӧ������16��������������Ҫ����һ���ƶ�����ʵ���Ƕ�Ӧ����һ��
	for (int i = 0; i < 4; ++i) {
		int k = i * 2;
		// ��ԭ�������Ӧ������λ�������ַ��������������λ
		for (int j = 0; j < 4; ++j) {
			ans[j][k] = s[(j + i) % 4][k];
			ans[j][k + 1] = s[(j + i) % 4][k + 1];
		}
	}
	return ans;
}

// �ָ��ַ���������Ϊ8��4��
vector<string> split_s(string& s)
{
	vector<string> ans;
	for (int i = 0; i < (int)s.length(); i += 2)
		ans.emplace_back(s.substr(i, 2));
	return ans;
}

string int_ch2(int num)
{
	string ans = int_to_chs(num);
	// ������Ϊ��ȷ��ֻ����λ�ַ���
	while (ans.length() < 2)
		ans = "0" + ans;
	return ans;
}

// ��λ��������ʵ������GF��2^8���ķ�Χ�����ݴβ���
int power(int num)
{
	int ans = (num << 1) % MOD;
	// �������λ��1
	if (num & 0x80)
		ans ^= 0x1b;
	return ans;
}

//�л���еĹ��ܺ���
int FieldMult(int x)
{
	int sd = 128;//10000000
	int k = 27;//00011011
	int t = (sd & x);//step1��������λ�Ƿ�Ϊ1����1��t=x������1��t=0��ʵ���ϴ˴�tֻҪ����0�ͷ�0���ɣ���һ��Ҫt=1��
	x = x << 1;//step2������1λ���Ҳಹ0
	if (t)//step3���޸�ԭ�ַ���ֵ
		x = x ^ k;
	return x;
}


// �����������л��
vector<string> MixColumn(vector<string>& s)
{
	vector<string> ans = s;
	// �㷨�ж�Ӧ�����У����ҵĳ���Ĵ洢�ṹ����ʵ���У����ַ�
	for (int i = 0; i < 4; i++) {  //step1
		int x[4], sm[4];
		auto temp = split_s(ans[i]);  //���Ϊ4����
		for (int j = 0; j < 4; j++)
			x[j] = (int)str_long(temp[j]);//x[j]��Ӧans[i][j]��Ϊ�������㷽�㣬��16�����ַ�תΪ����
		for (int j = 0; j < 4; j++)  //step2
			sm[j] = (x[(j + 1) % 4] ^ x[(j + 2) % 4] ^ x[(j + 3) % 4]) % 256;//ģ1 0000 0000����֤��8bit
		for (int j = 0; j < 4; j++)  //step3
			x[j] = FieldMult(x[j]);
		for (int j = 0; j < 4; j++)  //step4
			sm[j] = (sm[j] ^ x[j] ^ x[(j + 1) % 4]) % 256;//ģ1 0000 0000����֤��8bit
		ans[i] = int_ch2(sm[0]) + int_ch2(sm[1]) + int_ch2(sm[2]) + int_ch2(sm[3]);  //��������
	}
	return ans;
}

// ��ʾ����
void show(vector<string>& text)
{
	for (auto t : text)
		cout << t;
	cout << endl;
}



// ����λ�����������
vector<string> in_ShiftRow(vector<string>& s)
{
	vector<string> ans = s;
	for (int i = 0; i < 4; ++i) {
		int k = i * 2;
		// ��ԭ�������Ӧ������λ�������ַ��������������λ
		for (int j = 0; j < 4; ++j) {
			ans[j][k] = s[(j - i + 4) % 4][k];
			ans[j][k + 1] = s[(j - i + 4) % 4][k + 1];
		}
	}
	return ans;
}

// ��S������
string in_SubByte(string& wi_1)
{
	int len = (int)wi_1.length();
	string ans = "";
	for (int i = 0; i < len; i += 2) {
		// ��ȡ��ǰ���±�
		int x = ch_to_int(wi_1[i]), y = ch_to_int(wi_1[i + 1]);
		// ��ȡ��ǰ������
		int num = S1[x][y];
		// ����ֵת��Ϊ�ַ���
		string s = int_to_chs(num);
		// ����Ļ���0
		while (s.length() < 2)
			s = "0" + s;

		// ������
		ans += s;
	}
	return ans;
}


// �л�ϵ���任
vector<string> in_MixColumn(vector<string>& s)
{
	// �㷨�ж�Ӧ�����У����ҵĳ���Ĵ洢�ṹ����ʵ���У����ַ�
	vector<string> ans = s;
	for (int i = 0; i < 4; i++) {  //step1
		int x[4], sm[4];
		auto temp = split_s(ans[i]);  //���Ϊ4����
		for (int j = 0; j < 4; j++)
			x[j] = (int)str_long(temp[j]);//x[j]��Ӧans[i][j]��Ϊ�������㷽�㣬��16�����ַ�תΪ����
		for (int j = 0; j < 4; j++)  //step2
			sm[j] = x[(j + 1) % 4] ^ x[(j + 2) % 4] ^ x[(j + 3) % 4];//ģ1 0000 0000����֤��8bit
		for (int j = 0; j < 4; j++)  //step3
			x[j] = FieldMult(x[j]);
		for (int j = 0; j < 4; j++)  //step4
			sm[j] = sm[j] ^ x[j] ^ x[(j + 1) % 4];
		x[0] = FieldMult(x[0] ^ x[2]);  //step5
		x[1] = FieldMult(x[1] ^ x[3]);
		for (int j = 0; j < 4; j++)  //step6
			sm[j] = sm[j] ^ x[j % 2];
		x[0] = FieldMult(x[0] ^ x[1]);  //step7
		for (int j = 0; j < 4; j++)  //step8
			sm[j] = (sm[j] ^ x[0]) % 256;
		ans[i] = int_ch2(sm[0]) + int_ch2(sm[1]) + int_ch2(sm[2]) + int_ch2(sm[3]);  //��������
	}
	return ans;
}