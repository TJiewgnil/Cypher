#include "AES.h"

//  aes 加密函数
string aes(string& plain_text, string& key)
{
	// 先拓展密钥
	string hex_key = "";
	for (char ch : key)
		hex_key += int_to_chs(ch);
	vector<string> keys = extend_key(hex_key);

	int index = 0;
	// 然后就是10轮迭代
	// 需要知道明文其实是32位，所以需要搞4下
	// 可以先把明文也分组

	//char型为8bit，1个char数据分割为2个char，使得每个char数据都可用1位16进制表示
	string hex_text = "";
	for (char ch : plain_text)
		hex_text += int_to_chs(ch);

	//转为16进制表示
	//vector<string> texts = group_key(plain_text);
	vector<string> texts = group_key(hex_text);

	// 进行一次轮密钥加
	for (int i = 0; i < 4; ++i)
		texts[i] = string_xor(texts[i], keys[i]);
	index += 4;
	// 十次迭代
	for (int k = 0; k < 10; ++k) {
		//S盒运算
		for (int j = 0; j < 4; ++j)
			texts[j] = SubByte(texts[j]);
		//行移位
		texts = ShiftRow(texts);
		//列混合
		if (k < 9)
			texts = MixColumn(texts);
		//轮密钥加
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

// aes 解密函数
string in_aes(string& text, string& key)
{
	string hex_key = "";
	for (char ch : key)
		hex_key += int_to_chs(ch);

	// 拓展密钥
	auto keys = extend_key(hex_key);

	// 初始下标
	int index = 40;

	string hex_text = "";
	for (char ch : text)
		hex_text += int_to_chs(ch);

	// 密文分组
	vector<string> texts = group_key(hex_text);

	// 依次轮密钥加
	for (int i = 0; i < 4; ++i)
		texts[i] = string_xor(texts[i], keys[index + i]);
	index -= 4;

	// 十次迭代
	for (int i = 0; i < 10; ++i) {
		// 逆行移位
		texts = in_ShiftRow(texts);

		// S盒运算逆操作
		for (int j = 0; j < 4; ++j)
			texts[j] = in_SubByte(texts[j]);

		// 轮密钥加
		for (int j = 0; j < 4; ++j)
			texts[j] = string_xor(texts[j], keys[index + j]);

		// 除了最后一轮，都要列混合逆变换
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

// 将16进制字符串转为数字
long long str_long(string str)
{
	long long ans = 0;
	// 遍历字符串，将字符串的内容变为16进制数字
	for (char ch : str)
		ans = ans * 16 + ch_to_int(ch);
	return ans;
}

// 字符转成数字的函数
int ch_to_int(char& ch)
{
	int ans = 0;
	// 数字的时候
	if (ch >= 48 && ch <= 57)
		ans = ch - '0';
	// 16进制中a 到 f
	else if (ch >= 'a' && ch <= 'f')
		ans = ch - 'a' + 10;
	// 这个在本实验的样例中，其实不会运行到的
	else if (ch >= 'A' && ch <= 'F')
		ans = ch - 'A' + 10;
	return ans;
}


// 数字转16进制字符串，只考虑小写
// 针对的是单个16进制
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
			// 通过位运算得到低四位
			int x = unum & 0xf;
			// 根据数值进行区分
			if (x <= 9) {
				char ch = x + '0';
				ans += ch;
			}
			else {
				char ch = x - 10 + 'a';
				ans += ch;
			}
			// 移位，其实相当于 / 16
			unum >>= 4;
		}
	}
	else {
		bool onebit = false;
		if (num < 16)
			onebit = true;
		while (num) {
			// 通过位运算得到低四位
			int x = num & 0xf;
			// 根据数值进行区分
			if (x <= 9) {
				char ch = x + '0';
				ans += ch;
			}
			else {
				char ch = x - 10 + 'a';
				ans += ch;
			}
			// 移位，其实相当于 / 16
			num >>= 4;
		}
		if (onebit)
			ans += '\x0';
	}

	// 反转字符
	int left = 0, right = (int)ans.length() - 1;
	// 双指针实现字符串反转
	while (left < right) {
		char  ch = ans[left];
		ans[left] = ans[right];
		ans[right] = ch;
		left++;
		right--;
	}
	return ans;
}

// 平均分为4组
vector<string> group_key(string& key)
{
	// 四组
	vector<string> groups(4);
	// 初始下标
	int index = 0;
	// 分组
	for (string& g : groups) {
		g = key.substr(index, 8);
		index += 8;
	}
	return groups;
}

// 拓展的时候，下标为4 的倍数时，需要麻烦一些，需要使用一个变换的T函数
string T(string& wi_1, int round)
{
	// T 变换由3部分构成
	// 字循环
	string ans = loop_wordbyte(wi_1);
	// S盒运算
	ans = SubByte(ans);
	// 轮密钥异或
	ans = AddRoundKey(ans, round);
	return ans;
}

// 字节循环实现
string loop_wordbyte(string& wi_1)
{
	string ans = wi_1.substr(2) + wi_1.substr(0, 2);
	return ans;
}

// 字符串对应的16进制数异或
string string_xor(string s1, string s2)
{
	long long num1 = str_long(s1), num2 = str_long(s2);
	long long num = num1 ^ num2;
	// 把数字转为字符串
	string ans = int_to_chs(num);
	// 不足8位的时候补位
	while (ans.length() < 8)
		ans = "0" + ans;
	return ans;
}


// 密钥的拓展
vector<string> extend_key(string& key)
{
	// 分组
	vector<string> w_key = group_key(key);
	for (int i = 0; i < 40; ++i) {
		string w = "";
		int index = 4 + i;
		string temp = w_key[index - 1];
		// 4 的倍数的时候，需要调用T函数
		if (index % 4 == 0)
			temp = T(temp, index / 4 - 1);
		w = string_xor(temp, w_key[index - 4]);

		// 压入数组中
		w_key.push_back(w);
	}

	return w_key;
}

// S盒运算
string SubByte(string& wi_1)
{
	int len = (int)wi_1.length();
	string ans = "";
	for (int i = 0; i < len; i += 2) {
		// 获取当前的下标
		int x = ch_to_int(wi_1[i]), y = ch_to_int(wi_1[i + 1]);
		// 获取当前的数字
		int num = S[x][y];
		// 将数值转化为字符串
		string s = int_to_chs(num);
		// 不足的话补0
		while (s.length() < 2)
			s = "0" + s;
		// 加起来
		ans += s;
	}
	return ans;
}

// 轮密钥异或
string AddRoundKey(string& wi_1, int rounds)
{
	// 将字符串变为数字
	long long num = 0;
	for (int i = 0; i < 8; ++i) {
		char ch = wi_1[i];
		num = num * 16 + ch_to_int(ch);
	}
	// 计算异或结果
	num ^= Rcon[rounds];
	// 将num转化为字符串
	string res = int_to_chs(num);
	while (res.length() < 8) {
		res = "0" + res;
	}
	return res;
}

// 行移位函数
vector<string> ShiftRow(vector<string>& s)
{
	vector<string> ans = s;
	// 几个比较麻烦的地方
	// 我的字符串数组其实每个是对应一列, 所以其实是对应到列进行移位
	// 一行对应有两个16进制数，所以需要两个一起移动，其实就是对应两列一起动
	for (int i = 0; i < 4; ++i) {
		int k = i * 2;
		// 就原本矩阵对应的行移位，对于字符串数组就是列移位
		for (int j = 0; j < 4; ++j) {
			ans[j][k] = s[(j + i) % 4][k];
			ans[j][k + 1] = s[(j + i) % 4][k + 1];
		}
	}
	return ans;
}

// 分割字符串，长度为8变4组
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
	// 这里是为了确保只有两位字符串
	while (ans.length() < 2)
		ans = "0" + ans;
	return ans;
}

// 移位函数，其实就是在GF（2^8）的范围进行幂次操作
int power(int num)
{
	int ans = (num << 1) % MOD;
	// 如果第七位是1
	if (num & 0x80)
		ans ^= 0x1b;
	return ans;
}

//列混合中的功能函数
int FieldMult(int x)
{
	int sd = 128;//10000000
	int k = 27;//00011011
	int t = (sd & x);//step1：检测最高位是否为1，是1则t=x，不是1则t=0（实际上此处t只要区分0和非0即可，不一定要t=1）
	x = x << 1;//step2：左移1位，右侧补0
	if (t)//step3：修改原字符的值
		x = x ^ k;
	return x;
}


// 接下来就是列混合
vector<string> MixColumn(vector<string>& s)
{
	vector<string> ans = s;
	// 算法中对应的是列，在我的程序的存储结构中其实是行，即字符
	for (int i = 0; i < 4; i++) {  //step1
		int x[4], sm[4];
		auto temp = split_s(ans[i]);  //打断为4部分
		for (int j = 0; j < 4; j++)
			x[j] = (int)str_long(temp[j]);//x[j]对应ans[i][j]，为后续运算方便，将16进制字符转为数字
		for (int j = 0; j < 4; j++)  //step2
			sm[j] = (x[(j + 1) % 4] ^ x[(j + 2) % 4] ^ x[(j + 3) % 4]) % 256;//模1 0000 0000，保证是8bit
		for (int j = 0; j < 4; j++)  //step3
			x[j] = FieldMult(x[j]);
		for (int j = 0; j < 4; j++)  //step4
			sm[j] = (sm[j] ^ x[j] ^ x[(j + 1) % 4]) % 256;//模1 0000 0000，保证是8bit
		ans[i] = int_ch2(sm[0]) + int_ch2(sm[1]) + int_ch2(sm[2]) + int_ch2(sm[3]);  //更新向量
	}
	return ans;
}

// 显示函数
void show(vector<string>& text)
{
	for (auto t : text)
		cout << t;
	cout << endl;
}



// 行移位的逆操作函数
vector<string> in_ShiftRow(vector<string>& s)
{
	vector<string> ans = s;
	for (int i = 0; i < 4; ++i) {
		int k = i * 2;
		// 就原本矩阵对应的行移位，对于字符串数组就是列移位
		for (int j = 0; j < 4; ++j) {
			ans[j][k] = s[(j - i + 4) % 4][k];
			ans[j][k + 1] = s[(j - i + 4) % 4][k + 1];
		}
	}
	return ans;
}

// 逆S盒运算
string in_SubByte(string& wi_1)
{
	int len = (int)wi_1.length();
	string ans = "";
	for (int i = 0; i < len; i += 2) {
		// 获取当前的下标
		int x = ch_to_int(wi_1[i]), y = ch_to_int(wi_1[i + 1]);
		// 获取当前的数字
		int num = S1[x][y];
		// 将数值转化为字符串
		string s = int_to_chs(num);
		// 不足的话补0
		while (s.length() < 2)
			s = "0" + s;

		// 加起来
		ans += s;
	}
	return ans;
}


// 列混合的逆变换
vector<string> in_MixColumn(vector<string>& s)
{
	// 算法中对应的是列，在我的程序的存储结构中其实是行，即字符
	vector<string> ans = s;
	for (int i = 0; i < 4; i++) {  //step1
		int x[4], sm[4];
		auto temp = split_s(ans[i]);  //打断为4部分
		for (int j = 0; j < 4; j++)
			x[j] = (int)str_long(temp[j]);//x[j]对应ans[i][j]，为后续运算方便，将16进制字符转为数字
		for (int j = 0; j < 4; j++)  //step2
			sm[j] = x[(j + 1) % 4] ^ x[(j + 2) % 4] ^ x[(j + 3) % 4];//模1 0000 0000，保证是8bit
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
		ans[i] = int_ch2(sm[0]) + int_ch2(sm[1]) + int_ch2(sm[2]) + int_ch2(sm[3]);  //更新向量
	}
	return ans;
}