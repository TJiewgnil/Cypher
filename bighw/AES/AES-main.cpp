#include "AES.h"

int main()
{
	int op;
	while (1) {
		cout << "-----------------------------------------------------------------------" << endl;
		cout << "����AES����������0������AES����������1" << "   ��������������˳���" << endl;
		cin >> op;	// �����ʶ��
		if (cin.fail())
			break;
		cout << endl;
		if (op == 0 || op == 1) {
			string text, key;
			if (op == 0) {
				cout << "���������ģ����ȱ���Ϊ16�ֽڣ�" << "   ʾ����cryptography1234" << endl;
				cout << "����Ϊ��" << endl;//��Ӧ���ģ�8b0cde2e9c976648eae8b6cb7c23ccaf
			}
			else {
				cout << "���������ģ����ȱ���Ϊ32�ֽڣ�" << "   ʾ����4723a1eb685e0e1332561fdc8bd94ca4" << endl;
				cout << "��ʵ��������Ϊ16�ֽڣ�Ϊ����ʾ���ɼ��ַ�����ÿ���ֽ���16���Ʊ�ʾ,�ʳ��ȱ�Ϊ2����" << endl;
				cout << "����Ϊ��" << endl;//��Ӧ���ģ�ilovetaylorswift
			}
			
			cin >> text;
			cout << endl;

			cout << "��������Կ�����ȱ���Ϊ16���ַ���" << "   ʾ����8i39c5t2b97ja1bz" << endl;
			cout << "��ԿΪ��" << endl;
			cin >> key;

			cout << endl;

			// ���ݱ�ʶ�����������ܻ��ǽ���
			if (op == 0) {
				cout << "��ʵ��������Ϊ16�ֽڣ�Ϊ����ʾ���ɼ��ַ�����ÿ���ֽ���16���Ʊ�ʾ,�ʳ��ȱ�Ϊ2����" << endl;
				cout << "���ܽ��Ϊ��" << endl;
				aes(text, key);
			}
			else {
				cout << "���ܽ��Ϊ��" << endl;
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