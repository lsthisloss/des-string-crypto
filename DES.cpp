#include <iostream>
#include <cstdlib>
#include <string>
#include <algorithm>
#include <vector>
#include "DES.h"

#define DEBUG 1

using namespace std;

DES::DES() {
    total_code = "";
    total_key = "";
    tempCode_1 = "";
    tempCode_2="";
    m_code = ""; 
    code = "";
    L = "";
    R = "";
    C = "";
    D = "";
}
DES::~DES(){}

void DES::encode(string text, string key) {
    total_code = text;
    total_key = key;
      
        if (DEBUG) {
            cout << "Get keys" << endl;
        }
        getKeys();
        if (DEBUG) {
            cout << "Format Source Code" << endl;
        }
        formatSourceCode();
        int count = 0;
        int s = total_code.size();
        while (count * 8 < s) {
            string sub;
            if (s - count * 8 >= 8) {
                sub = total_code.substr(count * 8, 8);
            }
            else {
                sub = total_code.substr(count * 8);
            }
            count++;
            fill(sub);
            if (DEBUG) {
                cout << "* Code length: " << tempCode_1.size() << endl;
            }
            if (DEBUG) {
                cout << "* IP_0" << endl;
            }
            getIP0();
            if (DEBUG) {
                cout << "* IterationT" << endl;
            }
            string a = iterationT_Encrypt(1, 16);
            if (DEBUG) {
                cout << "* IP_1" << endl;
            }
            string result = getIP_1(a);
            m_code += result;
            if (DEBUG) {
                cout << result.size() << endl;
            }
        }
        cout << m_code << endl;
    }
void DES::decode(string text, string key) {
        int count = 0;
        getKeys();
        while (count * 64 < text.size()) {
            tempCode_1 = text.substr(count * 64, 64);
            total_key = key;
            count++;
            if (DEBUG) {
                cout << "* K : " << endl;
                for (int i = 0; i < K.size(); i++) {
                    cout << K[i] << endl;
                }
                cout << "* IP_0" << endl;
            }
            getIP0();
            if (DEBUG) {
                cout << "* IterationT" << endl;
            }
            string a = iterationT_Decrypt(16, 1);
            if (DEBUG) {
                cout << "* IP_1" << endl;
            }
            string result = getIP_1(a);
            if (count * 64 == text.size()) {
                code += formatAndReduceResult(result);
            }
            else {
                code += formatResult(result);
            }
        }
        cout << code << endl;
    }
void DES::fill(string str) {
        tempCode_1 = "";
        for (int i = 0; i < 8; i++) {
            string s;
            int a = i < str.size() ? (int)str[i] : 8 - str.size();
            while (a > 0) {
                s = (char)(a % 2 + 48) + s;
                a /= 2;
            }
            while (s.size() < 8) {
                s = "0" + s;
            }
            tempCode_1 += s;
        }
        if (DEBUG) {
            cout << tempCode_1 << endl;
        }
    }
void DES::formatSourceCode() {
        if (total_code.size() % 8 == 0) {
            total_code += "\b\b\b\b\b\b\b\b";
        }
    }
void DES::getIP0() {
        tempCode_2 = tempCode_1;
        L = "";
        R = "";
        for (int i = 0; i < 64; i++) {
            tempCode_2[i] = tempCode_1[IP[i] - 1];
        }
        for (int i = 0; i < 64; i++) {
            if (i < 32) {
                L += tempCode_2[i];
            }
            else {
                R += tempCode_2[i];
            }
        }

        if (DEBUG) {
            cout << "* tempCode_2: " << tempCode_2 << endl;
            cout << "* L: " << L << endl;
            cout << "* R: " << R << endl;
        }
    }
string DES::feistel(string R, string K) {
        string res = "", rec = "";
        string ER = e_Expend(R);
        for (int i = 0; i < 48; i++) {
            res += (char)(((ER[i] - 48) ^ (K[i] - 48)) + 48);
        }
        cout << endl << "------------------------------------" << endl;
        cout << "* S_Box: " << endl;

        for (int i = 0; i < 8; i++) {
            string sub = res.substr(i * 6, 6);
            string sub_m = feistel_SBOX(sub, i);
            rec += sub_m;
        }
        if (DEBUG) {
            cout << "* Substring length: " << rec.size() << endl;
        }
        return getPTransform(rec);
    }
string DES::getPTransform(string str) {
        string res = "";
        for (int i = 0; i < 32; i++) {
            res += str[P_transform[i] - 1];
        }
        return res;
    }
string DES::feistel_SBOX(string str, int num) {
        int n = (str[0] - 48) * 2 + (str[5] - 48);
        int m = (str[1] - 48) * 8 + (str[2] - 48) * 4 + (str[3] - 48) * 2 + (str[4] - 48);
        int number = SBox[num][n][m];
        string res = "";
        while (number > 0) {
            res = (char)(number % 2 + 48) + res;
            number /= 2;
        }
        while (res.size() < 4) {
            res = "0" + res;
        }
        if (DEBUG) {

            cout << str << " " << num << " " << res << endl;

        }
        return res;
    }
string DES::e_Expend(string str) {
        string res = "";
        for (int i = 0; i < 48; i++) {
            res += str[E_exp[i] - 1];
        }
        if (DEBUG) {
            cout << "* E expend: " << res << endl;
        }
        return res;
    }
string DES::xor_Operation(string a, string b) {
        string res = "";
        for (int i = 0; i < 32; i++) {
            res += (char)(((a[i] - 48) ^ (b[i] - 48)) + 48);
        }
        return res;
    }
string DES::iterationT_Encrypt(int begin, int end) {
        string L_temp, R_temp;
        for (int i = begin - 1; i <= end - 1; i++) {
            L_temp = R;
            R_temp = xor_Operation(L, feistel(R, K[i]));
            L = L_temp;
            R = R_temp;
        }
        return R + L;
    }
string DES::iterationT_Decrypt(int begin, int end) {
        string L_temp, R_temp;
        for (int i = begin - 1; i >= end - 1; i--) {
            L_temp = R;
            R_temp = xor_Operation(L, feistel(R, K[i]));
            L = L_temp;
            R = R_temp;
        }
        return R + L;
    }
string DES::getIP_1(string str) {
        string res = "";
        for (int i = 0; i < 64; i++) {
            res += str[IP_1[i] - 1];
        }
        return res;
    }
string DES::formatResult(string str) {
        int count = 0;
        string res = "";
        while (count * 8 < str.size()) {
            string a = str.substr(count * 8, 8);
            res += (char)(Two2Ten(a));
            count++;
        }
        return res;
    }
string DES::formatAndReduceResult(string str) {
        int count = 0;
        string res = "";
        string a = str.substr(str.size() - 8, 8);
        int n = (int)(Two2Ten(a));
        if (DEBUG) {
            cout << a << endl;
            cout << n << endl;
        }
        while (count < 8 - n) {
            a = str.substr(count * 8, 8);
            res += (char)(Two2Ten(a));
            count++;
        }
        return res;
    }
int DES::Two2Ten(string num) {
        int base = 1;
        int res = 0;
        for (int i = num.size() - 1; i >= 0; i--) {
            res += (int)(num[i] - 48) * base;
            base *= 2;
        }
        return res;
    }
string DES::formatKey() {
        string res = "", rec = "";
        for (int i = 0; i < 8; i++) {
            int num = (int)total_key[i];
            res = "";
            while (num > 0) {
                res = (char)(num % 2 + 48) + res;
                num /= 2;
            }
            while (res.size() < 8) {
                res = "0" + res;
            }
            rec += res;
        }
        if (DEBUG) {
            cout << "* Rec: " << rec << endl;
        }
        return rec;
    }
string DES::getPC1Key(string str) {
        string res = str;
        for (int i = 0; i < 56; i++) {
            res[i] = str[PC_1[i] - 1];
        }
        if (DEBUG) {
            cout << "* Res: " << res << endl;
        }
        return res;
    }
void DES::get_C_D(string str) {
        C = "";
        D = "";
        str.erase(63, 1);
        str.erase(55, 1);
        str.erase(47, 1);
        str.erase(39, 1);
        str.erase(31, 1);
        str.erase(23, 1);
        str.erase(15, 1);
        str.erase(7, 1);
        for (int i = 0; i < str.size(); i++) {
            if (i < 28) {
                C += str[i];
            }
            else {
                D += str[i];
            }
        }
        if (DEBUG) {
            cout << "* C: " << C << endl;
            cout << "* D: " << D << endl;
        }
    }
void DES::getKeyI() {
        for (int i = 1; i <= 16; i++) {
            if (i == 1 || i == 2 || i == 9 || i == 16) {
                LS_1(C);
                LS_1(D);
            }
            else {
                LS_2(C);
                LS_2(D);
            }
            string t = C + D;
            t = getPC2Key(t);
            K.push_back(t);
        }
    }
void DES::LS_1(string& str) {
        char a = str[0];
        for (int i = 0; i < str.size() - 1; i++) {
            str[i] = str[i + 1];
        }
        str[str.size() - 1] = a;
    }
void DES::LS_2(string& str) {
        char a = str[0], b = str[1];
        for (int i = 0; i < str.size() - 2; i++) {
            str[i] = str[i + 2];
        }
        str[str.size() - 2] = a;
        str[str.size() - 1] = b;
    }
string DES::getPC2Key(string str) {
        string res = str;
        for (int i = 0; i < 48; i++) {
            res[i] = str[PC_2[i] - 1];
        }
        res.erase(53, 1);
        res.erase(42, 1);
        res.erase(37, 1);
        res.erase(34, 1);
        res.erase(24, 1);
        res.erase(21, 1);
        res.erase(17, 1);
        res.erase(8, 1);
        return res;
    }
void DES::getKeys() {
        vector<string> t;
        K = t;
        string a = formatKey();
        a = getPC1Key(a);
        get_C_D(a);
        getKeyI();
    }


int main() {
    DES desObj;
    string text, key;
    cout << "text: ";
    cin >> text;
    cout << "key: ";
    cin >> key;

    cout << endl << "------------------------------------" << endl;
    cout << "Encoded result:" << endl;
    desObj.encode(text, key);
    cout << endl << "------------------------------------" << endl;
    cout << "To decode, enter ciphertext: ";
    cin >> text;
    cout << "Key: ";
    cin >> key;
    cout << endl << "------------------------------------" << endl;
    cout << "Decoded result:" << endl;   
    desObj.decode(text, key);
    return 0;
}