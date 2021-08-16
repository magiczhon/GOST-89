// GOST-89.cpp: определяет точку входа для консольного приложения.
//

#include "stdafx.h"
#include "iostream"
#include <string>
#include <vector>
#include <algorithm>
#include <ctime>

using namespace std;

typedef uint8_t  u8;
typedef uint16_t u16;
typedef uint32_t u32;
typedef uint64_t u64;

static u8 s_box0[16] = { 0xC, 4, 6,	2, 0xA, 5, 0xB,	9, 0xE,	8, 0xD,	7, 0, 3, 0xF, 1 };
static u8 s_box1[16] = { 6,	8,	2,	3, 9, 0xA, 5, 0xC, 1, 0xE, 4, 7, 0xB, 0xD, 0, 0xF };
static u8 s_box2[16] = { 0xB, 3, 5,	8, 2, 0xF, 0xA, 0xD, 0xE, 1, 7,	4, 0xC,	9, 6, 0 };
static u8 s_box3[16] = { 0xC, 8, 2,	1, 0xD,	4, 0xF,	6, 7, 0, 0xA, 5, 3,	0xE, 9,	0xB };
static u8 s_box4[16] = { 7,	0xF, 5,	0xA, 8,	1, 6, 0xD, 0, 9, 3,	0xE, 0xB, 4, 2,	0xC };
static u8 s_box5[16] = { 5,	0xD, 0xF, 6, 9,	2, 0xC,	0xA, 0xB , 7, 8, 1,	4, 3, 0xE, 0 };
static u8 s_box6[16] = { 8,	0xE, 2,	5, 6, 9, 1,	0xC, 0xF, 4, 0xB, 0, 0xD, 0xA, 3, 7 };
static u8 s_box7[16] = { 1,	7, 0xE,	0xD, 0,	5 ,8 ,3 , 4, 0xF, 0xA, 6 , 9, 0xC, 0xB,	2 };

struct element_mem
{
	u32 key[8] = { 0, 0, 0, 0, 0, 0, 0, 0 };
	u64 text;
};

bool sorter(element_mem i, element_mem j)
{
	return i.text < j.text;
}


class magma
{
private:
	element_mem res;
	u32* round_key = new u32[32];
	void expand_key(u64*) const;
public:
	u32 t(u32);
	u32 g(u32, u32);
	u64 G(u64, u32);
	u64 GG(u64, u32);
	magma();
	~magma();
	u64 encrypt(u64, u64*);
	u64 decrypt(u64 o_text, u64* key_str);
	u64 decrypt_10_rounds(u64 o_text, u32* key_str);
	u64 dec_2_rounds(u64 e_text, u32 rkey1, u32 rkey2);
	u64 enc_2_rounds(u64 e_text, u32 rkey1, u32 rkey2);
	element_mem enc_3_rounds(u64 text, u32 rkey3, u32 rkey4, u32 rkey5);
	u64 dec_3_rounds(u64 text, u32 rkey8, u32 rkey7, u32 rkey6);
	static void print_key(u32* key);
	element_mem soglosovanie(u64 l_text, u64 r_text);
	u32* attack(u64 o_text, u64 e_text);
	u64 enc_10_rounds(u64 o_text, u32* key_str);
};

inline magma::magma()
{
	for (int i = 0;i < 32; i++)
		round_key[i] = 0;

	res.text = 0;
}

inline magma::~magma()
{
	delete round_key;
}

inline void magma::expand_key(u64* key) const
{
	round_key[7] = u32(key[0]);
	round_key[6] = u32(key[0] >> 32);
	round_key[5] = u32(key[1]);
	round_key[4] = u32(key[1] >> 32);
	round_key[3] = u32(key[2]);
	round_key[2] = u32(key[2] >> 32);
	round_key[1] = u32(key[3]);
	round_key[0] = u32(key[3] >> 32);

	for (int i = 0; i < 8; i++)
	{
		round_key[i + 8] = round_key[i];
		round_key[i + 16] = round_key[i];
		round_key[i + 24] = round_key[7 - i];
	}
}

inline u32 magma::t(u32 a)
{
	u8 a7 = (a >> 28) & 0xf;
	u8 a6 = (a >> 24) & 0xf;
	u8 a5 = (a >> 20) & 0xf;
	u8 a4 = (a >> 16) & 0xf;
	u8 a3 = (a >> 12) & 0xf;
	u8 a2 = (a >> 8) & 0xf;
	u8 a1 = (a >> 4) & 0xf;
	u8 a0 = a & 0xf;

	a7 = s_box7[a7];
	a6 = s_box6[a6];
	a5 = s_box5[a5];
	a4 = s_box4[a4];
	a3 = s_box3[a3];
	a2 = s_box2[a2];
	a1 = s_box1[a1];
	a0 = s_box0[a0];

	u32 res;

	res = (a7 << 28) ^
		(a6 << 24) ^
		(a5 << 20) ^
		(a4 << 16) ^
		(a3 << 12) ^
		(a2 << 8) ^
		(a1 << 4) ^
		a0;

	return res;
}

inline u32 magma::g(u32 a, u32 k)
{
	u32 res = t(a + k);

	return (res << 11) ^ ((res & 0xFFE00000) >> 21);
}

inline u64 magma::G(u64 a, u32 k)
{
	u32 a_1_value = a >> 32;
	u32 a_0_value = u32(a);
	u64 temp = (u64(a_0_value) << 32) ^ u64(g(a_0_value, k) ^ a_1_value);

	return temp;
}

inline u64 magma::GG(u64 a, u32 k)
{
	u32 a_1_value = a >> 32;
	u32 a_0_value = u32(a);

	return (u64(g(a_0_value, k) ^ a_1_value) << 32) ^ u64(a_0_value);
}

inline u64 magma::encrypt(u64 o_text, u64* key_str)
{
	expand_key(key_str);

	for (int i = 0; i < 31; i++)
		o_text = G(o_text, round_key[i]);

	return GG(o_text, round_key[31]);
}

inline u64 magma::enc_10_rounds(u64 o_text, u32* key)
{

	for (int i = 0; i < 9; i++) 
	{
		cout << "e_text_key" << i << " = " << o_text << endl << "rkey" << i % 8 << " = " << key[i] << endl;
		o_text = G(o_text, key[i]);
	}

	return GG(o_text, key[9]);
}

inline u64 magma::decrypt(u64 o_text, u64* key_str)
{
	expand_key(key_str);


	for (int i = 31; i > 0; i--)
		o_text = G(o_text, round_key[i]);

	return GG(o_text, round_key[0]);
}

inline u64 magma::decrypt_10_rounds(u64 o_text, u32* key)
{

	for (int i = 9; i > 0; i--)
	{
		cout << "d_text_key" << i << " = " << o_text << endl << "rkey"<<i%8<<" = " << key[i] << endl;

		o_text = G(o_text, key[i]);
	}

	return GG(o_text, key[0]);
}

inline u64 magma::dec_2_rounds(u64 e_text, u32 rkey1, u32 rkey2)
{
	e_text = G(e_text, rkey2);
	e_text = G(e_text, rkey1);
	return e_text;
}

inline u64 magma::enc_2_rounds(u64 o_text, u32 rkey1, u32 rkey2)
{
	o_text = G(o_text, rkey1);
	o_text = G(o_text, rkey2);
	return o_text;
}


inline element_mem magma::enc_3_rounds(u64 text, u32 rkey3, u32 rkey4, u32 rkey5)
{
	
	text = G(text, rkey3);

	text = G(text, rkey4);
	
	text = G(text, rkey5);

	element_mem el;
	el.text = text;
	el.key[2] = rkey3;
	el.key[3] = rkey4;
	el.key[4] = rkey5;

	return el;
}

inline u64 magma::dec_3_rounds(u64 text, u32 rkey6, u32 rkey7, u32 rkey8)
{
	text = G(text, rkey8);
	text = G(text, rkey7);
	text = GG(text, rkey6);
	return text;
	
}


void magma::print_key(u32* key)
{
	for (int i = 0; i < 8; i++)
		std::cout << std::hex << key[i] << "  ";

	std::cout << std::endl;
}


int main()
{
	/*u64* key = new u64[4];
	key[3] = 0xffeeddccbbaa9988;
	key[2] = 0x7766554433221100;
	key[1] = 0xf0f1f2f3f4f5f6f7;
	key[0] = 0xf8f9fafbfcfdfeff;
	u64 o_text = 0xfedcba9876543210;*/

	u32 key[10] = { 0x20, 0x200000, 0x8000, 0x1000, 0x2000, 0x80000000, 0x1, 0x1000000, 0x20, 0x200000 };
	u64 o_text = 0x30039264721aab12;
	u64 e_text = 0x756abf3a2b4f5f97;
	u32* keys;
	magma alg{};

	if (keys == nullptr)
	{
		cout << "ERROR!!!" << endl;
		exit(0);
	}
	
	for (int i = 0; i < 8; i++)
		key[i] = keys[i];
	key[8] = keys[0];
	key[9] = keys[1];
	

	e_text = alg.enc_10_rounds(o_text, key);
	std::cout << std::hex << "enc = " << e_text << std::endl << endl;
	o_text = alg.decrypt_10_rounds(e_text, key);

	std::cout << std::hex << "dec = " << o_text << std::endl;
	
	/*e_text = alg.encrypt(o_text, key);

	std::cout << std::hex << "enc = " << e_text << std::endl;

	o_text = alg.decrypt(e_text, key);

	std::cout << std::hex << "dec = " << o_text << std::endl;
*/
	

    return 0;
}

