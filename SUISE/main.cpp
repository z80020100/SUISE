﻿/*
Paper: Searchable Encryption with Secure and Efficient Updates
Scheme: seccurely updating index-based searchable encryption (SUISE)
*/

#define _CRT_SECURE_NO_WARNINGS

#include <iostream>
#include <cstdio>
#include <fstream>
#include <vector>
#include <algorithm>

#include <hex.h>
#include <cmac.h>
#include <hmac.h>
#include "AES_RNG.h"

#include <dirent.h>

#define KEY_LENGTH 32
#define MAX_KEYWORD_LENGTH 32
#define SEARCH_TOKEN_LENGTH 16
#define CIPHER_LENGTH 64

#pragma comment(lib, "cryptlib.lib")

using namespace std;
using namespace CryptoPP;

struct AddTokenHeader
{
	int file_ID;
	int keyword_number;
	int token_number;
};

string AES_256_PRNG()
{
	SecByteBlock seed(32);
	OS_GenerateRandomBlock(false, seed, seed.size());

	AES_RNG prng(seed, seed.size());

	SecByteBlock t(32);
	prng.GenerateBlock(t, t.size());

	string s;
	HexEncoder hex(new StringSink(s));

	hex.Put(t, t.size());
	hex.MessageEnd();
	//cout << "Random: " << s << endl;

	string decoded;
	HexDecoder decoder;

	decoder.Put((byte*)s.data(), s.size());
	decoder.MessageEnd();

	word64 size = decoder.MaxRetrievable();
	if (size && size <= SIZE_MAX)
	{
		decoded.resize(size);
		decoder.Get((byte*)decoded.data(), decoded.size());
	}

	return decoded;
}

string CMAC_AES_128(byte *user_key, int user_key_len, string plain) // user_key_len must be equal to AES::DEFAULT_KEYLENGTH
{
	//byte user_key[16] = {0x00};
	SecByteBlock key(user_key, user_key_len);

	//string plain = "CMAC Test";
	string mac, encoded;

	/*
	// Pretty print key
	encoded.clear();
	StringSource ss1(key, key.size(), true,
	new HexEncoder(
	new StringSink(encoded)
	) // HexEncoder
	); // StringSource

	cout << "key: " << encoded << endl;
	cout << "plain text: " << plain << endl;
	*/

	try
	{
		CMAC< AES > cmac(key.data(), key.size());

		StringSource ss2(plain, true,
			new HashFilter(cmac,
			new StringSink(mac)
			) // HashFilter      
			); // StringSource
	}
	catch (const CryptoPP::Exception& e)
	{
		cerr << e.what() << endl;
		exit(1);
	}

	/*
	// Pretty print
	encoded.clear();
	StringSource ss3(mac, true,
	new HexEncoder(
	new StringSink(encoded)
	) // HexEncoder
	); // StringSource

	cout << "cmac: " << encoded << endl;
	*/

	return mac;
}

string HMAC_SHA_256(byte *user_key, int user_key_len, string plain)
{
	SecByteBlock key(user_key, user_key_len);
	string mac, encoded;

	/*
	// Pretty print key
	encoded.clear();
	StringSource ss1(key, key.size(), true,
	new HexEncoder(
	new StringSink(encoded)
	) // HexEncoder
	); // StringSource

	cout << "key: " << encoded << endl;
	cout << "plain text: " << plain << endl;
	*/

	try
	{
		HMAC< SHA256 > hmac(key, key.size());

		StringSource ss2(plain, true,
			new HashFilter(hmac,
			new StringSink(mac)
			) // HashFilter      
			); // StringSource
	}
	catch (const CryptoPP::Exception& e)
	{
		cerr << e.what() << endl;
		exit(1);
	}

	/*
	// Pretty print
	encoded.clear();
	StringSource ss3(mac, true,
	new HexEncoder(
	new StringSink(encoded)
	) // HexEncoder
	); // StringSource

	cout << "hmac: " << encoded << endl;
	*/

	return mac;
}

inline string hex_encoder(string raw)  // encode raw data to hex string data for showing
{
	string hex;
	StringSource ss2(raw, true,
		new HexEncoder(
		new StringSink(hex)
		) // HexEncoder
		); // StringSource
	return hex;
}

inline void string_to_byte(byte *b_text, string s_text, int b_text_len)
{
	memcpy((char*)b_text, s_text.c_str(), b_text_len);
}

class SUISE
{
public:
	void client_gen()
	{
		memset(k1, 'K', KEY_LENGTH);
		memset(k2, 'k', KEY_LENGTH);

		cout << "**** Client pass a empty search index to sercer ****" << endl;
	}

	void client_add_token() // read list file in ./Client/List and generate add token to ./Comm/AddToken
	{
		DIR *dp;
		struct dirent *ep;
		string list_path = "./Client/List/";
		
		dp = opendir(list_path.c_str()); // for each file f, create a list f_bar of unique keyword
		if (dp != NULL)
		{
			int list_number = 0, start, end;
			int length;
			char *buf = NULL;
			char keyword[MAX_KEYWORD_LENGTH];
			int keyword_length;
			string w; // keyword string
			string c; // cipher encrypted by HMAC_SHA_256 with reandom number s
			string s; // random number generated by AES_256_PRNG
			string token;
			string token_hex;
			vector<string> x_list; // for store the search token was used for previous search
			vector<string> c_bar; //for store cipher

			fstream file_obj;
			string path;
			
			int keyword_number = 0, token_number = 0; // for AddTokenHeader
			struct AddTokenHeader token_header;

			while (ep = readdir(dp)) // read the list file, the list file need to be UNIX format
			{
				//printf("%s\n", ep->d_name);
				list_number++;
			}
			list_number = list_number - 2; // 扣掉當前目錄和上層目錄
			cout << "**** We have " << list_number << " list ****" << endl;

			rewinddir(dp);
			readdir(dp); // .
			readdir(dp); // ..

			while (ep = readdir(dp))
			{
				keyword_number = 0;
				token_number = 0;
				x_list.clear();
				c_bar.clear();
				//printf("%s\n", ep->d_name);

				path.clear();
				path = list_path + path.assign(ep->d_name);
				file_obj.open(path, ios::in | ios::binary);
				if (!file_obj)
				{
					cerr << "List file: " << ep->d_name << " open failed..." << endl << endl;
					continue;
				}

				/* Calculate file size (bytes) */
				file_obj.seekg(0, ios::end);
				length = file_obj.tellg(); // the size of the file
				file_obj.seekg(0, ios::beg);
				cout << "List file: " << ep->d_name << " is " << length << " bytes." << endl;
				/* Calculate file size (bytes) */

				buf = new char[length];
				file_obj.read(buf, length);
				file_obj.close();

				/* Counte the number of keuyword */
				for (int i = 0; i < length; i++)
				{
					if (buf[i] == '\n')
					{
						keyword_number++;
					}
				}
				/* Counte the number of keyword */

				cout << "**** Please Enter the file ID for " << ep->d_name << " ****" << endl << ">>";
				cin >> token_header.file_ID;

				start = 0;
				for (int i = 0; i < length; i++)
				{
					if (buf[i] == '\n')
					{
						end = i;
						//cout << "DEBUG: start = " << start << endl;
						//cout << "DEBUG: end = " << end << endl;
						memset(keyword, 0, MAX_KEYWORD_LENGTH);
						keyword_length = end - start;
						if (keyword_length <= MAX_KEYWORD_LENGTH)
						{
							strncpy(keyword, &buf[start], keyword_length);
							//cout << keyword << endl;
							w.assign(keyword);
							//cout << w << endl;

							token = CMAC_AES_128(k1, KEY_LENGTH, keyword);
							token_hex.assign(hex_encoder(token));
							cout << token_hex << endl;
							
							path = "./Client/History/" + token_hex;
							file_obj.open(path, ios::in | ios::binary);
							if (file_obj)
							{
								token_number++;
								file_obj.close();
								x_list.push_back(token);
							}
							start = end + 1;

							s = AES_256_PRNG();
							c = HMAC_SHA_256((byte*)token.c_str(), token.size(), s);
							c = c + s;
							c_bar.push_back(c);
						}
					}
				}
				delete[] buf;

				sort(c_bar.begin(), c_bar.end());

				cout << "Keyword number: " << keyword_number << endl;
				token_header.keyword_number = keyword_number;
				cout << "Token number: " << token_number << endl;
				token_header.token_number = token_number;

				/* Write token to file */
				path = "./Comm/AddToken/" + to_string(token_header.file_ID);
				file_obj.open(path, ios::out | ios::binary);
				if (!file_obj)
					cerr << "Error: create add token file: " << path << " failed..." << endl;
				else
				{
					file_obj.write((char*)&token_header, sizeof(struct AddTokenHeader)); // write header

					for (int i = 0; i < c_bar.size(); i++)
					{
						file_obj << c_bar[i];
					}

					for (int i = 0; i < x_list.size(); i++)
					{
						file_obj << x_list[i];
					}

					file_obj.close();
				}
				/* Write token to file */

				cout << endl;
			}
		}
	}

	void server_add()
	{
		DIR *dp;
		struct dirent *ep;
		string token_path = "./Comm/AddToken/";

		dp = opendir(token_path.c_str());
		if (dp != NULL)
		{
			int token_number = 0;
			struct AddTokenHeader token_header;
			
			fstream file_obj, index_file;
			string path, index_path;

			char buf[CIPHER_LENGTH];
			string buf_str;

			while (ep = readdir(dp))
			{
				//printf("%s\n", ep->d_name);
				token_number++;
			}
			token_number = token_number - 2; // 扣掉當前目錄和上層目錄
			cout << "**** We have " << token_number << " add token ****" << endl;

			rewinddir(dp);
			readdir(dp); // .
			readdir(dp); // ..

			while (ep = readdir(dp))
			{
				printf("Add Token file: %s\n", ep->d_name);

				path.clear();
				path = token_path + path.assign(ep->d_name);
				file_obj.open(path, ios::in | ios::binary);
				if (!file_obj)
					cerr << "Error: open add token file: " << path << " failed..." << endl;
				else
				{
					file_obj.read((char*)&token_header, sizeof(token_header));
					cout << "                   File ID: " << token_header.file_ID << endl;
					cout << "     The number of keyword: " << token_header.keyword_number << endl;
					cout << "The number of search token: " << token_header.token_number << endl;

					/* Build Regular Index */
					memset(buf, 0, CIPHER_LENGTH);
					index_path = "./Server/RegularIndex/R_" + to_string(token_header.file_ID);
					index_file.open(index_path, ios::out | ios::binary);
					for (int i = 0; i < token_header.keyword_number; i++)
					{
						file_obj.read(buf, CIPHER_LENGTH);
						index_file.write(buf, CIPHER_LENGTH);
					}
					index_file.close();
					/* Build Regular Index */

					/* Build Invert Index */
					for (int i = 0; i < token_header.token_number; i++) // for each search token
					{
						memset(buf, 0, CIPHER_LENGTH);
						file_obj.read(buf, SEARCH_TOKEN_LENGTH);
						buf_str.assign(buf, SEARCH_TOKEN_LENGTH);
						index_path = "./Server/InvertIndex/I_";
						index_path.append(hex_encoder(buf_str));
						cout << "Open invert index file: " << index_path << endl;
						index_file.open(index_path, ios::out | ios::in | ios::binary);
						if (!index_file)
						{
							index_file.open(index_path, ios::out | ios::binary);
							if (!index_file)
							{
								cerr << "Error: open failed..." << endl;
								continue;
							}
						}
						index_file.seekp(0, index_file.end);

						cout << "Add file ID: " << token_header.file_ID << " to the index" << endl;
						index_file.write((char*)&token_header.file_ID, sizeof(token_header.file_ID));
						//index_file << '\n';
						index_file.close();
					}
					/* Build Invert Index */

					file_obj.close();
				}
				
				cout << endl;
			}
		}
	}

	void clien_search_token(string keyword)
	{
		string token = CMAC_AES_128(k1, KEY_LENGTH, keyword);
		fstream file_h; // search history
		string h_path = "./Client/History/";
		h_path.append(hex_encoder(token));
		cout << "**** Generate a search token and stroe search histroy: " << h_path << " ****" << endl;
		file_h.open(h_path, ios::out | ios::binary);
		if (!file_h)
			cerr << "Error: create search history file failed..." << endl;
	}

	void server_search(string search_token)
	{

	}

private:
	byte k1[KEY_LENGTH], k2[KEY_LENGTH];
};


int main()
{
	SUISE SUISE_obj;
	SUISE_obj.clien_search_token("w1");
	//SUISE_obj.clien_search_token("w2");
	SUISE_obj.client_add_token();
	SUISE_obj.server_add();

	system("PAUSE");
	return 0;
}