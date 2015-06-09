/*
	Paper: Searchable Encryption with Secure and Efficient Updates
	Scheme: seccurely updating index-based searchable encryption (SUISE)
 */

#define _CRT_SECURE_NO_WARNINGS

#include <hex.h>
#include <cmac.h>
#include <hmac.h>
#include "AES_RNG.h"

#include <string>
#include <iostream>
#include <cstdio>
#include <cstdlib>
#include <fstream>
#include <vector>
#include <algorithm>
#include <windows.h>
#include <iomanip>

#include <dirent.h>

#define KEY_LENGTH 16
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

inline wstring s2ws(const std::string& s)
{
	int len;
	int slength = (int)s.length() + 1;
	len = MultiByteToWideChar(CP_ACP, 0, s.c_str(), slength, 0, 0);
	std::wstring r(len, L'\0');
	MultiByteToWideChar(CP_ACP, 0, s.c_str(), slength, &r[0], len);
	return r;
}

class SUISE
{
public:
	void client_gen()
	{
		memset(k1, 'K', KEY_LENGTH);
		//memset(k2, 'k', KEY_LENGTH);
		cout << "**** Client generate a key k1 (and pass a empty search index to server) ****" << endl;
	}

	void client_add_token() // read ALL list file in ./Client/List and generate add token to ./Comm/AddToken
	{
		/* Mapping Index File to Memory */
		string list_path = "./Client/List/Forward_Index.list";
		wstring w_list_path = s2ws(list_path);

		// 打開文件 for list index
		HANDLE list_fileH = CreateFile(w_list_path.c_str(),
			GENERIC_READ | GENERIC_WRITE,
			FILE_SHARE_READ,
			NULL,
			OPEN_EXISTING,
			FILE_ATTRIBUTE_NORMAL,
			NULL);
		if (list_fileH == INVALID_HANDLE_VALUE)
		{
			cerr << "Error: CreateFile() for " << list_path << endl;
			system("PAUSE");
			return;
		}
		else
		{
			cout << "Open file: " << list_path << endl;
		}
		int list_size = GetFileSize(list_fileH, NULL); // get the file size

		// 創建文件映射內核對象
		HANDLE list_mapFileH = CreateFileMapping(list_fileH,
			NULL,
			PAGE_READWRITE,
			0,
			0,
			NULL);
		if (list_mapFileH == NULL)
		{
			cerr << "Error: CreateFileMapping() for " << list_path << endl;
			system("PAUSE");
			return;
		}

		// 將文件數據映射到進程地址空間
		char *list_mapH = (char *)MapViewOfFile(list_mapFileH,
			FILE_MAP_ALL_ACCESS,
			0,
			0,
			0);
		if (list_mapH == NULL)
		{
			cerr << "Error: MapViewOfFile() for " << list_path << endl;
			system("PAUSE");
			return;
		}

		// 設定存取指標
		char *list_ptr = list_mapH;
		/*
		for (int i = 0; i < list_size; i++)
		{
			cout << list_ptr[i];
		}
		*/
		/* Mapping Index File to Memory */
		
		string buf, file_ID, keyword;
		int buf_head = 0, buf_end, buf_size;
		int keyword_head, keyword_end;

		string c; // cipher encrypted by HMAC_SHA_256 with reandom number s
		string s; // random number generated by AES_256_PRNG
		string token, token_hex; // token_hex for show and file name
		vector<string> x_list; // for store the search token was used for previous search
		vector<string> c_bar; //for store cipher

		fstream file_obj, log_file;
		string path, log_path = "./client_add_token_log.txt";

		int keyword_number = 0, token_number = 0; // for AddTokenHeader
		struct AddTokenHeader token_header;

		log_file.open(log_path, ios::out | ios::app);
		cout << "Create a log file: " << log_path << endl;
		if (!log_file)
			cerr << "Error: create log file " << log_path << " failed..." << endl;
		
		for (int i = 0; i < list_size; i++)
		{
			//cout << list_ptr[i];
			if (list_ptr[i] == '\n') // buf裡的內容相當於getline得到的內容
			{
				buf_end = i;
				buf.assign(list_ptr + buf_head, buf_end - buf_head);
				buf_head = i + 1;
				//cout << buf << endl; // show the content in buf
				buf_size = buf.size();

				x_list.clear();
				c_bar.clear();

				for (int j = 0; j < buf_size; j++)
				{
					if (buf[j] == ':') // read file ID from list
					{
						file_ID.assign(buf.c_str(), j);
						//cout << file_ID << endl; // show the file ID
						
						keyword_head = j + 1;

						for (int k = keyword_head; k < buf_size; k++) // read keyword from list
						{
							if (buf[k] == 32) // 32 is SPACE in ASCII
							{
								keyword_end = k;
								keyword.assign(buf.c_str() + keyword_head, keyword_end - keyword_head);
								keyword_head = keyword_end + 1;
								//cout << keyword << endl; // show the keyword
								
								/* code above can get each keyword and store at string keyword */

								if (keyword.size() <= MAX_KEYWORD_LENGTH)
								{
									token = CMAC_AES_128(k1, KEY_LENGTH, keyword);
									token_hex.assign(hex_encoder(token));
									//cout << token_hex << endl; // show the token

									path = "./Client/History/" + token_hex;
									file_obj.open(path, ios::in | ios::binary);
									if (file_obj)
									{
										token_number++;
										file_obj.close();
										x_list.push_back(token);
										x_list.shrink_to_fit(); // for redurce memory use
									}

									s = AES_256_PRNG();
									c = HMAC_SHA_256((byte*)token.c_str(), token.size(), s);
									c = c + s;
									c_bar.push_back(c);
								}
							}
						}

						keyword_number = c_bar.size();

						c_bar.shrink_to_fit();
						x_list.shrink_to_fit();

						sort(c_bar.begin(), c_bar.end());

						//cout << "Keyword number: " << keyword_number << endl;
						log_file << "Keyword number: " << keyword_number << endl;
						token_header.keyword_number = keyword_number;
						//cout << "Token number: " << token_number << endl;
						log_file << "Token number: " << token_number << endl;
						token_header.token_number = token_number;

						/* Write token to file */
						token_header.file_ID = atoi(file_ID.c_str());
						path = "./Comm/AddToken/" + file_ID;
						//cout << "Generate add tokken: " << path << endl;
						log_file << "Generate add tokken: " << path << endl;
						file_obj.open(path, ios::out | ios::binary);
						if (!file_obj)
						{
							cerr << "Error: create add token file: " << path << " failed..." << endl;
							log_file << "Error: create add token file: " << path << " failed..." << endl;
						}
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

						//cout << endl;
						log_file << endl;

						break; // break after found ':' 
					}
				}
			}
		}
		log_file.close();

		UnmapViewOfFile(list_mapH);
		CloseHandle(list_mapFileH);
		CloseHandle(list_fileH);
	}

	void client_add_token(string list_file_name) // read specific list file in ./Client/List and generate add token to ./Comm/AddToken
	{
		string list_path = "./Client/List/";
		int start, end;
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


		path = list_path + list_file_name + ".list";
		file_obj.open(path, ios::in | ios::binary);
		if (!file_obj)
		{
			cerr << "Error: list file: " << path << " open failed..." << endl << endl;
		}
		else
		{
			/* Calculate file size (bytes) */
			file_obj.seekg(0, ios::end);
			length = file_obj.tellg(); // the size of the file
			file_obj.seekg(0, ios::beg);
			cout << "List file: " << path << " is " << length << " bytes." << endl;
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

			cout << "**** Please Enter the file ID for " << path << " ****" << endl << ">>";
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

	void server_add()
	{
		DIR *dp;
		struct dirent *ep;
		string token_path = "./Comm/AddToken/";

		fstream log_file;
		string log_path = "./server_add_log.txt";
		cout << "Create a log file: " << log_path << endl;
		log_file.open(log_path, ios::out | ios::app);
		if (!log_file)
			cerr << "Error: create log file " << log_path << " failed..." << endl;

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
			log_file << "**** We have " << token_number << " add token ****" << endl;

			rewinddir(dp);
			readdir(dp); // .
			readdir(dp); // ..

			while (ep = readdir(dp))
			{
				//printf("Add token file: %s\n", ep->d_name);
				log_file << "Add token file: " << ep->d_name << endl;

				path.clear();
				path = token_path + path.assign(ep->d_name);
				file_obj.open(path, ios::in | ios::binary);
				if (!file_obj)
				{
					cerr << "Error: open add token file: " << path << " failed..." << endl;
					log_file << "Error: open add token file: " << path << " failed..." << endl;
				}
				else
				{
					file_obj.read((char*)&token_header, sizeof(token_header));
					//cout << "                   File ID: " << token_header.file_ID << endl;
					//cout << "     The number of keyword: " << token_header.keyword_number << endl;
					//cout << "The number of search token: " << token_header.token_number << endl;
					log_file << "                   File ID: " << token_header.file_ID << endl;
					log_file << "     The number of keyword: " << token_header.keyword_number << endl;
					log_file << "The number of search token: " << token_header.token_number << endl;

					/* Build Regular Index */
					memset(buf, 0, CIPHER_LENGTH);
					index_path = "./Server/RegularIndex/R_" + to_string(token_header.file_ID);
					//cout << "Generate regular index: " << index_path << endl;
					log_file << "Generate regular index: " << index_path << endl;
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
						//cout << "Open invert index file: " << index_path << endl;
						log_file << "Open invert index file: " << index_path << endl;
						index_file.open(index_path, ios::out | ios::in | ios::binary);
						if (!index_file)
						{
							index_file.open(index_path, ios::out | ios::binary);
							if (!index_file)
							{
								cerr << "Error: open failed..." << endl;
								log_file << "Error: open failed..." << endl;
								continue;
							}
						}
						index_file.seekp(0, index_file.end);

						//cout << "Add file ID: " << token_header.file_ID << " to the index" << endl;
						log_file << "Add file ID: " << token_header.file_ID << " to the index" << endl;
						index_file.write((char*)&token_header.file_ID, sizeof(token_header.file_ID));
						//index_file << '\n';
						index_file.close();
					}
					/* Build Invert Index */

					file_obj.close();
					if (remove(path.c_str()) != 0)
					{
						cerr << "Error: delete add token: " << path << " failed..." << endl;
						log_file << "Error: delete add token: " << path << " failed..." << endl;
					}
				}
				//cout << endl;
				log_file << endl;
			}
		}

	}

	string clien_search_token(string keyword)
	{
		fstream log_file;
		string log_path = "./client_search_token_log.txt";
		//cout << "Create a log file: " << log_path << endl;
		log_file.open(log_path, ios::out | ios::app);
		if (!log_file)
			cerr << "Error: create log file " << log_path << " failed..." << endl;

		string token = CMAC_AES_128(k1, KEY_LENGTH, keyword);
		fstream file_h; // search history
		string h_path = "./Client/History/";
		h_path.append(hex_encoder(token));
		//cout << "**** Generate a search token and stroe search histroy: " << h_path << " ****" << endl << endl;
		log_file << "**** Generate a search token and stroe search histroy: " << h_path << " ****" << endl << endl;
		file_h.open(h_path, ios::out | ios::binary);
		if (!file_h)
		{
			cerr << "Error: create search history file failed..." << endl;
			log_file << "Error: create search history file failed..." << endl;
		}
		file_h.close();
		return token;
	}

	void server_search(string search_token)
	{
		fstream index_file;
		string index_path;
		string hex_token = hex_encoder(search_token);
		int ID_buf;

		fstream log_file;
		string log_path = "./SUISE_Search_Result.txt";

		log_file.open(log_path, ios::out | ios::app);
		//cout << "Create a log file: " << log_path << endl;
		if (!log_file)
			cerr << "Error: create log file " << log_path << " failed..." << endl;

		index_path = "./Server/InvertIndex/I_" + hex_token;
		index_file.open(index_path, ios::in | ios::binary);
		if (index_file)
		{
			//cout << "Found invert index file: " << index_path << endl << endl;
			//log_file << "Found invert index file: " << index_path << endl << endl;
			//cout << "**** Search Result ****" << endl;
			log_file << "**** Search Result ****" << endl;
			log_file << "for token: " << hex_token << endl;
			while (index_file.read((char*)&ID_buf, sizeof(ID_buf)))
			{
				//cout << "File ID: " << ID_buf << endl;
				log_file << "File ID: " << ID_buf << endl;
			}
			index_file.close();
			//cout << "***********************" << endl;
			log_file << "***********************" << endl << endl;
		}
		else
		{
			DIR *dp;
			struct dirent *ep;
			string cipher_path = "./Server/RegularIndex/";

			dp = opendir(cipher_path.c_str());
			if (dp != NULL)
			{
				fstream index_file;
				string index_path;

				char buf[CIPHER_LENGTH / 2];
				string l, r, temp; // l: 密文前半段, r:密文後半段(random number)
				vector<int> I; // the set of file ID including the keyword;
				
				string file_name;

				readdir(dp); // .
				readdir(dp); // ..
				while (ep = readdir(dp))
				{
					//printf("Search on: %s\n", ep->d_name);
					//log_file << "Search on: " << ep->d_name << endl;
					file_name.assign(ep->d_name);
					ID_buf = stoi(file_name.substr(2));
					//cout << "File ID: " << ID_buf << endl;

					index_path = cipher_path;
					index_path.append(ep->d_name);
					index_file.open(index_path, ios::in | ios::binary);
					if (!index_file)
					{
						cerr << "Error: open regular index file: " << index_path << " failed..." << endl;
						log_file << "Error: open regular index file: " << index_path << " failed..." << endl;
						continue;
					}

					while (index_file.read(buf, CIPHER_LENGTH / 2)) // 讀取前半段
					{
						l.assign(buf, CIPHER_LENGTH / 2);

						index_file.read(buf, CIPHER_LENGTH / 2); // 讀取後半段
						r.assign(buf, CIPHER_LENGTH / 2);

						temp = HMAC_SHA_256((byte*)search_token.c_str(), search_token.size(), r);
						if (temp.compare(l) == 0)
						{
							//cout << "	Got it!" << endl;
							I.push_back(ID_buf);
						}
					}

					index_file.close();
				}

				if (I.size() != 0)
				{
					/* Build Invert Index */
					index_path = "./Server/InvertIndex/I_";
					index_path.append(hex_encoder(search_token));
					//cout << "Create invert index file: " << index_path << endl;
					//log_file << "Create invert index file: " << index_path << endl;
					index_file.open(index_path, ios::out | ios::binary);
					if (!index_file)
					{
						cerr << "Error: open failed..." << endl;
						log_file << "Error: open failed..." << endl;
					}
					else
					{

						for (int i = 0; i < I.size(); i++)
						{
							//cout << "Add file ID: " << I[i] << " to the index" << endl;
							//log_file << "Add file ID: " << I[i] << " to the index" << endl;
							ID_buf = I[i];
							index_file.write((char*)&ID_buf, sizeof(ID_buf));
						}
						index_file.close();
					}
					/* Build Invert Index */

					/* Show the search result */
					//cout << "**** Search Result ****" << endl;
					log_file << "**** Search Result ****" << endl;
					log_file << "for token: " << hex_token << endl;
					for (int i = 0; i < I.size(); i++)
					{
						//cout << "File ID: " << I[i] << endl;
						log_file << "File ID: " << I[i] << endl;
					}
					//cout << "***********************" << endl;
					log_file << "***********************" << endl << endl;
					/* Show the search result */
				}
				else
				{
					//cout << "**** Search Result ****" << endl;
					//cout << "!!	NOT FOUND	!!" << endl;
					//cout << "***********************" << endl;
					log_file << "**** Search Result ****" << endl;
					log_file << "for token: " << hex_token << endl;
					log_file << "!!	NOT FOUND	!!" << endl;
					log_file << "***********************" << endl << endl;
				}
			}
		}
		log_file.close();
	}

	void server_delete(int file_ID)
	{
		fstream log_file;
		string log_path = "./server_delete_log.txt";

		log_file.open(log_path, ios::out | ios::app);
		cout << "Create a log file: " << log_path << endl;
		if (!log_file)
			cerr << "Error: create log file " << log_path << " failed..." << endl;


		//cout << "**** The file ID: " << file_ID << " on server will be deleted ****" << endl;
		log_file << "**** The file ID: " << file_ID << " on server will be deleted ****" << endl;
		
		/* Delete from regular index */
		string file_path = "./Server/RegularIndex/R_" + to_string(file_ID);
		//cout << "**** Delete " << file_path << " ****" << endl;
		log_file << "**** Delete " << file_path << " ****" << endl;
		if (remove(file_path.c_str()) != 0)
		{
			cerr << "Error: Delete: " << file_path << " failed..." << endl;
			log_file << "Error: Delete: " << file_path << " failed..." << endl;
		}
		/* Delete from regular index */

		/* Delete from invert index */
		DIR *dp;
		struct dirent *ep;
		string cipher_path = "./Server/InvertIndex/";

		dp = opendir(cipher_path.c_str());
		if (dp != NULL)
		{
			fstream index_file;
			string index_path;

			int ID_buf;
			vector<int> new_ID_list;
			int renew;

			readdir(dp); // .
			readdir(dp); // ..
			while (ep = readdir(dp))
			{
				new_ID_list.clear();
				renew = 0;
				index_path = "./Server/InvertIndex/";
				index_path.append(ep->d_name);
				//cout << "Search file ID on: " << index_path << endl;
				log_file << "Search file ID on: " << index_path << endl;
				index_file.open(index_path, ios::in | ios::binary);
				if (!index_file)
				{
					cerr << "Error: open " << index_path << " failed..." << endl;
					log_file << "Error: open " << index_path << " failed..." << endl;
					continue;
				}
				while (index_file.read((char*)&ID_buf, sizeof(ID_buf)))
				{
					if (ID_buf == file_ID)
					{
						//cout << "**** Find file ID in index: " << index_path << " ****" << endl;
						log_file << "**** Find file ID in index: " << index_path << " ****" << endl;
						renew = 1;
					}
					else
					{
						new_ID_list.push_back(ID_buf);
					}
				}
				index_file.close();

				if (renew == 1)
				{
					//cout << "**** Update invert index: " << index_path << " ****" << endl;
					log_file << "**** Update invert index: " << index_path << " ****" << endl;
					index_file.open(index_path, ios::out | ios::trunc | ios::binary);
					if (!index_file)
					{
						cerr << "Error: update " << index_path << " failed..." << endl;
						log_file << "Error: update " << index_path << " failed..." << endl;
					}
					else
					{
						for (int i = 0; i < new_ID_list.size(); i++)
						{
							ID_buf = new_ID_list[i];
							index_file.write((char*)&ID_buf, sizeof(ID_buf));
						}
						index_file.close();
					}
				}
				else
				{
					//cout << "**** Do not need to update ****" << endl;
					log_file << "**** Do not need to update ****" << endl;
				}
			}
		}
		/* Delete from invert index */
		log_file.close();
	}

	private:
		byte k1[KEY_LENGTH];
		//byte k2[KEY_LENGTH];
};


int main()
{
	cout << "**** Clear old search history, add token at client, and index on server ****" << endl;
	//system("Clear.bat");
	cout << "****************************************************************************" << endl << endl;

	SUISE SUISE_obj;
	SUISE_obj.client_gen();
	
	int opcode, file_ID, mode;
	string file_name, keyword, search_token;

	fstream log_file, test_file;
	log_file.open("./SUISE_Log.txt", ios::out);

	LARGE_INTEGER startTime, endTime, fre;
	double times;
	
	cout << "Do you want to enter testing mode?" << endl;
	cout << "	0 = Yes, other = No" << endl << ">>";
	cin >> mode;
	if (mode == 0)
	{
		cout << "**** Testing Mode ****" << endl;
		cout << "	8: search testing" << endl;
		cout << "	9: delete testing" << endl;
		cout << ">>";
		cin >> opcode;
		int test_time;
		string file_ID_str;
		cout << "Enter testing times" << endl << ">>";
		cin >> test_time;

		if (opcode == 8)
		{
			test_file.open("./Test/Search.txt");
		}
		else if (opcode == 9)
		{
			test_file.open("./Test/Delete.txt");
		}

		for (int i = 0; i < test_time; i++)
		{
			if (opcode == 8)
			{
				getline(test_file, keyword);
				cout << keyword << endl;
				//cout << "Load keyword" << endl << ">>";
				//cin >> keyword;
			}
			else if (opcode == 9)
			{
				getline(test_file, file_ID_str);
				file_ID = atoi(file_ID_str.c_str());
				cout << file_ID << endl;
				//cout << "Load file ID" << endl << ">>";
				//cin >> file_ID;
			}
			
			QueryPerformanceFrequency(&fre); // 取得CPU頻率
			QueryPerformanceCounter(&startTime); // 取得開機到現在經過幾個CPU Cycle
			/* Program to Timing */
			switch (opcode)
			{

			case 8: // for testing search
				//cin >> keyword;
				search_token = SUISE_obj.clien_search_token(keyword);
				log_file << "Client search token generation" << endl;
				log_file << "	Token for: " << keyword << endl;

				SUISE_obj.server_search(search_token);
				log_file << "Server search operation" << endl;
				break;

			case 9: // for testing delete
				//cin >> file_ID;
				SUISE_obj.server_delete(file_ID);
				log_file << "Server delete operation" << endl;
				break;

			default:
				cout << "Opcode is incorrect..." << endl;
			}

			/* Program to Timing */
			QueryPerformanceCounter(&endTime); // 取得開機到程式執行完成經過幾個CPU Cycle
			times = ((double)endTime.QuadPart - (double)startTime.QuadPart) / fre.QuadPart;
			cout << fixed << setprecision(3) << "Processing time: " << times << 's' << endl << endl;
			log_file << fixed << setprecision(3) << "Processing time: " << times << 's' << endl << endl;
		}
		test_file.close();
		system("PAUSE");
	}
	else
	{
		cout << "**** Normal Mode ****" << endl;

		cout << endl << "Enter OP code:" << endl;
		cout << "	For client:" << endl;
		cout << "		0: Generate add token for ALL list" << endl;
		cout << "		1: Generate a add token for a specific list" << endl;
		cout << "		2: Generate a search token foa a keyword" << endl;
		cout << "	For server:" << endl;
		cout << "		3: Add file for ALL add token" << endl;
		cout << "		4: Keyword search with the search token produced by function 2" << endl;
		cout << "		5: Add a file for a specific add token (not yet)" << endl;
		cout << "		6: Delete a file" << endl;
		cout << "	Ctrl + Z: Exit" << endl;
		cout << ">>";

		while (cin >> opcode)
		{
			QueryPerformanceFrequency(&fre); // 取得CPU頻率
			QueryPerformanceCounter(&startTime); // 取得開機到現在經過幾個CPU Cycle
			/* Program to Timing */
			switch (opcode)
			{
			case 0:
				SUISE_obj.client_add_token();
				log_file << "Client add token generation" << endl;
				break;

			case 1:
				cout << "Enter a list file name you want to add:" << endl << ">>";
				cin >> file_name;
				SUISE_obj.client_add_token(file_name);
				break;

			case 2:
				cout << "Enter a keyword you want to search:" << endl << ">>";
				cin >> keyword;
				search_token = SUISE_obj.clien_search_token(keyword);
				log_file << "Client search token generation" << endl;
				break;

			case 3:
				SUISE_obj.server_add();
				log_file << "Server add operation" << endl;
				break;

			case 4:
				SUISE_obj.server_search(search_token);
				log_file << "Server search operation" << endl;
				break;

			case 5:

				break;

			case 6:
				cout << "Enter a fie ID you want to delete:" << endl << ">>";
				cin >> file_ID;
				SUISE_obj.server_delete(file_ID);
				log_file << "Server delete operation" << endl;
				break;

			default:
				cout << "Opcode is incorrect..." << endl;
			}

			/* Program to Timing */
			QueryPerformanceCounter(&endTime); // 取得開機到程式執行完成經過幾個CPU Cycle
			times = ((double)endTime.QuadPart - (double)startTime.QuadPart) / fre.QuadPart;
			cout << fixed << setprecision(3) << "Processing time: " << times << 's' << endl << endl;
			log_file << fixed << setprecision(3) << "Processing time: " << times << 's' << endl << endl;

			cout << endl << "Enter OP code:" << endl;
			cout << "	For client:" << endl;
			cout << "		0: Generate add token for ALL list" << endl;
			cout << "		1: Generate a add token for a specific list" << endl;
			cout << "		2: Generate a search token foa a keyword" << endl;
			cout << "	For server:" << endl;
			cout << "		3: Add file for ALL add token" << endl;
			cout << "		4: Keyword search with the search token produced by function 2" << endl;
			cout << "		5: Add a file for a specific add token (not yet)" << endl;
			cout << "		6: Delete a file" << endl;
			cout << "	Ctrl + Z: Exit" << endl;
			cout << ">>";
		}
	}

	log_file.close();

	return 0;
}