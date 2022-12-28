#include <fstream>
#include "openssl/rsa.h"
#include "openssl/pem.h"
#include "openssl/err.h"

#define KEY_LENGTH  2048             // ��Կ����
#define PUB_KEY_FILE "pubkey.pem"    // ��Կ·��
#define PRI_KEY_FILE "prikey.pem"    // ˽Կ·��

/*
������Կ�ԣ�˽Կ�͹�Կ
**/
void GenerateRSAKey(std::string& out_pub_key, std::string& out_pri_key)
{
	size_t pri_len = 0; // ˽Կ����
	size_t pub_len = 0; // ��Կ����
	char* pri_key = nullptr; // ˽Կ
	char* pub_key = nullptr; // ��Կ

	// ������Կ��
	RSA* keypair = RSA_generate_key(KEY_LENGTH, RSA_3, NULL, NULL);

	BIO* pri = BIO_new(BIO_s_mem());
	BIO* pub = BIO_new(BIO_s_mem());

	// ����˽Կ
	PEM_write_bio_RSAPrivateKey(pri, keypair, NULL, NULL, 0, NULL, NULL);
	// ע��------���ɵ�1�ָ�ʽ�Ĺ�Կ
	//PEM_write_bio_RSAPublicKey(pub, keypair);
	// ע��------���ɵ�2�ָ�ʽ�Ĺ�Կ���˴�������ʹ�����֣�
	PEM_write_bio_RSA_PUBKEY(pub, keypair);

	// ��ȡ����  
	pri_len = BIO_pending(pri);
	pub_len = BIO_pending(pub);

	// ��Կ�Զ�ȡ���ַ���  
	pri_key = (char*)malloc(pri_len + 1);
	pub_key = (char*)malloc(pub_len + 1);

	BIO_read(pri, pri_key, pri_len);
	BIO_read(pub, pub_key, pub_len);

	pri_key[pri_len] = '\0';
	pub_key[pub_len] = '\0';

	out_pub_key = pub_key;
	out_pri_key = pri_key;

	// ����Կд���ļ�
	std::ofstream pub_file(PUB_KEY_FILE, std::ios::out);
	if (!pub_file.is_open())
	{
		perror("pub key file open fail:");
		return;
	}
	pub_file << pub_key;
	pub_file.close();

	// ��˽Կд���ļ�
	std::ofstream pri_file(PRI_KEY_FILE, std::ios::out);
	if (!pri_file.is_open())
	{
		perror("pri key file open fail:");
		return;
	}
	pri_file << pri_key;
	pri_file.close();

	// �ͷ��ڴ�
	RSA_free(keypair);
	BIO_free_all(pub);
	BIO_free_all(pri);

	free(pri_key);
	free(pub_key);
}

/*
@brief : ˽Կ����
@para  : clear_text  -[i] ��Ҫ���м��ܵ�����
		 pri_key     -[i] ˽Կ
@return: ���ܺ������
**/
std::string RsaPriEncrypt(const std::string& clear_text, std::string& pri_key)
{
	std::string encrypt_text;
	BIO* keybio = BIO_new_mem_buf((unsigned char*)pri_key.c_str(), -1);
	RSA* rsa = RSA_new();
	rsa = PEM_read_bio_RSAPrivateKey(keybio, &rsa, NULL, NULL);
	if (!rsa)
	{
		BIO_free_all(keybio);
		return std::string("");
	}

	// ��ȡRSA���ο��Դ�������ݵ���󳤶�
	int len = RSA_size(rsa);

	// �����ڴ棺�������ܺ����������
	char* text = new char[len + 1];
	memset(text, 0, len + 1);

	// �����ݽ���˽Կ���ܣ�����ֵ�Ǽ��ܺ����ݵĳ��ȣ�
	int ret = RSA_private_encrypt(clear_text.length(), (const unsigned char*)clear_text.c_str(), (unsigned char*)text, rsa, RSA_PKCS1_PADDING);
	if (ret >= 0) {
		encrypt_text = std::string(text, ret);
	}

	// �ͷ��ڴ�  
	free(text);
	BIO_free_all(keybio);
	RSA_free(rsa);

	return encrypt_text;
}

/*
@brief : ��Կ����
@para  : cipher_text -[i] ���ܵ�����
		 pub_key     -[i] ��Կ
@return: ���ܺ������
**/
std::string RsaPubDecrypt(const std::string& cipher_text, const std::string& pub_key)
{
	std::string decrypt_text;
	BIO* keybio = BIO_new_mem_buf((unsigned char*)pub_key.c_str(), -1);
	RSA* rsa = RSA_new();

	// ע��--------ʹ�õ�1�ָ�ʽ�Ĺ�Կ���н���
	//rsa = PEM_read_bio_RSAPublicKey(keybio, &rsa, NULL, NULL);
	// ע��--------ʹ�õ�2�ָ�ʽ�Ĺ�Կ���н��ܣ�����ʹ�����ָ�ʽ��Ϊʾ����
	rsa = PEM_read_bio_RSA_PUBKEY(keybio, &rsa, NULL, NULL);
	if (!rsa)
	{
		unsigned long err = ERR_get_error(); //��ȡ�����
		char err_msg[1024] = { 0 };
		ERR_error_string(err, err_msg); // ��ʽ��error:errId:��:����:ԭ��
		printf("err msg: err:%ld, msg:%s\n", err, err_msg);
		BIO_free_all(keybio);
		return decrypt_text;
	}

	int len = RSA_size(rsa);
	char* text = new char[len + 1];
	memset(text, 0, len + 1);
	// �����Ľ��н���
	int ret = RSA_public_decrypt(cipher_text.length(), (const unsigned char*)cipher_text.c_str(), (unsigned char*)text, rsa, RSA_PKCS1_PADDING);
	if (ret >= 0) {
		decrypt_text.append(std::string(text, ret));
	}

	// �ͷ��ڴ�  
	delete text;
	BIO_free_all(keybio);
	RSA_free(rsa);

	return decrypt_text;
}

/*
@brief : ��Կ����
@para  : clear_text  -[i] ��Ҫ���м��ܵ�����
		 pri_key     -[i] ˽Կ
@return: ���ܺ������
**/
std::string RsaPubEncrypt(const std::string& clear_text, const std::string& pub_key)
{
	std::string encrypt_text;
	BIO* keybio = BIO_new_mem_buf((unsigned char*)pub_key.c_str(), -1);
	RSA* rsa = RSA_new();
	// ע��-----��1�ָ�ʽ�Ĺ�Կ
	//rsa = PEM_read_bio_RSAPublicKey(keybio, &rsa, NULL, NULL);
	// ע��-----��2�ָ�ʽ�Ĺ�Կ�������Եڶ��ָ�ʽΪ����
	rsa = PEM_read_bio_RSA_PUBKEY(keybio, &rsa, NULL, NULL);

	// ��ȡRSA���ο��Դ�������ݿ����󳤶�
	int key_len = RSA_size(rsa);
	int block_len = key_len - 11;    // ��Ϊ��䷽ʽΪRSA_PKCS1_PADDING, ����Ҫ��key_len�����ϼ�ȥ11

	// �����ڴ棺�������ܺ����������
	char* sub_text = new char[key_len + 1];
	memset(sub_text, 0, key_len + 1);
	int ret = 0;
	int pos = 0;
	std::string sub_str;
	// �����ݽ��зֶμ��ܣ�����ֵ�Ǽ��ܺ����ݵĳ��ȣ�
	while (pos < clear_text.length()) {
		sub_str = clear_text.substr(pos, block_len);
		memset(sub_text, 0, key_len + 1);
		ret = RSA_public_encrypt(sub_str.length(), (const unsigned char*)sub_str.c_str(), (unsigned char*)sub_text, rsa, RSA_PKCS1_PADDING);
		if (ret >= 0) {
			encrypt_text.append(std::string(sub_text, ret));
		}
		pos += block_len;
	}

	// �ͷ��ڴ�  
	BIO_free_all(keybio);
	RSA_free(rsa);
	delete[] sub_text;

	return encrypt_text;
}

/*
@brief : ˽Կ����
@para  : cipher_text -[i] ���ܵ�����
		 pub_key     -[i] ��Կ
@return: ���ܺ������
**/
std::string RsaPriDecrypt(const std::string& cipher_text, const std::string& pri_key)
{
	std::string decrypt_text;
	RSA* rsa = RSA_new();
	BIO* keybio;
	keybio = BIO_new_mem_buf((unsigned char*)pri_key.c_str(), -1);

	rsa = PEM_read_bio_RSAPrivateKey(keybio, &rsa, NULL, NULL);
	if (rsa == nullptr) {
		unsigned long err = ERR_get_error(); //��ȡ�����
		char err_msg[1024] = { 0 };
		ERR_error_string(err, err_msg); // ��ʽ��error:errId:��:����:ԭ��
		printf("err msg: err:%ld, msg:%s\n", err, err_msg);
		return std::string();
	}

	// ��ȡRSA���δ������󳤶�
	int key_len = RSA_size(rsa);
	char* sub_text = new char[key_len + 1];
	memset(sub_text, 0, key_len + 1);
	int ret = 0;
	std::string sub_str;
	int pos = 0;
	// �����Ľ��зֶν���
	while (pos < cipher_text.length()) {
		sub_str = cipher_text.substr(pos, key_len);
		memset(sub_text, 0, key_len + 1);
		ret = RSA_private_decrypt(sub_str.length(), (const unsigned char*)sub_str.c_str(), (unsigned char*)sub_text, rsa, RSA_PKCS1_PADDING);
		if (ret >= 0) {
			decrypt_text.append(std::string(sub_text, ret));
			printf("pos:%d, sub: %s\n", pos, sub_text);
			pos += key_len;
		}
	}
	// �ͷ��ڴ�  
	delete[] sub_text;
	BIO_free_all(keybio);
	RSA_free(rsa);

	return decrypt_text;
}

int main(int argc, char** argv)
{
	// ԭʼ����  
	std::string src_text = "abcdefg";
	//src_text = "rsa test";

	std::string encrypt_text;
	std::string decrypt_text;

	// ������Կ��
	std::string pub_key;
	std::string pri_key;
	GenerateRSAKey(pub_key, pri_key);
	printf("public key:\n");
	printf("%s\n", pub_key.c_str());
	printf("private key:\n");
	printf("%s\n", pri_key.c_str());



	// ˽Կ����-��Կ����
	encrypt_text = RsaPriEncrypt(src_text, pri_key);
	printf("encrypt: len=%d\n", encrypt_text.length());
	decrypt_text = RsaPubDecrypt(encrypt_text, pub_key);
	printf("decrypt: len=%d\n", decrypt_text.length());
	printf("decrypt: %s\n", decrypt_text.c_str());

	// ��Կ����-˽Կ����
	encrypt_text = RsaPubEncrypt(src_text, pub_key);
	printf("encrypt: len=%d\n", encrypt_text.length());
	decrypt_text = RsaPriDecrypt(encrypt_text, pri_key);
	printf("decrypt: len=%d\n", decrypt_text.length());

	
    return 0;
}