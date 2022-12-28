#include <fstream>
#include "openssl/rsa.h"
#include "openssl/pem.h"
#include "openssl/err.h"

#define KEY_LENGTH  2048             // 密钥长度
#define PUB_KEY_FILE "pubkey.pem"    // 公钥路径
#define PRI_KEY_FILE "prikey.pem"    // 私钥路径

/*
制造密钥对：私钥和公钥
**/
void GenerateRSAKey(std::string& out_pub_key, std::string& out_pri_key)
{
	size_t pri_len = 0; // 私钥长度
	size_t pub_len = 0; // 公钥长度
	char* pri_key = nullptr; // 私钥
	char* pub_key = nullptr; // 公钥

	// 生成密钥对
	RSA* keypair = RSA_generate_key(KEY_LENGTH, RSA_3, NULL, NULL);

	BIO* pri = BIO_new(BIO_s_mem());
	BIO* pub = BIO_new(BIO_s_mem());

	// 生成私钥
	PEM_write_bio_RSAPrivateKey(pri, keypair, NULL, NULL, 0, NULL, NULL);
	// 注意------生成第1种格式的公钥
	//PEM_write_bio_RSAPublicKey(pub, keypair);
	// 注意------生成第2种格式的公钥（此处代码中使用这种）
	PEM_write_bio_RSA_PUBKEY(pub, keypair);

	// 获取长度  
	pri_len = BIO_pending(pri);
	pub_len = BIO_pending(pub);

	// 密钥对读取到字符串  
	pri_key = (char*)malloc(pri_len + 1);
	pub_key = (char*)malloc(pub_len + 1);

	BIO_read(pri, pri_key, pri_len);
	BIO_read(pub, pub_key, pub_len);

	pri_key[pri_len] = '\0';
	pub_key[pub_len] = '\0';

	out_pub_key = pub_key;
	out_pri_key = pri_key;

	// 将公钥写入文件
	std::ofstream pub_file(PUB_KEY_FILE, std::ios::out);
	if (!pub_file.is_open())
	{
		perror("pub key file open fail:");
		return;
	}
	pub_file << pub_key;
	pub_file.close();

	// 将私钥写入文件
	std::ofstream pri_file(PRI_KEY_FILE, std::ios::out);
	if (!pri_file.is_open())
	{
		perror("pri key file open fail:");
		return;
	}
	pri_file << pri_key;
	pri_file.close();

	// 释放内存
	RSA_free(keypair);
	BIO_free_all(pub);
	BIO_free_all(pri);

	free(pri_key);
	free(pub_key);
}

/*
@brief : 私钥加密
@para  : clear_text  -[i] 需要进行加密的明文
		 pri_key     -[i] 私钥
@return: 加密后的数据
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

	// 获取RSA单次可以处理的数据的最大长度
	int len = RSA_size(rsa);

	// 申请内存：存贮加密后的密文数据
	char* text = new char[len + 1];
	memset(text, 0, len + 1);

	// 对数据进行私钥加密（返回值是加密后数据的长度）
	int ret = RSA_private_encrypt(clear_text.length(), (const unsigned char*)clear_text.c_str(), (unsigned char*)text, rsa, RSA_PKCS1_PADDING);
	if (ret >= 0) {
		encrypt_text = std::string(text, ret);
	}

	// 释放内存  
	free(text);
	BIO_free_all(keybio);
	RSA_free(rsa);

	return encrypt_text;
}

/*
@brief : 公钥解密
@para  : cipher_text -[i] 加密的密文
		 pub_key     -[i] 公钥
@return: 解密后的数据
**/
std::string RsaPubDecrypt(const std::string& cipher_text, const std::string& pub_key)
{
	std::string decrypt_text;
	BIO* keybio = BIO_new_mem_buf((unsigned char*)pub_key.c_str(), -1);
	RSA* rsa = RSA_new();

	// 注意--------使用第1种格式的公钥进行解密
	//rsa = PEM_read_bio_RSAPublicKey(keybio, &rsa, NULL, NULL);
	// 注意--------使用第2种格式的公钥进行解密（我们使用这种格式作为示例）
	rsa = PEM_read_bio_RSA_PUBKEY(keybio, &rsa, NULL, NULL);
	if (!rsa)
	{
		unsigned long err = ERR_get_error(); //获取错误号
		char err_msg[1024] = { 0 };
		ERR_error_string(err, err_msg); // 格式：error:errId:库:函数:原因
		printf("err msg: err:%ld, msg:%s\n", err, err_msg);
		BIO_free_all(keybio);
		return decrypt_text;
	}

	int len = RSA_size(rsa);
	char* text = new char[len + 1];
	memset(text, 0, len + 1);
	// 对密文进行解密
	int ret = RSA_public_decrypt(cipher_text.length(), (const unsigned char*)cipher_text.c_str(), (unsigned char*)text, rsa, RSA_PKCS1_PADDING);
	if (ret >= 0) {
		decrypt_text.append(std::string(text, ret));
	}

	// 释放内存  
	delete text;
	BIO_free_all(keybio);
	RSA_free(rsa);

	return decrypt_text;
}

/*
@brief : 公钥加密
@para  : clear_text  -[i] 需要进行加密的明文
		 pri_key     -[i] 私钥
@return: 加密后的数据
**/
std::string RsaPubEncrypt(const std::string& clear_text, const std::string& pub_key)
{
	std::string encrypt_text;
	BIO* keybio = BIO_new_mem_buf((unsigned char*)pub_key.c_str(), -1);
	RSA* rsa = RSA_new();
	// 注意-----第1种格式的公钥
	//rsa = PEM_read_bio_RSAPublicKey(keybio, &rsa, NULL, NULL);
	// 注意-----第2种格式的公钥（这里以第二种格式为例）
	rsa = PEM_read_bio_RSA_PUBKEY(keybio, &rsa, NULL, NULL);

	// 获取RSA单次可以处理的数据块的最大长度
	int key_len = RSA_size(rsa);
	int block_len = key_len - 11;    // 因为填充方式为RSA_PKCS1_PADDING, 所以要在key_len基础上减去11

	// 申请内存：存贮加密后的密文数据
	char* sub_text = new char[key_len + 1];
	memset(sub_text, 0, key_len + 1);
	int ret = 0;
	int pos = 0;
	std::string sub_str;
	// 对数据进行分段加密（返回值是加密后数据的长度）
	while (pos < clear_text.length()) {
		sub_str = clear_text.substr(pos, block_len);
		memset(sub_text, 0, key_len + 1);
		ret = RSA_public_encrypt(sub_str.length(), (const unsigned char*)sub_str.c_str(), (unsigned char*)sub_text, rsa, RSA_PKCS1_PADDING);
		if (ret >= 0) {
			encrypt_text.append(std::string(sub_text, ret));
		}
		pos += block_len;
	}

	// 释放内存  
	BIO_free_all(keybio);
	RSA_free(rsa);
	delete[] sub_text;

	return encrypt_text;
}

/*
@brief : 私钥解密
@para  : cipher_text -[i] 加密的密文
		 pub_key     -[i] 公钥
@return: 解密后的数据
**/
std::string RsaPriDecrypt(const std::string& cipher_text, const std::string& pri_key)
{
	std::string decrypt_text;
	RSA* rsa = RSA_new();
	BIO* keybio;
	keybio = BIO_new_mem_buf((unsigned char*)pri_key.c_str(), -1);

	rsa = PEM_read_bio_RSAPrivateKey(keybio, &rsa, NULL, NULL);
	if (rsa == nullptr) {
		unsigned long err = ERR_get_error(); //获取错误号
		char err_msg[1024] = { 0 };
		ERR_error_string(err, err_msg); // 格式：error:errId:库:函数:原因
		printf("err msg: err:%ld, msg:%s\n", err, err_msg);
		return std::string();
	}

	// 获取RSA单次处理的最大长度
	int key_len = RSA_size(rsa);
	char* sub_text = new char[key_len + 1];
	memset(sub_text, 0, key_len + 1);
	int ret = 0;
	std::string sub_str;
	int pos = 0;
	// 对密文进行分段解密
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
	// 释放内存  
	delete[] sub_text;
	BIO_free_all(keybio);
	RSA_free(rsa);

	return decrypt_text;
}

int main(int argc, char** argv)
{
	// 原始明文  
	std::string src_text = "abcdefg";
	//src_text = "rsa test";

	std::string encrypt_text;
	std::string decrypt_text;

	// 生成密钥对
	std::string pub_key;
	std::string pri_key;
	GenerateRSAKey(pub_key, pri_key);
	printf("public key:\n");
	printf("%s\n", pub_key.c_str());
	printf("private key:\n");
	printf("%s\n", pri_key.c_str());



	// 私钥加密-公钥解密
	encrypt_text = RsaPriEncrypt(src_text, pri_key);
	printf("encrypt: len=%d\n", encrypt_text.length());
	decrypt_text = RsaPubDecrypt(encrypt_text, pub_key);
	printf("decrypt: len=%d\n", decrypt_text.length());
	printf("decrypt: %s\n", decrypt_text.c_str());

	// 公钥加密-私钥解密
	encrypt_text = RsaPubEncrypt(src_text, pub_key);
	printf("encrypt: len=%d\n", encrypt_text.length());
	decrypt_text = RsaPriDecrypt(encrypt_text, pri_key);
	printf("decrypt: len=%d\n", decrypt_text.length());

	
    return 0;
}