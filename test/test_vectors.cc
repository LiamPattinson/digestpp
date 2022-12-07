#include <numeric>
#include <regex>
#include <iostream>
#include <fstream>
#include "digestpp/digestpp.hpp"
#include "gtest/gtest.h"

template<typename T>
class has_customization
{
	template<typename U>
	static auto test(int) -> decltype(std::declval<U>().set_customization(std::declval<std::string>()), std::true_type());
	template<typename>
	static std::false_type test(...);
public:
	static constexpr bool value = std::is_same<decltype(test<T>(0)), std::true_type>::value;
};

template<typename T>
class has_personalization
{
	template<typename U>
	static auto test(int) -> decltype(std::declval<U>().set_personalization(std::declval<std::string>()), std::true_type());
	template<typename>
	static std::false_type test(...);
public:
	static constexpr bool value = std::is_same<decltype(test<T>(0)), std::true_type>::value;
};

template<typename T>
class has_salt
{
	template<typename U>
	static auto test(int) -> decltype(std::declval<U>().set_salt(std::declval<std::string>()), std::true_type());
	template<typename>
	static std::false_type test(...);
public:
	static constexpr bool value = std::is_same<decltype(test<T>(0)), std::true_type>::value;
};

template<typename T>
class has_key
{
	template<typename U>
	static auto test(int) -> decltype(std::declval<U>().set_key(std::declval<std::string>()), std::true_type());
	template<typename>
	static std::false_type test(...);
public:
	static constexpr bool value = std::is_same<decltype(test<T>(0)), std::true_type>::value;
};

inline std::string hex2string(const std::string& hex)
{
	std::string res;
	res.resize(hex.length() / 2);
	for (size_t i = 0; i < hex.length(); i += 2)
		res[i / 2] = static_cast<char>(strtoul(hex.substr(i, 2).c_str(), nullptr, 16));
	return res;
}

inline void trim_string(std::string& str)
{
	str.erase(str.find_last_not_of("\r\n\t ") + 1);
	str.erase(0, str.find_first_not_of("\r\n\t "));
}

inline std::pair<std::string, std::string> split_vector(const std::string& str)
{
	std::pair<std::string, std::string> res;
	auto sep = str.find("=");
	if (sep == str.npos)
		return res;

	res.first = str.substr(0, sep);
	res.second = str.substr(sep + 1);
	trim_string(res.first);
	trim_string(res.second);
	return res;
}

template<typename H, template<typename> class M, typename std::enable_if<!digestpp::detail::is_xof<H>::value>::type* = nullptr>
std::string compute_vector(const std::string&, digestpp::hasher<H, M>& hasher)
{
	return hasher.hexdigest();
}

template<typename H, template<typename> class M, typename std::enable_if<digestpp::detail::is_xof<H>::value>::type* = nullptr>
std::string compute_vector(const std::string& expected, digestpp::hasher<H, M>& hasher)
{
	return hasher.hexsqueeze(expected.size() / 2);
}

template<typename H, typename std::enable_if<!has_customization<H>::value && !has_personalization<H>::value>::type* = nullptr>
void set_customization(const std::string& customization, H& hasher)
{
}

template<typename H, typename std::enable_if<has_customization<H>::value>::type* = nullptr>
void set_customization(const std::string& customization, H& hasher)
{
	hasher.set_customization(customization);
}

template<typename H, typename std::enable_if<has_personalization<H>::value>::type* = nullptr>
void set_customization(const std::string& customization, H& hasher)
{
	hasher.set_personalization(customization);
}

template<typename H, typename std::enable_if<!has_salt<H>::value>::type* = nullptr>
void set_salt(const std::string& salt, H& hasher)
{
}

template<typename H, typename std::enable_if<has_salt<H>::value>::type* = nullptr>
void set_salt(const std::string& salt, H& hasher)
{
	hasher.set_salt(salt);
}

template<typename H, typename std::enable_if<!has_key<H>::value>::type* = nullptr>
void set_key(const std::string& key, H& hasher)
{
}

template<typename H, typename std::enable_if<has_key<H>::value>::type* = nullptr>
void set_key(const std::string& key, H& hasher)
{
	hasher.set_key(key);
}

template<typename H>
unsigned int test_vectors(const H& hasher, const char* name, const char* filename)
{
	H copy(hasher);
	std::ifstream file(filename, std::ios::in);
	std::string line;
	unsigned int count = 0, failed = 0, success = 0;
	std::string::size_type msgbytes = 0;
	while (std::getline(file, line))
	{
		auto splitted = split_vector(line);
		std::string second = splitted.second;
		if (splitted.first == "Bytes")
			msgbytes = std::stol(splitted.second);
		if (splitted.first == "C")
		{
			std::string teststr = hex2string(second);
			set_customization(teststr, copy);
		}
		if (splitted.first == "Salt")
		{
			std::string teststr = hex2string(second);
			set_salt(teststr, copy);
		}
		if (splitted.first == "Key")
		{
			std::string teststr = hex2string(second);
			set_key(teststr, copy);
		}
		if (splitted.first == "Msg")
		{
			std::string teststr = hex2string(second);
			if (!msgbytes)
				copy.absorb(teststr);
			else while (msgbytes)
			{
				auto toabsorb = std::min(teststr.size(), msgbytes);
				copy.absorb(teststr.c_str(), toabsorb);
				msgbytes -= toabsorb;
			}
		}
		if (splitted.first == "MD")
		{
			std::transform(second.begin(), second.end(), second.begin(), [](unsigned char c) { return tolower(c); });
			std::string actual = compute_vector(second, copy);
			if (second != actual)
			{
				std::cerr << "\nError for test " << count << "\nExpected: " << second 
					<< "\nActual: " << actual << std::endl;
				failed++;
			}
			else success++;
			count++;
			copy.reset();
		}
	}
	std::cout << name << ": ";
	if (success)
		std::cout << success << "/" << count << " OK";
	if (failed && success)
		std::cout << ", ";
	if (failed)
		std::cout << failed << "/" << count << " FAILED";
	if (!success && !failed)
		std::cout << "No tests found";
	std::cout << std::endl;
    return success;
}


TEST(TestVectors, BLAKE_244){
    ASSERT_TRUE(test_vectors(digestpp::blake(224), "blake/224", "testvectors/blake224.txt"));
}

TEST(TestVectors, BLAKE_256){
    ASSERT_TRUE(test_vectors(digestpp::blake(256), "blake/256", "testvectors/blake256.txt"));
}

TEST(TestVectors, BLAKE_384){
    ASSERT_TRUE(test_vectors(digestpp::blake(384), "blake/384", "testvectors/blake384.txt"));
}

TEST(TestVectors, BLAKE_512){
    ASSERT_TRUE(test_vectors(digestpp::blake(512), "blake/512", "testvectors/blake512.txt"));
}

TEST(TestVectors, BLAKE_256_salt){
    ASSERT_TRUE(test_vectors(digestpp::blake(256), "blake/256-salt", "testvectors/blake256salt.txt"));
}

TEST(TestVectors, BLAKE_384_salt){
    ASSERT_TRUE(test_vectors(digestpp::blake(384), "blake/384-salt", "testvectors/blake384salt.txt"));
}

TEST(TestVectors, BLAKE2S_128){
    ASSERT_TRUE(test_vectors(digestpp::blake2s(128), "blake2s/128", "testvectors/blake2s_128.txt"));
}

TEST(TestVectors, BLAKE2S_160){
    ASSERT_TRUE(test_vectors(digestpp::blake2s(160), "blake2s/160", "testvectors/blake2s_160.txt"));
}

TEST(TestVectors, BLAKE2S_224){
    ASSERT_TRUE(test_vectors(digestpp::blake2s(224), "blake2s/224", "testvectors/blake2s_224.txt"));
}

TEST(TestVectors, BLAKE2S_256){
    ASSERT_TRUE(test_vectors(digestpp::blake2s(256), "blake2s/256", "testvectors/blake2s_256.txt"));
}

TEST(TestVectors, BLAKE2B_128){
    ASSERT_TRUE(test_vectors(digestpp::blake2b(128), "blake2b/128", "testvectors/blake2b_128.txt"));
}

TEST(TestVectors, BLAKE2B_160){
    ASSERT_TRUE(test_vectors(digestpp::blake2b(160), "blake2b/160", "testvectors/blake2b_160.txt"));
}

TEST(TestVectors, BLAKE2B_224){
    ASSERT_TRUE(test_vectors(digestpp::blake2b(224), "blake2b/224", "testvectors/blake2b_224.txt"));
}

TEST(TestVectors, BLAKE2B_256){
    ASSERT_TRUE(test_vectors(digestpp::blake2b(256), "blake2b/256", "testvectors/blake2b_256.txt"));
}

TEST(TestVectors, BLAKE2B_384){
    ASSERT_TRUE(test_vectors(digestpp::blake2b(384), "blake2b/384", "testvectors/blake2b_384.txt"));
}

TEST(TestVectors, BLAKE2B_512){
    ASSERT_TRUE(test_vectors(digestpp::blake2b(512), "blake2b/512", "testvectors/blake2b_512.txt"));
}

TEST(TestVectors, BLAKE2XB_256){
    ASSERT_TRUE(test_vectors(digestpp::blake2xb(256), "blake2xb/256", "testvectors/blake2xb_256.txt"));
}

TEST(TestVectors, BLAKE2XB_512){
    ASSERT_TRUE(test_vectors(digestpp::blake2xb(512), "blake2xb/512", "testvectors/blake2xb_512.txt"));
}

TEST(TestVectors, BLAKE2XB_2040){
    ASSERT_TRUE(test_vectors(digestpp::blake2xb(2040), "blake2xb/2040", "testvectors/blake2xb_2040.txt"));
}

TEST(TestVectors, BLAKE2XB_2056){
    ASSERT_TRUE(test_vectors(digestpp::blake2xb(2056), "blake2xb/2056", "testvectors/blake2xb_2056.txt"));
}

TEST(TestVectors, BLAKE2XB_2056_param){
    ASSERT_TRUE(test_vectors(digestpp::blake2xb(2056), "blake2xb/2056-param", "testvectors/blake2xb_2056param.txt"));
}

TEST(TestVectors, BLAKE2XS_256){
    ASSERT_TRUE(test_vectors(digestpp::blake2xs(256), "blake2xs/256", "testvectors/blake2xs_256.txt"));
}

TEST(TestVectors, BLAKE2XS_2056){
    ASSERT_TRUE(test_vectors(digestpp::blake2xs(2056), "blake2xs/2056", "testvectors/blake2xs_2056.txt"));
}

TEST(TestVectors, BLAKE2XS_2056_param){
    ASSERT_TRUE(test_vectors(digestpp::blake2xs(2056), "blake2xs/2056-param", "testvectors/blake2xs_2056param.txt"));
}

TEST(TestVectors, ECHO_224){
    ASSERT_TRUE(test_vectors(digestpp::echo(224), "echo/224", "testvectors/echo224.txt"));
}

TEST(TestVectors, ECHO_256){
    ASSERT_TRUE(test_vectors(digestpp::echo(256), "echo/256", "testvectors/echo256.txt"));
}

TEST(TestVectors, ECHO_384){
    ASSERT_TRUE(test_vectors(digestpp::echo(384), "echo/384", "testvectors/echo384.txt"));
}

TEST(TestVectors, ECHO_512){
    ASSERT_TRUE(test_vectors(digestpp::echo(512), "echo/512", "testvectors/echo512.txt"));
}

TEST(TestVectors, Esch_256){
    ASSERT_TRUE(test_vectors(digestpp::esch(256), "esch/256", "testvectors/esch256.txt"));
}

TEST(TestVectors, Esch_384){
    ASSERT_TRUE(test_vectors(digestpp::esch(384), "esch/384", "testvectors/esch384.txt"));
}

TEST(TestVectors, Groestl_224){
    ASSERT_TRUE(test_vectors(digestpp::groestl(224), "groestl/224", "testvectors/groestl224.txt"));
}

TEST(TestVectors, Groestl_256){
    ASSERT_TRUE(test_vectors(digestpp::groestl(256), "groestl/256", "testvectors/groestl256.txt"));
}

TEST(TestVectors, Groestl_384){
    ASSERT_TRUE(test_vectors(digestpp::groestl(384), "groestl/384", "testvectors/groestl384.txt"));
}

TEST(TestVectors, Groestl_512){
    ASSERT_TRUE(test_vectors(digestpp::groestl(512), "groestl/512", "testvectors/groestl512.txt"));
}

TEST(TestVectors, JH_224){
    ASSERT_TRUE(test_vectors(digestpp::jh(224), "jh/224", "testvectors/jh224.txt"));
}

TEST(TestVectors, JH_256){
    ASSERT_TRUE(test_vectors(digestpp::jh(256), "jh/256", "testvectors/jh256.txt"));
}

TEST(TestVectors, JH_384){
    ASSERT_TRUE(test_vectors(digestpp::jh(384), "jh/384", "testvectors/jh384.txt"));
}

TEST(TestVectors, JH_512){
    ASSERT_TRUE(test_vectors(digestpp::jh(512), "jh/512", "testvectors/jh512.txt"));
}

TEST(TestVectors, Kupyna_256){
    ASSERT_TRUE(test_vectors(digestpp::kupyna(256), "kupyna/256", "testvectors/kupyna256.txt"));
}

TEST(TestVectors, Kupyna_512){
    ASSERT_TRUE(test_vectors(digestpp::kupyna(512), "kupyna/512", "testvectors/kupyna512.txt"));
}

TEST(TestVectors, MD5){
    ASSERT_TRUE(test_vectors(digestpp::md5(), "md5", "testvectors/md5.txt"));
}

TEST(TestVectors, SHA1){
    ASSERT_TRUE(test_vectors(digestpp::sha1(), "sha1", "testvectors/sha1.txt"));
}

TEST(TestVectors, SHA224){
    ASSERT_TRUE(test_vectors(digestpp::sha224(), "sha224", "testvectors/sha224.txt"));
}

TEST(TestVectors, SHA256){
    ASSERT_TRUE(test_vectors(digestpp::sha256(), "sha256", "testvectors/sha256.txt"));
}

TEST(TestVectors, SHA384){
    ASSERT_TRUE(test_vectors(digestpp::sha384(), "sha384", "testvectors/sha384.txt"));
}

TEST(TestVectors, SHA512){
    ASSERT_TRUE(test_vectors(digestpp::sha512(), "sha512", "testvectors/sha512.txt"));
}

TEST(TestVectors, SHA512_224){
    ASSERT_TRUE(test_vectors(digestpp::sha512(224), "sha512/224", "testvectors/sha512_224.txt"));
}

TEST(TestVectors, SHA512_256){
    ASSERT_TRUE(test_vectors(digestpp::sha512(256), "sha512/256", "testvectors/sha512_256.txt"));
}

TEST(TestVectors, SHA3_224){
    ASSERT_TRUE(test_vectors(digestpp::sha3(224), "sha3/224", "testvectors/sha3_224.txt"));
}

TEST(TestVectors, SHA3_256){
    ASSERT_TRUE(test_vectors(digestpp::sha3(256), "sha3/256", "testvectors/sha3_256.txt"));
}

TEST(TestVectors, SHA3_384){
    ASSERT_TRUE(test_vectors(digestpp::sha3(384), "sha3/384", "testvectors/sha3_384.txt"));
}

TEST(TestVectors, SHA3_512){
    ASSERT_TRUE(test_vectors(digestpp::sha3(512), "sha3/512", "testvectors/sha3_512.txt"));
}

TEST(TestVectors, Skein256_128){
    ASSERT_TRUE(test_vectors(digestpp::skein256(128), "skein256/128", "testvectors/skein256_128.txt"));
}

TEST(TestVectors, Skein256_160){
    ASSERT_TRUE(test_vectors(digestpp::skein256(160), "skein256/160", "testvectors/skein256_160.txt"));
}

TEST(TestVectors, Skein256_224){
    ASSERT_TRUE(test_vectors(digestpp::skein256(224), "skein256/224", "testvectors/skein256_224.txt"));
}

TEST(TestVectors, Skein256_256){
    ASSERT_TRUE(test_vectors(digestpp::skein256(256), "skein256/256", "testvectors/skein256_256.txt"));
}

TEST(TestVectors, Skein256_2056){
    ASSERT_TRUE(test_vectors(digestpp::skein256(2056), "skein256/2056", "testvectors/skein256_2056.txt"));
}

TEST(TestVectors, Skein512_128){
    ASSERT_TRUE(test_vectors(digestpp::skein512(128), "skein512/128", "testvectors/skein512_128.txt"));
}

TEST(TestVectors, Skein512_160){
    ASSERT_TRUE(test_vectors(digestpp::skein512(160), "skein512/160", "testvectors/skein512_160.txt"));
}

TEST(TestVectors, Skein512_224){
    ASSERT_TRUE(test_vectors(digestpp::skein512(224), "skein512/224", "testvectors/skein512_224.txt"));
}

TEST(TestVectors, Skein512_256){
    ASSERT_TRUE(test_vectors(digestpp::skein512(256), "skein512/256", "testvectors/skein512_256.txt"));
}

TEST(TestVectors, Skein512_384){
    ASSERT_TRUE(test_vectors(digestpp::skein512(384), "skein512/384", "testvectors/skein512_384.txt"));
}

TEST(TestVectors, Skein512_512){
    ASSERT_TRUE(test_vectors(digestpp::skein512(512), "skein512/512", "testvectors/skein512_512.txt"));
}

TEST(TestVectors, Skein512_2056){
    ASSERT_TRUE(test_vectors(digestpp::skein512(2056), "skein512/2056", "testvectors/skein512_2056.txt"));
}

TEST(TestVectors, Skein1024_256){
    ASSERT_TRUE(test_vectors(digestpp::skein1024(256), "skein1024/256", "testvectors/skein1024_256.txt"));
}

TEST(TestVectors, Skein1024_384){
    ASSERT_TRUE(test_vectors(digestpp::skein1024(384), "skein1024/384", "testvectors/skein1024_384.txt"));
}

TEST(TestVectors, Skein1024_512){
    ASSERT_TRUE(test_vectors(digestpp::skein1024(512), "skein1024/512", "testvectors/skein1024_512.txt"));
}

TEST(TestVectors, Skein1024_1024){
    ASSERT_TRUE(test_vectors(digestpp::skein1024(1024), "skein1024/1024", "testvectors/skein1024_1024.txt"));
}

TEST(TestVectors, Skein1024_2056){
    ASSERT_TRUE(test_vectors(digestpp::skein1024(2056), "skein1024/2056", "testvectors/skein1024_2056.txt"));
}

TEST(TestVectors, SM3){
    ASSERT_TRUE(test_vectors(digestpp::sm3(), "sm3", "testvectors/sm3.txt"));
}

TEST(TestVectors, Streebog_256){
    ASSERT_TRUE(test_vectors(digestpp::streebog(256), "streebog/256", "testvectors/streebog256.txt"));
}

TEST(TestVectors, Streebog_512){
    ASSERT_TRUE(test_vectors(digestpp::streebog(512), "streebog/512", "testvectors/streebog512.txt"));
}

TEST(TestVectors, Whirlpool){
    ASSERT_TRUE(test_vectors(digestpp::whirlpool(), "whirlpool", "testvectors/whirlpool.txt"));
}


// XOFs

TEST(TestVectorsXOF, BLAKE2XB_XOF){
	ASSERT_TRUE(test_vectors(digestpp::blake2xb_xof(), "blake2xb_xof", "testvectors/blake2xb_xof.txt"));
}

TEST(TestVectorsXOF, BLAKE2XS_XOF){
    ASSERT_TRUE(test_vectors(digestpp::blake2xs_xof(), "blake2xs_xof", "testvectors/blake2xs_xof.txt"));
}

TEST(TestVectorsXOF, SHAKE128){
    ASSERT_TRUE(test_vectors(digestpp::shake128(), "shake128", "testvectors/shake128.txt"));
}

TEST(TestVectorsXOF, SHAKE256){
    ASSERT_TRUE(test_vectors(digestpp::shake256(), "shake256", "testvectors/shake256.txt"));
}

TEST(TestVectorsXOF, cSHAKE256){
    ASSERT_TRUE(test_vectors(digestpp::cshake256().set_customization("Email Signature"), "cshake256", "testvectors/cshake256.txt"));
}

TEST(TestVectorsXOF, K12){
    ASSERT_TRUE(test_vectors(digestpp::k12(), "k12", "testvectors/k12.txt"));
}

TEST(TestVectorsXOF, KMAC128){
    ASSERT_TRUE(test_vectors(digestpp::kmac128(256), "kmac128", "testvectors/kmac128.txt"));
}

TEST(TestVectorsXOF, KMAC256){
    ASSERT_TRUE(test_vectors(digestpp::kmac256(512), "kmac256", "testvectors/kmac256.txt"));
}

TEST(TestVectorsXOF, Skein256_XOF){
    ASSERT_TRUE(test_vectors(digestpp::skein256_xof(), "skein256-XOF", "testvectors/skein256_xof.txt"));
}

TEST(TestVectorsXOF, Skein512_XOF){
    ASSERT_TRUE(test_vectors(digestpp::skein512_xof(), "skein512-XOF", "testvectors/skein512_xof.txt"));
}
