#include"main.h"

// SimHash 类定义
class SimHash {
public:
    // 用 EVP 获取字符串的哈希值，返回一个二进制字符串表示
    static std::string getHash(const std::wstring& str) {
        unsigned char digest[EVP_MAX_MD_SIZE]; // 存储哈希结果
        unsigned int digestLength = 0;
        std::string inputString(str.begin(), str.end());

        // 使用 OpenSSL 的 EVP API 计算 MD5
        EVP_MD_CTX* context = EVP_MD_CTX_new(); // 创建上下文
        EVP_DigestInit_ex(context, EVP_md5(), NULL); // 初始化 MD5
        EVP_DigestUpdate(context, inputString.c_str(), inputString.size()); // 传入数据
        EVP_DigestFinal_ex(context, digest, &digestLength); // 获取哈希值
        EVP_MD_CTX_free(context); // 释放上下文

        // 将哈希结果转换为 128 位二进制表示
        std::bitset<128> bitsetHash;
        for (int i = 0; i < static_cast<int>(digestLength); ++i) {
            std::bitset<8> byteBits(digest[i]);
            for (int j = 0; j < 8; ++j) {
                bitsetHash[i * 8 + j] = byteBits[j];
            }
        }

        return bitsetHash.to_string();
    }

    // 计算字符串的 SimHash
    static std::string getSimHash(const std::wstring& str) {
        int v[128] = { 0 }; // 创建一个128位的特征向量

        std::wstring word;
        for (const auto& ch : str) {
            word += ch; // 模拟分词
            std::string hash = getHash(word);

            for (int i = 0; i < 128; ++i) {
                if (hash[i] == '1') {
                    v[i] += 1;
                }
                else {
                    v[i] -= 1;
                }
            }
            word.clear();
        }

        // 将特征向量转换为 SimHash 二进制字符串
        std::string simHash;
        for (int i = 0; i < 128; ++i) {
            if (v[i] > 0) {
                simHash += '1';
            }
            else {
                simHash += '0';
            }
        }

        return simHash;
    }
};

// HammingUtils 类定义
class HammingUtils {
public:
    // 计算两个SimHash值之间的汉明距离
    static int getHammingDistance(const std::string& simHash1, const std::string& simHash2) {
        if (simHash1.length() != simHash2.length()) {
            throw std::invalid_argument("SimHash lengths do not match.");
        }

        int distance = 0;
        for (size_t i = 0; i < simHash1.length(); ++i) {
            if (simHash1[i] != simHash2[i]) {
                ++distance;
            }
        }
        return distance;
    }

    // 根据汉明距离计算相似度
    static double getSimilarity(int distance) {
        return 1.0 - static_cast<double>(distance) / 128;
    }
};



// 读取文件内容
std::wstring readFile(const std::wstring& filePath) {
    std::wifstream file(filePath);
    if (!file.is_open()) {
        std::wcerr << L"无法打开文件: " << filePath << std::endl;
        exit(1);
    }

    file.imbue(std::locale(file.getloc(), new std::codecvt_utf8<wchar_t>));

    std::wstringstream buffer;
    buffer << file.rdbuf();
    file.close();
    return buffer.str();
}

// 将string转换为wstring
std::wstring charToWstring(const std::string& str) {
    std::wstring_convert<std::codecvt_utf8_utf16<wchar_t>> converter;
    return converter.from_bytes(str);
}

// 主程序
int main(int argc, char* argv[]) {
    if (argc < 4) {
        std::cerr << "用法: " << argv[0] << " <E:\\test.RG\orig.txt> <E:\\test.RG\orig_0.8_add.txt> <E:\\test.RG\orig_0.8_del.txt> <E:\\test.RG\orig_0.8_dis_1.txt> <E:\\软工作业测试文本\orig_0.8_dis_10.txt> <E:\\test.RG\orig_0.8_dis_15.txt> <C:\\Users\86184\Desktop\input.txt>" << std::endl;
        return 1;
    }

    // 读取原文的文件路径
    std::wstring origFilePath = charToWstring(argv[1]);

    // 获取所有抄袭文本文件路径
    std::vector<std::wstring> plagiarizedFilePaths;
    for (int i = 2; i < argc - 1; ++i) {
        plagiarizedFilePaths.push_back(charToWstring(argv[i]));
    }

    // 读取输出文件路径
    std::wstring outputFilePath = charToWstring(argv[argc - 1]);

    // 读取原文的内容
    std::wstring origContent = readFile(origFilePath);

    // 打开输出文件
    std::wofstream outFile(outputFilePath);
    if (!outFile.is_open()) {
        std::wcerr << L"无法写入文件: " << outputFilePath << std::endl;
        return 1;
    }

    // 处理每个抄袭文本
    for (const std::wstring& plagiarizedFilePath : plagiarizedFilePaths) {
        // 读取抄袭文本的内容
        std::wstring plagiarizedContent = readFile(plagiarizedFilePath);

        // 计算原文和抄袭文本的SimHash值
        std::string origSimHash = SimHash::getSimHash(origContent);
        std::string plagiarizedSimHash = SimHash::getSimHash(plagiarizedContent);

        // 计算汉明距离
        int hammingDistance = HammingUtils::getHammingDistance(origSimHash, plagiarizedSimHash);

        // 计算相似度
        double similarity = HammingUtils::getSimilarity(hammingDistance);

        // 输出结果到控制台
        std::wcout << "原文文件: " << origFilePath << std::endl;
        std::wcout << "抄袭文件: " << plagiarizedFilePath << std::endl;
        std::wcout << "相似度: " << similarity * 100 << L"%" << std::endl;
        std::wcout << "----------------------------" << std::endl;

        // 输出结果到文件
        outFile << "原文文件: " << origFilePath << std::endl;
        outFile << "抄袭文件: " << plagiarizedFilePath << std::endl;
        outFile << "相似度: " << similarity * 100 << L"%" << std::endl;
        outFile << "----------------------------" << std::endl;
    }

    std::wcout << "查重完成，结果已输出到: " << outputFilePath << std::endl;

    return 0;
}
