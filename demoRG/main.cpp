#include"main.h"

// SimHash �ඨ��
class SimHash {
public:
    // �� EVP ��ȡ�ַ����Ĺ�ϣֵ������һ���������ַ�����ʾ
    static std::string getHash(const std::wstring& str) {
        unsigned char digest[EVP_MAX_MD_SIZE]; // �洢��ϣ���
        unsigned int digestLength = 0;
        std::string inputString(str.begin(), str.end());

        // ʹ�� OpenSSL �� EVP API ���� MD5
        EVP_MD_CTX* context = EVP_MD_CTX_new(); // ����������
        EVP_DigestInit_ex(context, EVP_md5(), NULL); // ��ʼ�� MD5
        EVP_DigestUpdate(context, inputString.c_str(), inputString.size()); // ��������
        EVP_DigestFinal_ex(context, digest, &digestLength); // ��ȡ��ϣֵ
        EVP_MD_CTX_free(context); // �ͷ�������

        // ����ϣ���ת��Ϊ 128 λ�����Ʊ�ʾ
        std::bitset<128> bitsetHash;
        for (int i = 0; i < static_cast<int>(digestLength); ++i) {
            std::bitset<8> byteBits(digest[i]);
            for (int j = 0; j < 8; ++j) {
                bitsetHash[i * 8 + j] = byteBits[j];
            }
        }

        return bitsetHash.to_string();
    }

    // �����ַ����� SimHash
    static std::string getSimHash(const std::wstring& str) {
        int v[128] = { 0 }; // ����һ��128λ����������

        std::wstring word;
        for (const auto& ch : str) {
            word += ch; // ģ��ִ�
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

        // ����������ת��Ϊ SimHash �������ַ���
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

// HammingUtils �ඨ��
class HammingUtils {
public:
    // ��������SimHashֵ֮��ĺ�������
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

    // ���ݺ�������������ƶ�
    static double getSimilarity(int distance) {
        return 1.0 - static_cast<double>(distance) / 128;
    }
};



// ��ȡ�ļ�����
std::wstring readFile(const std::wstring& filePath) {
    std::wifstream file(filePath);
    if (!file.is_open()) {
        std::wcerr << L"�޷����ļ�: " << filePath << std::endl;
        exit(1);
    }

    file.imbue(std::locale(file.getloc(), new std::codecvt_utf8<wchar_t>));

    std::wstringstream buffer;
    buffer << file.rdbuf();
    file.close();
    return buffer.str();
}

// ��stringת��Ϊwstring
std::wstring charToWstring(const std::string& str) {
    std::wstring_convert<std::codecvt_utf8_utf16<wchar_t>> converter;
    return converter.from_bytes(str);
}

// ������
int main(int argc, char* argv[]) {
    if (argc < 4) {
        std::cerr << "�÷�: " << argv[0] << " <E:\\test.RG\orig.txt> <E:\\test.RG\orig_0.8_add.txt> <E:\\test.RG\orig_0.8_del.txt> <E:\\test.RG\orig_0.8_dis_1.txt> <E:\\����ҵ�����ı�\orig_0.8_dis_10.txt> <E:\\test.RG\orig_0.8_dis_15.txt> <C:\\Users\86184\Desktop\input.txt>" << std::endl;
        return 1;
    }

    // ��ȡԭ�ĵ��ļ�·��
    std::wstring origFilePath = charToWstring(argv[1]);

    // ��ȡ���г�Ϯ�ı��ļ�·��
    std::vector<std::wstring> plagiarizedFilePaths;
    for (int i = 2; i < argc - 1; ++i) {
        plagiarizedFilePaths.push_back(charToWstring(argv[i]));
    }

    // ��ȡ����ļ�·��
    std::wstring outputFilePath = charToWstring(argv[argc - 1]);

    // ��ȡԭ�ĵ�����
    std::wstring origContent = readFile(origFilePath);

    // ������ļ�
    std::wofstream outFile(outputFilePath);
    if (!outFile.is_open()) {
        std::wcerr << L"�޷�д���ļ�: " << outputFilePath << std::endl;
        return 1;
    }

    // ����ÿ����Ϯ�ı�
    for (const std::wstring& plagiarizedFilePath : plagiarizedFilePaths) {
        // ��ȡ��Ϯ�ı�������
        std::wstring plagiarizedContent = readFile(plagiarizedFilePath);

        // ����ԭ�ĺͳ�Ϯ�ı���SimHashֵ
        std::string origSimHash = SimHash::getSimHash(origContent);
        std::string plagiarizedSimHash = SimHash::getSimHash(plagiarizedContent);

        // ���㺺������
        int hammingDistance = HammingUtils::getHammingDistance(origSimHash, plagiarizedSimHash);

        // �������ƶ�
        double similarity = HammingUtils::getSimilarity(hammingDistance);

        // ������������̨
        std::wcout << "ԭ���ļ�: " << origFilePath << std::endl;
        std::wcout << "��Ϯ�ļ�: " << plagiarizedFilePath << std::endl;
        std::wcout << "���ƶ�: " << similarity * 100 << L"%" << std::endl;
        std::wcout << "----------------------------" << std::endl;

        // ���������ļ�
        outFile << "ԭ���ļ�: " << origFilePath << std::endl;
        outFile << "��Ϯ�ļ�: " << plagiarizedFilePath << std::endl;
        outFile << "���ƶ�: " << similarity * 100 << L"%" << std::endl;
        outFile << "----------------------------" << std::endl;
    }

    std::wcout << "������ɣ�����������: " << outputFilePath << std::endl;

    return 0;
}
