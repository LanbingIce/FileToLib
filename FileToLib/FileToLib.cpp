#include <iostream>
#include <sstream>
#include <string>
#include <chrono>
#include <vector>
#include <Windows.h>
#include <fstream>
#include <filesystem>
#include <sstream>

using std::string;
using std::vector;
using std::cout;

namespace utils {
    template<typename T>
    static T convert(T v) {
        auto buf = (uint8_t*)&v;
        for (size_t i = 0; i < sizeof(T) / 2; i++) {
            uint8_t temp = buf[i];
            buf[i] = buf[sizeof(T) - i - 1];
            buf[sizeof(T) - i - 1] = temp;
        }
        return v;
    }

    static DWORD GetCurrentTimestamp() {
        auto now = std::chrono::system_clock::now();
        auto now_c = std::chrono::system_clock::to_time_t(now);
        return static_cast<DWORD>(now_c);
    }

    static string ReplaceInvalidCharacters(const string& str) {
        std::ostringstream oss;

        for (auto& c : str)
        {
            oss << (char)(isalnum(c) ? c : '_');
        }
        return oss.str();
    }

    static string ReplaceFilename(const std::string& str, const string& replacement) {
        string result(str);
        string target = "{filename}";
        size_t pos = str.find(target);
        while (pos != std::string::npos) {
            result.replace(pos, target.length(), replacement);
            pos = result.find(target, pos + replacement.length());
        }
        return result;
    }
}

struct SectionHeader {
    string Name;      // 名称 16
    string Time = std::to_string(utils::GetCurrentTimestamp());      // 时间 12
    string UserID = "";     // 用户ID  6
    string GroupID = "";    // 组ID   6
    string Mode = "0";       // 模式    8
    string Size;      // 长度 10
    string EndOfHeader = "`\n";// 结束符   2

    static string pad(const string& str, int size) {
        string result(str);
        result.resize(size, ' ');
        return result;
    }

    int GetSize() const {
        return 16 + 12 + 6 + 6 + 8 + 10 + 2;
    }

    friend std::ostream& operator<<(std::ostream& os, const SectionHeader& obj) {
        os << pad(obj.Name, 16);
        os << pad(obj.Time, 12);
        os << pad(obj.UserID, 6);
        os << pad(obj.GroupID, 6);
        os << pad(obj.Mode, 8);
        os << pad(obj.Size, 10);
        os << pad(obj.EndOfHeader, 2);
        return os;
    }
};

struct FirstSec {
    DWORD SymbolNum = 0;         // 库中符号的数量
    vector<DWORD> SymbolOffset;
    vector<string> StrTable;                // 符号名称字符串表

    void Add(const string& str) {
        SymbolOffset.push_back(0);
        StrTable.push_back(str);
        SymbolNum++;
    }

    int GetSize() const {
        int size = 0;
        size += sizeof(SymbolNum);

        for (auto& offset : SymbolOffset) {
            size += sizeof(offset);
        }

        for (auto& str : StrTable) {
            size += str.size() + 1;
        }

        return size;
    }

    friend std::ostream& operator<<(std::ostream& os, const FirstSec& obj) {
        auto temp = utils::convert(obj.SymbolNum);
        os.write((char*)&temp, sizeof(temp));
        for (auto& offset : obj.SymbolOffset) {
            auto temp = utils::convert(offset);
            os.write((char*)&temp, sizeof(temp));
        }
        for (auto& str : obj.StrTable) {
            os << str << '\0';
        }
        return os;
    }
};

struct SecondSec {
    DWORD ObjNum = 0;        // Obj Sec的数量
    vector<DWORD>ObjOffset;  // 每一个Obj Sec的偏移
    DWORD SymbolNum = 0;     // 库中符号的数量
    vector<WORD>SymbolIdx; // 符号在ObjOffset表中的索引
    vector<string> StrTable;            // 符号名称字符串表
    void AddObj() {
        ObjOffset.push_back(0);
        ObjNum++;
    }
    void AddSymbol(WORD index, const string& str) {
        SymbolIdx.push_back(index);
        StrTable.push_back(str);
        SymbolNum++;
    }

    int GetSize() const {
        int size = 0;
        size += sizeof(ObjNum);

        for (auto& offset : ObjOffset) {
            size += sizeof(offset);
        }

        size += sizeof(SymbolNum);

        for (auto& index : SymbolIdx) {
            size += sizeof(index);
        }

        for (auto& str : StrTable) {
            size += str.size() + 1;
        }

        return size;
    }

    friend std::ostream& operator<<(std::ostream& os, const SecondSec& obj) {
        os.write((char*)&obj.ObjNum, sizeof(obj.ObjNum));

        for (auto& offset : obj.ObjOffset) {
            os.write((char*)&offset, sizeof(offset));
        }
        os.write((char*)&obj.SymbolNum, sizeof(obj.SymbolNum));
        for (auto& index : obj.SymbolIdx) {
            os.write((char*)&index, sizeof(index));
        }

        for (auto& str : obj.StrTable) {
            os << str << '\0';
        }
        return os;
    }
};

struct LongnameSec {
    vector<string> StrTable;                // 符号名称字符串表

    void Add(const string& str) {
        StrTable.push_back(str);
    }

    int GetSize() const {
        int size = 0;
        for (auto& str : StrTable) {
            size += str.size() + 1;
        }
        return size;
    }

    friend std::ostream& operator<<(std::ostream& os, const LongnameSec& obj) {
        for (auto& str : obj.StrTable) {
            os << str << '\0';
        }
        return os;
    }
};

struct ObjSec {
    IMAGE_FILE_HEADER fileHeader{
        IMAGE_FILE_MACHINE_I386,//Machine
        1,//NumberOfSections
        utils::GetCurrentTimestamp(),//TimeDateStamp
        0,  //PointerToSymbolTable
        3,//NumberOfSymbols
        0,//SizeOfOptionalHeader
        IMAGE_FILE_32BIT_MACHINE | IMAGE_FILE_LINE_NUMS_STRIPPED //Characteristics
    };

    IMAGE_SECTION_HEADER sectionHeader{
        ".flat",    //Name
        0,    //Misc
        0,      //VirtualAddress
        0,     //SizeOfRawData
        sizeof(IMAGE_FILE_HEADER) + sizeof(IMAGE_SECTION_HEADER),       //PointerToRawData
        0,      //PointerToRelocations
        0,      //PointerToLinenumbers
        0,      //NumberOfRelocations
        0,      //NumberOfLinenumbers
        IMAGE_SCN_CNT_INITIALIZED_DATA | IMAGE_SCN_CNT_CODE     //Characteristics
    };

    string data;

    IMAGE_SYMBOL symbolTable1{
            ".flat",    //N
            0,      //Value
            1,      //SectionNumber
            IMAGE_SYM_TYPE_NULL,        //Type
            IMAGE_SYM_CLASS_STATIC,     //StorageClass
            0       //NumberOfAuxSymbols
    };

    IMAGE_SYMBOL symbolTableDataName{
        "",    //N
        0,      //Value
        1,      //SectionNumber
        IMAGE_SYM_TYPE_NULL,        //Type
        IMAGE_SYM_CLASS_EXTERNAL,     //StorageClass
        0       //NumberOfAuxSymbols
    };

    IMAGE_SYMBOL symbolTableSizeName{
    "",    //N
    0,      //Value
    1,      //SectionNumber
    IMAGE_SYM_TYPE_NULL,        //Type
    IMAGE_SYM_CLASS_EXTERNAL,     //StorageClass
    0       //NumberOfAuxSymbols
    };

    vector<string> strTable;

    int stringTableSize() const {
        int size = 0;
        for (auto& str : strTable) {
            size += str.size() + 1;
        }
        return size;
    }

    int GetSize() const {
        int size = 0;
        size += sizeof(IMAGE_FILE_HEADER);
        size += sizeof(IMAGE_SECTION_HEADER);
        size += data.size();
        size += sizeof(data.size());
        size += sizeof(IMAGE_SYMBOL);
        size += sizeof(IMAGE_SYMBOL);
        size += sizeof(IMAGE_SYMBOL);
        size += sizeof(stringTableSize());
        size += stringTableSize();
        return size;
    }

    ObjSec(string& data, string& dataName, string& sizeName) {
        this->data = data;
        fileHeader.PointerToSymbolTable = sectionHeader.PointerToRawData + data.size() + sizeof(data.size());
        sectionHeader.SizeOfRawData = data.size() + sizeof(data.size());
        if (dataName.size() <= 8)
        {
            strcpy_s((char*)&symbolTableDataName.N.ShortName, 8, dataName.c_str());
        }
        else
        {
            symbolTableDataName.N.Name.Short = 0;
            symbolTableDataName.N.Name.Long = stringTableSize() + 4;
            strTable.push_back(dataName);
        }

        symbolTableSizeName.Value = data.size();

        if (sizeName.size() <= 8)
        {
            strcpy_s((char*)&symbolTableSizeName.N.ShortName, 8, sizeName.c_str());
        }
        else
        {
            symbolTableSizeName.N.Name.Short = 0;
            symbolTableSizeName.N.Name.Long = stringTableSize() + 4;
            strTable.push_back(sizeName);
        }

    }

    friend std::ostream& operator<<(std::ostream& os, const ObjSec& obj) {
        os.write((char*)&obj.fileHeader, sizeof(obj.fileHeader));
        os.write((char*)&obj.sectionHeader, sizeof(obj.sectionHeader));
        os << obj.data;
        int size = obj.data.size();
        os.write((char*)&size, sizeof(size));
        os.write((char*)&obj.symbolTable1, sizeof(obj.symbolTable1));
        os.write((char*)&obj.symbolTableDataName, sizeof(obj.symbolTableDataName));
        os.write((char*)&obj.symbolTableSizeName, sizeof(obj.symbolTableSizeName));
        size = obj.stringTableSize() + 4;
        os.write((char*)&size, sizeof(size));
        for (auto& str : obj.strTable) {
            os << str << '\0';
        }
        return os;
    }
};



int main(int argc, char* argv[])
{
    if (argc < 2)
    {
        return 0;
    }

    std::filesystem::path path(argv[1]);
    std::ifstream file(path, std::ios::in | std::ios::binary);
    auto data = string((std::istreambuf_iterator<char>(file)), std::istreambuf_iterator<char>());
    string Signature = "!<arch>\n";
    string filename = path.stem().string();
    filename = utils::ReplaceInvalidCharacters(filename);
    string dataName = "_data_" + filename;
    string sizeName = "_size_" + filename;

    FirstSec firstSec;
    firstSec.Add(dataName);
    firstSec.Add(sizeName);

    SectionHeader firstSecHeader;
    firstSecHeader.Name = "/";
    firstSecHeader.Size = std::to_string(firstSec.GetSize());

    //SecondSec secondSec;
    //secondSec.AddObj();
    //secondSec.AddSymbol(1, dataName);
    //secondSec.AddSymbol(1, sizeName);

    //SectionHeader secondSecHeader;
    //secondSecHeader.Name = "/";
    //secondSecHeader.Size = std::to_string(secondSec.GetSize());

    LongnameSec longnameSec;

    SectionHeader longnameSecHeader;
    longnameSecHeader.Name = "//";
    longnameSecHeader.Size = std::to_string(longnameSec.GetSize());

    ObjSec objSec(data, dataName, sizeName);

    SectionHeader objSecHeader;
    objSecHeader.Name = "/0";
    objSecHeader.Mode = "100666";
    objSecHeader.Size = std::to_string(objSec.GetSize());

    int offset = 0;
    offset += Signature.size();
    offset += firstSecHeader.GetSize();
    offset += firstSec.GetSize();
    //offset += secondSecHeader.GetSize();
    //offset += secondSec.GetSize();
    offset += longnameSecHeader.GetSize();
    offset += longnameSec.GetSize();

    firstSec.SymbolOffset[0] = offset;
    firstSec.SymbolOffset[1] = offset;
    //secondSec.ObjOffset[0] = offset;

    path.replace_filename(path.stem().string() + ".lib");
    std::ofstream ofs(path, std::ios::binary);
    ofs << Signature;
    ofs << firstSecHeader << firstSec;
    // ofs << secondSecHeader << secondSec;
    ofs << longnameSecHeader << longnameSec;
    ofs << objSecHeader << objSec;

    std::streampos pos = ofs.tellp();
    if (pos % 2 == 1) {
        ofs << '\n';
    }

    string str = R"(
extern "C" size_t size_{filename};
extern "C" char data_{filename}[];
)";
   
    cout << utils::ReplaceFilename(str, filename);
    ofs.close();
    std::cin.get();

    return 0;
}
