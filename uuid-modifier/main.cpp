//
//  main.cpp
//  uuid-modifier
//
//  Created by 张星宇 on 2019/3/20.
//  Copyright © 2019 张星宇. All rights reserved.
//

#include <iostream>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <LIEF/LIEF.hpp>

using namespace LIEF::MachO;
using namespace std;

const string validInstructionSets[2] = {"-arm64", "-armv7"};
const string usage = "Usage: bsUUIDModifier path/to/mach-o -armv7 3BC4C67F-XXXX-XXXX-XXXX-0863C5E33FCE -arm64 3BC4C67F-XXXX-XXXX-XXXX-0863C5E33FCE ... -o output_path";

bool isValidParams(int argc, const char * argv[]);
string parseOutputPath(int argc, const char * argv[]);

std::vector<uint8_t> rawUUID(string UUID);
bool isCurrentInstructionSet(Header h, string instructionSet);
size_t _GetFileSize(int fileDescriptor);
void modifyDsymUUID(char *contents, FatBinary *macho, string instructionSet, string UUID);

// Example format of LC_UUID command
// 1b 00 00 00  (1b 表示接下来是 LC_UUID，这个位置的下标就是 c->command_offset()。)
// 18 00 00 00  (18 是 16 进制表示，对应 10 进制是 24，表示 LC_UUID 这一段长度是 24 个字节)
// xx xx xx xx
// xx xx xx xx
// xx xx xx xx
// xx xx xx xx
// 上面一共 16 字节，加上一开始的 8 字节刚好是 24 字节
int main(int argc, const char * argv[]) {
    int fileDescriptor = open(argv[1], O_RDONLY, 0);
    if (fileDescriptor < 0) {
        cout << "Failed to open file" << endl;
        return 1;
    }
    size_t size = _GetFileSize(fileDescriptor);
    char *contents = static_cast<char*>(mmap(0, size, PROT_READ | PROT_WRITE, MAP_PRIVATE, fileDescriptor, 0));

    // 校验参数是否合法
    if (!isValidParams(argc, argv)) {
        return 1;
    }
    
    // 读取 mach-o 文件
    FatBinary *macho = Parser::parse(argv[1]);
    cout << "Finish loading and parsing file" << endl;
    
    // 对于每一种指令集，分别改写 UUID
    for (int i = 2; i < argc; i+=2) {
        string instructionSet(argv[i]);
        string UUID(argv[i+1]);
        modifyDsymUUID(contents, macho, instructionSet, UUID);
    }
    
    // 解析输出路径，并写回文件
    string outputPath = parseOutputPath(argc, argv);

    std::ofstream outputStream;
    outputStream.open(outputPath);
    outputStream.write((const char *)contents, size);
    cout << "Done" << endl;
    
    return 0;
}

void modifyDsymUUID(char *contents, FatBinary *macho, string instructionSet, string UUID) {
    // 先找到对应的指令集
    for (Binary &binary :*macho) {
        Header header = binary.header();
        // 根据 header 判断是不是当前需要处理的指令集，如果不是的话就略过
        if (!isCurrentInstructionSet(header, instructionSet)) {
            continue;
        }
        cout << "Modify uuid of instruction set: " << instructionSet << endl;
        
        // 开始处理，找到 LC_UUID 段，以及这一段的偏移量和大小
        UUIDCommand uuidCommand = binary.uuid();
        uint64_t binaryFatOffset = binary.fat_offset();
        uint64_t commandOffset = uuidCommand.command_offset();
        uint32_t commandSize = uuidCommand.size();

        // 生成新的 uuid 数据并逐个替换
        std::vector<uint8_t> newUUID = rawUUID(UUID);
        for (int i = 8; i < commandSize; ++i) {
            contents[binaryFatOffset + commandOffset + i] = newUUID[i - 8];
        }
    }
}

#pragma 校验判断指令集和 UUID
bool isValidInstructionSet(string instructionSet) {
    // 合法的指令集d数组的长度
    int length = sizeof(validInstructionSets) / sizeof(validInstructionSets[0]);
    for (int i = 0; i < length; ++i) {
        if (validInstructionSets[i] == instructionSet) {
            return true;
        }
    }
    cout << "Valid instruction set are: ";
    
    //Invalid instruction set: -arm64, -armv7
    for (int i = 0; i < length; ++i) {
        cout << validInstructionSets[i];
        if (i != length - 1) {
            cout << ", ";
        }
    }
    cout << endl << "Invalid instruction set: " << instructionSet << endl;
    return false;
}

bool isCurrentInstructionSet(Header h, string instructionSet) {
    // 新增指令集需要在这里拓展
    if (instructionSet == "-armv7") {
        return h.cpu_type() == CPU_TYPES::CPU_TYPE_ARM && h.cpu_subtype() == (int)CPU_SUBTYPES_ARM::CPU_SUBTYPE_ARM_V7;
    } else if (instructionSet == "-arm64") {
        return h.cpu_type() == CPU_TYPES::CPU_TYPE_ARM64 && h.cpu_subtype() == (int)CPU_SUBTYPES_ARM64::CPU_SUBTYPE_ARM64_ALL;
    } else {
        return false;
    }
}

bool isValidUUIDValue(string UUID) {
    int count = 0;
    int length = (int)UUID.size();
    
    for (int i = 0; i < length; ++i) {
        int c = UUID[i];
        if (c != '-') {
            if (!(c >= '0' && c <= '9') && !(c >= 'A' && c <= 'F')) {
                cerr << "Invalid UUID " << UUID << endl;
                cerr << "Valid characters are 0-9 and A-F" << endl;
                return false;
            }
            count += 1;
        }
    }
    
    if (count != 32) {
        cerr << "Invalid UUID " << UUID << endl;
        cerr << "There should be 32 characters (without `-`), such as: 3BC4C67F-BD0D-3B35-9827-08630F111012" << endl;
        return false;
    }
    return true;
}

bool isValidParams(int argc, const char * argv[]) {
    // 校验参数长度是否合法
    if (argc < 4 || argc % 2 != 0) {
        cout << usage << endl;
        return false;
    }
    
    // 校验参数值是否合法
    for (int i = 2; i < argc; i+=2) {
        string instructionSet(argv[i]);
        string UUID(argv[i+1]);
        
        if (instructionSet == "-o") { // -o 是专用参数，指定输出路径，因此不需要后续的判断逻辑
            continue;
        }
        if (!isValidInstructionSet(instructionSet) || !isValidUUIDValue(UUID)) {
            cout << usage << endl;
            return false;
        }
    }
    return true;
}

/**
 * 假设这里的 UUID 是合法的，在 Main 函数的一开始做校验
 */
vector<uint8_t> rawUUID(string UUID) {
    std::vector<uint8_t> raw;
    uint8_t characters[32];
    int characterIndex = 0;
    
    for (int i = 0; i < UUID.size(); ++i) {
        if (UUID[i] != '-') {
            unsigned int x;
            stringstream ss;
            ss << hex << UUID[i];
            ss >> x;
            characters[characterIndex++] = x;
        }
    }
    for (int i = 0; i < 32; i += 2) {
        uint8_t value = characters[i] * 16 + characters[i + 1];
        raw.push_back(value);
    }
    return raw;
}

#pragma Helper 辅助函数
string parseOutputPath(int argc, const char * argv[]) {
    string outputPath = argv[1];
    for (int i = 0; i < argc; ++i) {
        if (strcmp(argv[i], "-o") == 0) {
            return argv[i+1];
        }
    }
    return outputPath + ".modified";
}

size_t _GetFileSize(int fileDescriptor) {
    size_t length;
    struct stat statInfo;
    
    if (fstat(fileDescriptor, &statInfo) != 0) {
        return -1;
    } else {
        length = statInfo.st_size;
    }
    return length;
}
