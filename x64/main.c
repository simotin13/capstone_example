#include <stdio.h>
#include <capstone/capstone.h>

int main() {
    // x86バイトコード (例としていくつかの基本的な命令)
    uint8_t code[] = { 0x55, 0x48, 0x8b, 0x05, 0xb8, 0x13, 0x00, 0x00 };
    size_t code_size = sizeof(code);

    // Capstoneの初期化
    csh handle;
    if (cs_open(CS_ARCH_X86, CS_MODE_64, &handle) != CS_ERR_OK) {
        fprintf(stderr, "Failed to initialize Capstone\n");
        return -1;
    }

    // 命令を逆アセンブル
    cs_insn *insn;
    size_t count = cs_disasm(handle, code, code_size, 0x1000, 0, &insn);
    if (count > 0) {
        for (size_t i = 0; i < count; i++) {
            printf("0x%"PRIx64":\t%s\t\t%s\n", 
                   insn[i].address, insn[i].mnemonic, insn[i].op_str);
        }
        cs_free(insn, count);
    } else {
        fprintf(stderr, "Failed to disassemble given code!\n");
    }

    // Capstoneの解放
    cs_close(&handle);

    return 0;
}
