#include <stdio.h>
#include <capstone/capstone.h>

int main() {
    // 逆アセンブルする RISC-V バイナリコード
    uint8_t code[] = { 0x13, 0x05, 0x00, 0x00, 0x93, 0x85, 0x05, 0x00, 0x33, 0x85, 0x06, 0x00, 0x03, 0xa5, 0x06, 0x00 };
    size_t code_size = sizeof(code);
    uint64_t address = 0x1000;  // 開始アドレス

    csh handle;
    cs_insn *insn;
    size_t count;

    // Capstone を初期化 (RISC-V 64-bit)
    if (cs_open(CS_ARCH_RISCV, CS_MODE_RISCV64, &handle) != CS_ERR_OK) {
        fprintf(stderr, "Failed to initialize Capstone\n");
        return -1;
    }

    // 逆アセンブルの実行
    count = cs_disasm(handle, code, code_size, address, 0, &insn);
    if (count > 0) {
        for (size_t i = 0; i < count; i++) {
            printf("0x%"PRIx64":\t%s\t%s\n", insn[i].address, insn[i].mnemonic, insn[i].op_str);
        }

        // 命令メモリの解放
        cs_free(insn, count);
    } else {
        fprintf(stderr, "Failed to disassemble given code!\n");
    }

    // Capstone のクリーンアップ
    cs_close(&handle);

    return 0;
}

