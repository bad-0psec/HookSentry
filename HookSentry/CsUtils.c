#include "CsUtils.h"
#include "capstone.h"
#include <stdio.h>

void PrintDisasm(PVOID startAddr, SIZE_T size, DWORD64 vaAddr)
{
    csh handle;
    cs_err err;
    cs_insn* insn;
    size_t count;
    
    // Initialize Capstone for x86-64 disassembly
    err = cs_open(CS_ARCH_X86, CS_MODE_64, &handle);
    if (err != CS_ERR_OK) {
        wprintf(L"[!] Failed to initialize Capstone disassembler\n");
        return;
    }
    
    // Set disassembly options
    cs_option(handle, CS_OPT_DETAIL, CS_OPT_ON);
    cs_option(handle, CS_OPT_SYNTAX, CS_OPT_SYNTAX_INTEL);
    
    // Disassemble the code
    count = cs_disasm(handle, (uint8_t*)startAddr, size, vaAddr, 0, &insn);
    
    if (count == 0) {
        wprintf(L"[!] No instructions to disassemble\n");
        cs_close(&handle);
        return;
    }
    
    // Print each instruction
    for (size_t i = 0; i < count; i++) {
        wprintf(L"    0x%016llx\t", insn[i].address);
        
        // Print the instruction bytes
        for (size_t j = 0; j < insn[i].size && j < 8; j++) {
            wprintf(L"%02x ", insn[i].bytes[j]);
        }
        for (size_t j = insn[i].size; j < 8; j++) {
            wprintf(L"   ");
        }
        
        // Print the mnemonic and operands
        wprintf(L"\t%hs %hs\n", insn[i].mnemonic, insn[i].op_str);
    }
    
    // Free memory and close handle
    cs_free(insn, count);
    cs_close(&handle);
}
