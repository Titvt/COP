#pragma once

#include "main.h"

/*
	push eax
	push eax
	pushfd
	call $+5
	pop eax
	add / xor eax, 0xCCCCCCCC
	mov [esp+8], eax
	popfd
	pop eax
*/
CONST BYTE flowerA32[] = { 0x50, 0x50, 0x9C, 0xE8, 0x00, 0x00, 0x00, 0x00, 0x58, 0x05,
						   0xCC, 0xCC, 0xCC, 0xCC, 0x89, 0x44, 0x24, 0x08, 0x9D, 0x58 };
CONST BYTE flowerB32[] = { 0x50, 0x50, 0x9C, 0xE8, 0x00, 0x00, 0x00, 0x00, 0x58, 0x35,
						   0xCC, 0xCC, 0xCC, 0xCC, 0x89, 0x44, 0x24, 0x08, 0x9D, 0x58 };

#define FLOWER32_LEN 20
#define FLOWER32_ADDR_OFFSET 8
#define FLOWER32_VALUE_OFFSET 10

/*
	push rax
	push rax
	pushfq
	call $+5
	pop rax
	add / xor rax, 0xCCCCCCCC
	mov [rsp+16], rax
	popfq
	pop rax
*/
CONST BYTE flowerA64[] = { 0x50, 0x50, 0x9C, 0xE8, 0x00, 0x00, 0x00, 0x00, 0x58, 0x48, 0x05,
						   0xCC, 0xCC, 0xCC, 0xCC, 0x48, 0x89, 0x44, 0x24, 0x10, 0x9D, 0x58 };
CONST BYTE flowerB64[] = { 0x50, 0x50, 0x9C, 0xE8, 0x00, 0x00, 0x00, 0x00, 0x58, 0x48, 0x35,
						   0xCC, 0xCC, 0xCC, 0xCC, 0x48, 0x89, 0x44, 0x24, 0x10, 0x9D, 0x58 };

#define FLOWER64_LEN 22
#define FLOWER64_ADDR_OFFSET 8
#define FLOWER64_VALUE_OFFSET 11

// push eax / rax : 50
// push ebx / rbx : 53
// push ecx / rcx : 51
// push edx / rdx : 52
// pop eax / rax : 58
// pop ebx / rbx : 5B
// pop ecx / rcx : 59
// pop edx / rdx : 5A
CONST BYTE flowerC[][2] = { { 0x50, 0x58 },
							{ 0x53, 0x5B },
							{ 0x51, 0x59 },
							{ 0x52, 0x5A } };
CONST BYTE flowerD[][4] = { { 0x50, 0x50, 0x58, 0x58 },
							{ 0x50, 0x58, 0x50, 0x58 },
							{ 0x53, 0x53, 0x5B, 0x5B },
							{ 0x53, 0x5B, 0x53, 0x5B },
							{ 0x51, 0x51, 0x59, 0x59 },
							{ 0x51, 0x59, 0x51, 0x59 },
							{ 0x52, 0x52, 0x5A, 0x5A },
							{ 0x52, 0x5A, 0x52, 0x5A },
							{ 0x50, 0x58, 0x53, 0x5B },
							{ 0x50, 0x53, 0x5B, 0x58 },
							{ 0x50, 0x58, 0x51, 0x59 },
							{ 0x50, 0x51, 0x59, 0x58 },
							{ 0x50, 0x58, 0x52, 0x5A },
							{ 0x50, 0x52, 0x5A, 0x58 },
							{ 0x53, 0x5B, 0x50, 0x58 },
							{ 0x53, 0x50, 0x58, 0x5B },
							{ 0x53, 0x5B, 0x51, 0x59 },
							{ 0x53, 0x51, 0x59, 0x5B },
							{ 0x53, 0x5B, 0x52, 0x5A },
							{ 0x53, 0x52, 0x5A, 0x5B },
							{ 0x51, 0x59, 0x50, 0x58 },
							{ 0x51, 0x50, 0x58, 0x59 },
							{ 0x51, 0x59, 0x53, 0x5B },
							{ 0x51, 0x53, 0x5B, 0x59 },
							{ 0x51, 0x59, 0x52, 0x5A },
							{ 0x51, 0x52, 0x5A, 0x59 },
							{ 0x52, 0x5A, 0x50, 0x58 },
							{ 0x52, 0x50, 0x58, 0x5A },
							{ 0x52, 0x5A, 0x53, 0x5B },
							{ 0x52, 0x53, 0x5B, 0x5A },
							{ 0x52, 0x5A, 0x51, 0x59 },
							{ 0x52, 0x51, 0x59, 0x5A } };
enum INSN_TYPE
{
	INSN_UNTRANSED,
	INSN_NORMAL,
	INSN_JMP_REL,
	INSN_JMP_ABS,
	INSN_JCC,
	INSN_CALL_REL,
	INSN_CALL_ABS,
	INSN_RET
};

class INSN
{
public:
	BOOL           withRel;
	BOOL           ripBased;
	PBYTE          bytes;
	PBYTE          bytesEx;
	size_t         length;
	size_t         lengthEx;
	size_t         address;
	size_t         addressEx;
	size_t         prefix;
	size_t         targetEx;
	size_t         ripOffset;
	string         mnemonic;
	vector<size_t> pointers;

	INSN(BOOL, PBYTE, size_t, size_t, string);
	~INSN();

	VOID trans32();
	VOID setTarget32(size_t);
	VOID setTargetEx32(size_t);
	VOID trans64();
	VOID setTarget64(size_t);
	VOID setTargetEx64(size_t);
	VOID relocate(size_t, size_t);

private:
	INSN_TYPE type;
	BOOL      bnd;

	VOID flower();
};