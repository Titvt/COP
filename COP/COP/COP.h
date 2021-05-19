#pragma once

#include "main.h"

struct SECTION
{
	PBYTE  rawAddr;
	size_t rawLen;
	size_t virBase;
	size_t virLen;
	string name;
};

class COP
{
public:
	BOOL error;

	COP(string);
	~COP();
	VOID parse(BOOL);
	VOID output(string);

private:
	BOOL            x64;
	BOOL            withRel;
	BOOL            withCop;
	csh             handle;
	PRELSEC         pRelSec;
	PBYTE           fileImage;
	PBYTE           fileHeaderImage;
	PBYTE           sectionHeaderImage;
	PBYTE           extraSectionImage;
	PBYTE           fileImageEx;
	size_t          fileSize;
	size_t          fileHeaderSize;
	size_t          sectionHeaderSize;
	size_t          extraSectionSize;
	size_t          fileSizeEx;
	size_t          imageBase;
	size_t          entryPoint;
	size_t          extraSectionBase;
	vector<SECTION> sections;
	vector<PINSN>   insns;
	vector<PBYTE>   sectionImages;
	vector<size_t>  relPtrAddr;
	vector<size_t>  randIndex;

	VOID    parse32();
	VOID    disassemble32();
	VOID    obfuscate32();
	VOID    refix32();
	VOID    build32();
	VOID    parse64();
	VOID    disassemble64();
	VOID    obfuscate64();
	VOID    refix64();
	VOID    build64();
	SECTION getSection(string);
	size_t  getSectionIndex(string);
	size_t  getOffset(string, string, PBYTE, size_t);
};