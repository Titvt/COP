#pragma once

#include "main.h"

struct RELBLOCK
{
	size_t type;
	size_t address;
};

class RELSEC
{
public:
	RELSEC(BOOL);
	~RELSEC();

	VOID  input(size_t, size_t);
	VOID  input(size_t, size_t, size_t);
	PBYTE output(psize_t);

private:
	BOOL                          x64;
	PBYTE                         bytes;
	map<size_t, vector<RELBLOCK>> blocks;
};