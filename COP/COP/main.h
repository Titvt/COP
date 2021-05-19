#pragma once

#include <iostream>
#include <fstream>
#include <ctime>
#include <vector>
#include <map>
#include <random>
#include <Windows.h>
#include "Capstone/capstone.h"

#pragma comment(lib, "capstone.lib")

#define ASSERT(x) if (!(x)) { error = TRUE; return; }
#define ALIGN(x) ((x) + (0x1000ULL - ((x) & 0xFFFULL) & 0xFFFULL))
#define BETWEEN(x,y,z) ((x) >= (y) && (x) < (y) + (z))

using namespace std;

class COP;
class INSN;
class RELSEC;

typedef __int8 i8;
typedef i8* pi8;
typedef __int32 i32;
typedef i32* pi32;
typedef size_t* psize_t;
typedef cs_insn* pcs_insn;
typedef COP* PCOP;
typedef INSN* PINSN;
typedef RELSEC* PRELSEC;

#include "COP.h"
#include "INSN.h"
#include "RELSEC.h"