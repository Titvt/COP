#include "main.h"

INT compare(LPCVOID p1, LPCVOID p2)
{
	return ((RELBLOCK*)p1)->address - ((RELBLOCK*)p2)->address;
}

RELSEC::RELSEC(BOOL x64) :
	x64(x64),
	bytes(NULL) {}

RELSEC::~RELSEC()
{
	// TODO
}

VOID RELSEC::input(size_t base, size_t address)
{
	input(base, x64 ? 0xAULL : 0x3ULL, address);
}

VOID RELSEC::input(size_t base, size_t type, size_t address)
{
	if (blocks.find(base) == blocks.end())
	{
		blocks[base] = vector<RELBLOCK>();
	}

	blocks[base].push_back({ type, address });
}

PBYTE RELSEC::output(psize_t length)
{
	PIMAGE_BASE_RELOCATION pImageBaseRelocation{};
	PBYTE                  curr{};
	size_t                 count{};
	size_t                 prev{};
	PUSHORT                pBlock{};

	if (bytes)
	{
		delete[] bytes;
		bytes = NULL;
	}

	*length = 0;

	for (auto& i : blocks)
	{
		qsort(&i.second[0], i.second.size(), sizeof(RELBLOCK), compare);

		count = i.second.size();

		prev = -1;

		for (size_t j = 0; j < count; j++)
		{
			if (i.second[j].address == prev)
			{
				i.second.erase(i.second.begin() + j);

				j--;
				count--;
			}

			prev = i.second[j].address;
		}

		*length += (i.second.size() + i.second.size() % 2) * 2 + sizeof(IMAGE_BASE_RELOCATION);
	}

	bytes = new BYTE[*length];
	RtlZeroMemory(bytes, *length);

	curr = bytes;

	for (auto& i : blocks)
	{
		pImageBaseRelocation = (PIMAGE_BASE_RELOCATION)curr;
		pImageBaseRelocation->VirtualAddress = i.first;
		pImageBaseRelocation->SizeOfBlock = (i.second.size() + i.second.size() % 2) * 2 + sizeof(IMAGE_BASE_RELOCATION);
		pBlock = (PUSHORT)(pImageBaseRelocation + 1);

		for (auto& j : i.second)
		{
			*pBlock++ = (j.type << 12) + j.address;
		}

		curr += pImageBaseRelocation->SizeOfBlock;
	}

	return bytes;
}