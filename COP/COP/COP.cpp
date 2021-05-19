#include "main.h"

COP::COP(string filePath) :
	error(FALSE),
	x64(FALSE),
	withRel(FALSE),
	withCop(FALSE),
	handle(0),
	pRelSec(NULL),
	fileImage(NULL),
	fileHeaderImage(NULL),
	sectionHeaderImage(NULL),
	extraSectionImage(NULL),
	fileImageEx(NULL),
	fileSize(0),
	fileHeaderSize(0),
	sectionHeaderSize(0),
	extraSectionSize(0),
	fileSizeEx(0),
	imageBase(0),
	entryPoint(0),
	extraSectionBase(0)
{
	fstream           fs{};
	PIMAGE_DOS_HEADER pImageDosHeader{};
	PIMAGE_NT_HEADERS pImageNtHeader{};

	srand(time(NULL));

	fs.open(filePath, ios::in | ios::binary);
	fs.seekg(0, ios::end);

	fileSize = fs.tellg();
	fileImage = new BYTE[fileSize];

	fs.seekg(0, ios::beg);
	fs.read((PSTR)fileImage, fileSize);
	fs.close();

	pImageDosHeader = (PIMAGE_DOS_HEADER)fileImage;

	ASSERT(pImageDosHeader->e_magic == IMAGE_DOS_SIGNATURE);

	pImageNtHeader = (PIMAGE_NT_HEADERS)(pImageDosHeader->e_lfanew + fileImage);

	ASSERT(pImageNtHeader->Signature == IMAGE_NT_SIGNATURE);

	if (pImageNtHeader->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC)
	{
		x64 = FALSE;
	}
	else if (pImageNtHeader->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC)
	{
		x64 = TRUE;
	}
	else
	{
		ASSERT(FALSE);
	}
}

COP::~COP()
{
	// TODO
}

VOID COP::parse(BOOL withRel)
{
	if (!error)
	{
		this->withRel = withRel;

		x64 ? parse64() : parse32();
	}
}

VOID COP::output(string filePath)
{
	fstream fs{};

	if (!error)
	{
		fs.open(filePath, ios::out | ios::binary);
		fs.write((PSTR)fileImageEx, fileSizeEx);
		fs.close();
	}
}

VOID COP::parse32()
{
	PIMAGE_DOS_HEADER      pImageDosHeader{};
	PIMAGE_NT_HEADERS32    pImageNtHeader{};
	PIMAGE_SECTION_HEADER  pImageSectionHeader{};
	PIMAGE_BASE_RELOCATION pImageBaseRelocation{};
	PBYTE                  relAddr{};
	size_t                 sectionCount{};
	size_t                 textBase{};
	size_t                 textLen{};
	size_t                 copBase{};
	size_t                 copLen{};
	size_t                 relLen{};
	size_t                 blockSize{};
	size_t                 blockCount{};
	size_t                 blockAddr{};
	PUSHORT                pBlock{};

	ASSERT(cs_open(CS_ARCH_X86, CS_MODE_32, &handle) == CS_ERR_OK);

	if (withRel)
	{
		pRelSec = new RELSEC(FALSE);
	};

	pImageDosHeader = (PIMAGE_DOS_HEADER)fileImage;
	pImageNtHeader = (PIMAGE_NT_HEADERS32)(pImageDosHeader->e_lfanew + fileImage);

	imageBase = pImageNtHeader->OptionalHeader.ImageBase;
	entryPoint = pImageNtHeader->OptionalHeader.AddressOfEntryPoint + imageBase;

	fileHeaderSize = pImageDosHeader->e_lfanew + sizeof(IMAGE_NT_HEADERS32);
	fileHeaderImage = new BYTE[fileHeaderSize];
	RtlCopyMemory(fileHeaderImage, fileImage, fileHeaderSize);

	pImageSectionHeader = (PIMAGE_SECTION_HEADER)(pImageNtHeader + 1);
	sectionCount = pImageNtHeader->FileHeader.NumberOfSections;

	while (sectionCount--)
	{
		sections.push_back({ pImageSectionHeader->PointerToRawData + fileImage, pImageSectionHeader->SizeOfRawData, pImageSectionHeader->VirtualAddress + imageBase, pImageSectionHeader->Misc.VirtualSize, (PSTR)pImageSectionHeader->Name });

		pImageSectionHeader++;
	}

	withCop = getSectionIndex(".cop") != -1;

	ASSERT(getSectionIndex(".text") == 0
		&& getSectionIndex(".reloc") == sections.size() - 1
		&& (!withCop || getSectionIndex(".cop") == sections.size() - 2));

	textBase = getSection(".text").virBase;
	textLen = getSection(".text").virLen;

	if (withCop)
	{
		copBase = getSection(".cop").virBase;
		copLen = getSection(".cop").virLen;
	}

	relAddr = getSection(".reloc").rawAddr;
	relLen = getSection(".reloc").virLen;

	sectionHeaderSize = sections[0].rawAddr - fileImage - fileHeaderSize;
	sectionHeaderImage = new BYTE[sectionHeaderSize];
	RtlCopyMemory(sectionHeaderImage, pImageNtHeader + 1, sectionHeaderSize);

	pImageSectionHeader--;

	if (withCop)
	{
		pImageSectionHeader--;
	}

	extraSectionBase = pImageSectionHeader->VirtualAddress + imageBase;

	pImageSectionHeader = (PIMAGE_SECTION_HEADER)sectionHeaderImage;
	pImageSectionHeader->Misc.VirtualSize = pImageSectionHeader->SizeOfRawData;

	for (auto& i : sections)
	{
		sectionImages.push_back(new BYTE[i.rawLen]);
		RtlCopyMemory(sectionImages.back(), i.rawAddr, i.rawLen);
	}

	while (relLen)
	{
		pImageBaseRelocation = (PIMAGE_BASE_RELOCATION)relAddr;
		blockSize = pImageBaseRelocation->SizeOfBlock;
		blockCount = (blockSize - sizeof(IMAGE_BASE_RELOCATION)) / 2;
		pBlock = (PUSHORT)(pImageBaseRelocation + 1);

		for (size_t i = 0; i < blockCount; i++)
		{
			if (pBlock[i] == 0)
			{
				break;
			}

			blockAddr = (pBlock[i] & 0xFFFULL) + pImageBaseRelocation->VirtualAddress + imageBase;

			if (withRel)
			{
				if (!BETWEEN(blockAddr, textBase, textLen))
				{
					if (!withCop || !BETWEEN(blockAddr, copBase, copLen))
					{
						pRelSec->input(pImageBaseRelocation->VirtualAddress, pBlock[i] >> 12, pBlock[i] & 0xFFFULL);
					}
				}
			};

			for (auto& j : sections)
			{
				if (BETWEEN(blockAddr, j.virBase, j.virLen))
				{
					relPtrAddr.push_back(blockAddr);

					break;
				}
			}
		}

		relAddr += blockSize;
		relLen -= blockSize;
	}

	disassemble32();
}

VOID COP::disassemble32()
{
	pcs_insn pInsn{};
	size_t   insnCount{};
	string   mnemonic{};

	insnCount = cs_disasm(handle, getSection(".text").rawAddr, getSection(".text").virLen, getSection(".text").virBase, 0, &pInsn);

	ASSERT(insnCount > 0);

	for (size_t i = 0; i < insnCount; i++)
	{
		mnemonic = pInsn[i].mnemonic;

		if (mnemonic == "int3" && (insns.back()->mnemonic == "int3" || insns.back()->mnemonic == "ret"))
		{
			continue;
		}

		insns.push_back(new INSN(withRel, pInsn[i].bytes, pInsn[i].size, pInsn[i].address, mnemonic));

		for (auto& j : relPtrAddr)
		{
			if (BETWEEN(j, pInsn[i].address, pInsn[i].size))
			{
				insns.back()->pointers.push_back(j - pInsn[i].address);
			}
		}
	}

	cs_free(pInsn, insnCount);

	if (withCop)
	{
		insnCount = cs_disasm(handle, getSection(".cop").rawAddr, getSection(".cop").virLen, getSection(".cop").virBase, 0, &pInsn);

		ASSERT(insnCount > 0);

		for (size_t i = 0; i < insnCount; i++)
		{
			mnemonic = pInsn[i].mnemonic;

			if (mnemonic == "int3" && (insns.back()->mnemonic == "int3" || insns.back()->mnemonic == "ret"))
			{
				continue;
			}

			insns.push_back(new INSN(withRel, pInsn[i].bytes, pInsn[i].size, pInsn[i].address, mnemonic));

			for (auto& j : relPtrAddr)
			{
				if (BETWEEN(j, pInsn[i].address, pInsn[i].size))
				{
					insns.back()->pointers.push_back(j - pInsn[i].address);
				}
			}
		}

		cs_free(pInsn, insnCount);
	}

	obfuscate32();
}

VOID COP::obfuscate32()
{
	PINSN  currInsn{};
	size_t textBase{};
	size_t remainTextLen{};
	size_t insnIndex{};
	size_t insnLength{};

	textBase = getSection(".text").virBase;

	for (size_t i = 0; i < insns.size(); i++)
	{
		insns[i]->trans32();

		randIndex.push_back(i);
	}

	shuffle(randIndex.begin(), randIndex.end(), default_random_engine(time(NULL)));

	remainTextLen = getSection(".text").rawLen;
	currInsn = insns[randIndex[insnIndex]];

	while (currInsn->lengthEx <= remainTextLen)
	{
		currInsn->addressEx = textBase + insnLength;
		insnLength += currInsn->lengthEx;
		remainTextLen -= currInsn->lengthEx;

		currInsn = insns[randIndex[++insnIndex]];
	}

	for (size_t i = insnIndex; i < insns.size(); i++)
	{
		currInsn = insns[randIndex[i]];
		currInsn->addressEx = extraSectionBase + extraSectionSize;

		extraSectionSize += currInsn->lengthEx;
	}

	extraSectionSize = ALIGN(extraSectionSize);
	extraSectionImage = new BYTE[extraSectionSize];
	RtlFillMemory(extraSectionImage, extraSectionSize, 0xCC);

	for (size_t i = 0; i < insns.size() - 1; i++)
	{
		insns[i]->setTarget32(insns[i + 1]->addressEx + insns[i + 1]->prefix * !insns[i + 1]->withRel);

		for (auto& j : insns)
		{
			if (insns[i]->targetEx == j->address)
			{
				insns[i]->setTargetEx32(j->addressEx + j->prefix * !j->withRel);

				break;
			}
		}
	}

	refix32();
}

VOID COP::refix32()
{
	PINSN  currInsn{};
	PBYTE  sectionImage{};
	PBYTE  textAddr{};
	size_t textBase{};
	size_t remainTextLen{};
	size_t insnIndex{};
	size_t insnLength{};
	size_t pointer{};

	if (withCop)
	{
		for (size_t i = 2; i < insns.size(); i++)
		{
			if (insns[i - 2]->length == 5
				&& insns[i - 2]->bytes[0] == 0xE8
				&& *(pi32)(insns[i - 2]->bytes + 1) == 0
				&& insns[i - 1]->length == 1
				&& insns[i - 1]->bytes[0] == 0x58
				&& insns[i]->length == 5
				&& insns[i]->bytes[0] == 0x05)
			{
				pointer = *(pi32)(insns[i]->bytesEx + insns[i]->prefix + 1) + insns[i - 1]->address;

				for (auto& j : insns)
				{
					if (BETWEEN(pointer, j->address, j->length))
					{
						insns[i]->relocate(1, j->addressEx + j->prefix * !j->withRel + pointer - j->address - insns[i - 1]->addressEx - insns[i - 1]->prefix * !insns[i - 1]->withRel);

						break;
					}
				}
			}
		}
	}

	for (auto& i : insns)
	{
		for (auto& j : i->pointers)
		{
			if (withRel)
			{
				pRelSec->input(i->addressEx + i->prefix + j - imageBase & 0xFFFFFFFFFFFFF000ULL, i->addressEx + i->prefix + j - imageBase & 0xFFFULL);
			};

			pointer = *(pi32)(i->bytesEx + i->prefix + j);

			for (auto& k : insns)
			{
				if (BETWEEN(pointer, k->address, k->length))
				{
					i->relocate(j, k->addressEx + k->prefix * !k->withRel + pointer - k->address);

					break;
				}
			}
		}
	}

	for (auto& i : relPtrAddr)
	{
		for (auto& j : sections)
		{
			if (BETWEEN(i, j.virBase, j.virLen))
			{
				sectionImage = sectionImages[getSectionIndex(j.name)];

				for (auto& k : insns)
				{
					if (BETWEEN(*(PULONG32)(i - j.virBase + sectionImage), k->address, k->length))
					{
						*(PULONG32)(i - j.virBase + sectionImage) += k->addressEx + k->prefix * !k->withRel - k->address;

						break;
					}
				}

				break;
			}
		}
	}

	textAddr = sectionImages[getSectionIndex(".text")];
	remainTextLen = getSection(".text").rawLen;
	RtlFillMemory(textAddr, remainTextLen, 0xCC);
	currInsn = insns[randIndex[insnIndex]];

	while (currInsn->lengthEx <= remainTextLen)
	{
		RtlCopyMemory(textAddr + insnLength, currInsn->bytesEx, currInsn->lengthEx);
		insnLength += currInsn->lengthEx;
		remainTextLen -= currInsn->lengthEx;

		currInsn = insns[randIndex[++insnIndex]];
	}

	insnLength = 0;

	for (size_t i = insnIndex; i < insns.size(); i++)
	{
		currInsn = insns[randIndex[i]];
		RtlCopyMemory(extraSectionImage + insnLength, currInsn->bytesEx, currInsn->lengthEx);

		insnLength += currInsn->lengthEx;
	}

	build32();
}

VOID COP::build32()
{
	PIMAGE_DOS_HEADER     pImageDosHeader{};
	PIMAGE_NT_HEADERS32   pImageNtHeader{};
	PIMAGE_SECTION_HEADER pImageSectionHeader{};
	PBYTE                 relImage{};
	PBYTE                 currImage{};
	size_t                relSize{};
	size_t                sectionCount{};
	IMAGE_SECTION_HEADER  tempHeader{};

	if (withRel)
	{
		relImage = pRelSec->output(&relSize);
	};

	fileSizeEx = fileSize + extraSectionSize + ALIGN(relSize);

	if (withCop)
	{
		fileSizeEx -= getSection(".cop").rawLen;
	}

	fileImageEx = new BYTE[fileSizeEx];

	currImage = fileImageEx;

	for (size_t i = 0; i < insns.size(); i++)
	{
		if (insns[i]->address == entryPoint)
		{
			pImageDosHeader = (PIMAGE_DOS_HEADER)fileHeaderImage;
			pImageNtHeader = (PIMAGE_NT_HEADERS32)(pImageDosHeader->e_lfanew + fileHeaderImage);
			sectionCount = pImageNtHeader->FileHeader.NumberOfSections;
			pImageNtHeader->OptionalHeader.AddressOfEntryPoint = insns[i]->addressEx + insns[i]->prefix * !insns[i]->withRel - imageBase;
			pImageNtHeader->OptionalHeader.SizeOfImage = pImageNtHeader->OptionalHeader.SizeOfImage + extraSectionSize + relSize;

			if (withCop)
			{
				pImageNtHeader->FileHeader.NumberOfSections--;
				pImageNtHeader->OptionalHeader.SizeOfImage -= getSection(".cop").virLen + ALIGN(getSection(".reloc").virLen);
			}
			else
			{
				pImageNtHeader->OptionalHeader.SizeOfImage -= getSection(".reloc").virLen;
			}

			if (withRel)
			{
				pImageNtHeader->FileHeader.NumberOfSections++;
				pImageNtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress = extraSectionBase + extraSectionSize - imageBase;
				pImageNtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size = relSize;
			}
			else
			{
				pImageNtHeader->OptionalHeader.DllCharacteristics &= ~IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE;
				pImageNtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress = 0;
				pImageNtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size = 0;
			}

			break;
		}
	}

	ASSERT(sectionCount != 0);

	RtlCopyMemory(currImage, fileHeaderImage, fileHeaderSize);
	currImage += fileHeaderSize;

	pImageSectionHeader = (PIMAGE_SECTION_HEADER)sectionHeaderImage + getSectionIndex(".reloc") - withCop;
	pImageSectionHeader->Characteristics = IMAGE_SCN_CNT_CODE | IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_READ;
	pImageSectionHeader->Misc.VirtualSize = extraSectionSize;
	RtlZeroMemory(pImageSectionHeader->Name, 8);
	RtlCopyMemory(pImageSectionHeader->Name, ".cop", 5);
	pImageSectionHeader->SizeOfRawData = extraSectionSize;
	pImageSectionHeader->VirtualAddress = extraSectionBase - imageBase;

	pImageSectionHeader++;

	if (withRel)
	{
		pImageSectionHeader->Characteristics = IMAGE_SCN_CNT_INITIALIZED_DATA | IMAGE_SCN_MEM_DISCARDABLE | IMAGE_SCN_MEM_READ;
		pImageSectionHeader->Misc.VirtualSize = relSize;
		RtlCopyMemory(pImageSectionHeader->Name, ".reloc", 7);
		pImageSectionHeader->PointerToRawData = (pImageSectionHeader - 1)->PointerToRawData + extraSectionSize;
		pImageSectionHeader->SizeOfRawData = ALIGN(relSize);
		pImageSectionHeader->VirtualAddress = extraSectionBase + extraSectionSize - imageBase;
	}
	else
	{
		RtlZeroMemory(pImageSectionHeader, sizeof(IMAGE_SECTION_HEADER));
	}

	RtlCopyMemory(currImage, sectionHeaderImage, sectionHeaderSize);
	currImage += sectionHeaderSize;

	for (size_t i = 0; i < sectionCount - 1 - withCop; i++)
	{
		RtlCopyMemory(currImage, sectionImages[i], sections[i].rawLen);
		currImage += sections[i].rawLen;
	}

	RtlCopyMemory(currImage, extraSectionImage, extraSectionSize);
	currImage += extraSectionSize;

	if (withRel)
	{
		RtlCopyMemory(currImage, relImage, relSize);
		currImage += relSize;

		RtlZeroMemory(currImage, ALIGN(relSize) - relSize);
	}
}

VOID COP::parse64()
{
	PIMAGE_DOS_HEADER      pImageDosHeader{};
	PIMAGE_NT_HEADERS64    pImageNtHeader{};
	PIMAGE_SECTION_HEADER  pImageSectionHeader{};
	PIMAGE_BASE_RELOCATION pImageBaseRelocation{};
	PBYTE                  relAddr{};
	size_t                 sectionCount{};
	size_t                 textBase{};
	size_t                 textLen{};
	size_t                 copBase{};
	size_t                 copLen{};
	size_t                 relLen{};
	size_t                 blockSize{};
	size_t                 blockCount{};
	size_t                 blockAddr{};
	PUSHORT                pBlock{};

	ASSERT(cs_open(CS_ARCH_X86, CS_MODE_64, &handle) == CS_ERR_OK);

	if (withRel)
	{
		pRelSec = new RELSEC(TRUE);
	};

	pImageDosHeader = (PIMAGE_DOS_HEADER)fileImage;
	pImageNtHeader = (PIMAGE_NT_HEADERS64)(pImageDosHeader->e_lfanew + fileImage);

	imageBase = pImageNtHeader->OptionalHeader.ImageBase;
	entryPoint = pImageNtHeader->OptionalHeader.AddressOfEntryPoint + imageBase;

	fileHeaderSize = pImageDosHeader->e_lfanew + sizeof(IMAGE_NT_HEADERS64);
	fileHeaderImage = new BYTE[fileHeaderSize];
	RtlCopyMemory(fileHeaderImage, fileImage, fileHeaderSize);

	pImageSectionHeader = (PIMAGE_SECTION_HEADER)(pImageNtHeader + 1);
	sectionCount = pImageNtHeader->FileHeader.NumberOfSections;

	while (sectionCount--)
	{
		sections.push_back({ pImageSectionHeader->PointerToRawData + fileImage, pImageSectionHeader->SizeOfRawData, pImageSectionHeader->VirtualAddress + imageBase, pImageSectionHeader->Misc.VirtualSize, (PSTR)pImageSectionHeader->Name });

		pImageSectionHeader++;
	}

	withCop = getSectionIndex(".cop") != -1;

	ASSERT(getSectionIndex(".text") == 0
		&& getSectionIndex(".reloc") == sections.size() - 1
		&& (!withCop || getSectionIndex(".cop") == sections.size() - 2));

	textBase = getSection(".text").virBase;
	textLen = getSection(".text").virLen;

	if (withCop)
	{
		copBase = getSection(".cop").virBase;
		copLen = getSection(".cop").virLen;
	}

	relAddr = getSection(".reloc").rawAddr;
	relLen = getSection(".reloc").virLen;

	sectionHeaderSize = sections[0].rawAddr - fileImage - fileHeaderSize;
	sectionHeaderImage = new BYTE[sectionHeaderSize];
	RtlCopyMemory(sectionHeaderImage, pImageNtHeader + 1, sectionHeaderSize);

	pImageSectionHeader--;

	if (withCop)
	{
		pImageSectionHeader--;
	}

	extraSectionBase = pImageSectionHeader->VirtualAddress + imageBase;

	pImageSectionHeader = (PIMAGE_SECTION_HEADER)sectionHeaderImage;
	pImageSectionHeader->Misc.VirtualSize = pImageSectionHeader->SizeOfRawData;

	for (auto& i : sections)
	{
		sectionImages.push_back(new BYTE[i.rawLen]);
		RtlCopyMemory(sectionImages.back(), i.rawAddr, i.rawLen);
	}

	while (relLen)
	{
		pImageBaseRelocation = (PIMAGE_BASE_RELOCATION)relAddr;
		blockSize = pImageBaseRelocation->SizeOfBlock;
		blockCount = (blockSize - sizeof(IMAGE_BASE_RELOCATION)) / 2;
		pBlock = (PUSHORT)(pImageBaseRelocation + 1);

		for (size_t i = 0; i < blockCount; i++)
		{
			if (pBlock[i] == 0)
			{
				break;
			}

			blockAddr = (pBlock[i] & 0xFFFULL) + pImageBaseRelocation->VirtualAddress + imageBase;

			if (withRel)
			{
				if (!BETWEEN(blockAddr, textBase, textLen))
				{
					if (!withCop || !BETWEEN(blockAddr, copBase, copLen))
					{
						pRelSec->input(pImageBaseRelocation->VirtualAddress, pBlock[i] >> 12, pBlock[i] & 0xFFFULL);
					}
				}
			};

			for (auto& j : sections)
			{
				if (BETWEEN(blockAddr, j.virBase, j.virLen))
				{
					relPtrAddr.push_back(blockAddr);

					break;
				}
			}
		}

		relAddr += blockSize;
		relLen -= blockSize;
	}

	disassemble64();
}

VOID COP::disassemble64()
{
	pcs_insn pInsn{};
	size_t   insnCount{};
	string   mnemonic{};

	insnCount = cs_disasm(handle, getSection(".text").rawAddr, getSection(".text").virLen, getSection(".text").virBase, 0, &pInsn);

	ASSERT(insnCount > 0);

	for (size_t i = 0; i < insnCount; i++)
	{
		mnemonic = pInsn[i].mnemonic;

		if (mnemonic == "int3" && (insns.back()->mnemonic == "int3" || insns.back()->mnemonic == "ret"))
		{
			continue;
		}

		insns.push_back(new INSN(withRel, pInsn[i].bytes, pInsn[i].size, pInsn[i].address, mnemonic));

		if (strstr(pInsn[i].op_str, "rip") != NULL)
		{
			insns.back()->ripBased = TRUE;
			insns.back()->ripOffset = getOffset(mnemonic, pInsn[i].op_str, pInsn[i].bytes, pInsn[i].size);
		}

		for (auto& j : relPtrAddr)
		{
			if (BETWEEN(j, pInsn[i].address, pInsn[i].size))
			{
				insns.back()->pointers.push_back(j - pInsn[i].address);
			}
		}
	}

	cs_free(pInsn, insnCount);

	if (withCop)
	{
		insnCount = cs_disasm(handle, getSection(".cop").rawAddr, getSection(".cop").virLen, getSection(".cop").virBase, 0, &pInsn);

		ASSERT(insnCount > 0);

		for (size_t i = 0; i < insnCount; i++)
		{
			mnemonic = pInsn[i].mnemonic;

			if (mnemonic == "int3" && (insns.back()->mnemonic == "int3" || insns.back()->mnemonic == "ret"))
			{
				continue;
			}

			insns.push_back(new INSN(withRel, pInsn[i].bytes, pInsn[i].size, pInsn[i].address, mnemonic));

			if (strstr(pInsn[i].op_str, "rip") != NULL)
			{
				insns.back()->ripBased = TRUE;
				insns.back()->ripOffset = getOffset(mnemonic, pInsn[i].op_str, pInsn[i].bytes, pInsn[i].size);
			}

			for (auto& j : relPtrAddr)
			{
				if (BETWEEN(j, pInsn[i].address, pInsn[i].size))
				{
					insns.back()->pointers.push_back(j - pInsn[i].address);
				}
			}
		}

		cs_free(pInsn, insnCount);
	}

	obfuscate64();
}

VOID COP::obfuscate64()
{
	PINSN  currInsn{};
	size_t textBase{};
	size_t remainTextLen{};
	size_t insnIndex{};
	size_t insnLength{};

	textBase = getSection(".text").virBase;

	for (size_t i = 0; i < insns.size(); i++)
	{
		insns[i]->trans64();

		randIndex.push_back(i);
	}

	shuffle(randIndex.begin(), randIndex.end(), default_random_engine(time(NULL)));

	remainTextLen = getSection(".text").rawLen;
	currInsn = insns[randIndex[insnIndex]];

	while (currInsn->lengthEx <= remainTextLen)
	{
		currInsn->addressEx = textBase + insnLength;
		insnLength += currInsn->lengthEx;
		remainTextLen -= currInsn->lengthEx;

		currInsn = insns[randIndex[++insnIndex]];
	}

	for (size_t i = insnIndex; i < insns.size(); i++)
	{
		currInsn = insns[randIndex[i]];
		currInsn->addressEx = extraSectionBase + extraSectionSize;

		extraSectionSize += currInsn->lengthEx;
	}

	extraSectionSize = ALIGN(extraSectionSize);
	extraSectionImage = new BYTE[extraSectionSize];
	RtlFillMemory(extraSectionImage, extraSectionSize, 0xCC);

	for (size_t i = 0; i < insns.size() - 1; i++)
	{
		insns[i]->setTarget64(insns[i + 1]->addressEx + insns[i + 1]->prefix * !insns[i + 1]->withRel);

		for (auto& j : insns)
		{
			if (insns[i]->targetEx == j->address)
			{
				insns[i]->setTargetEx64(j->addressEx + j->prefix * !j->withRel);

				break;
			}
		}
	}

	refix64();
}

VOID COP::refix64()
{
	PINSN  currInsn{};
	PBYTE  sectionImage{};
	PBYTE  textAddr{};
	size_t textBase{};
	size_t remainTextLen{};
	size_t insnIndex{};
	size_t insnLength{};
	size_t pointer{};
	BOOL   redirected{};

	for (auto& i : insns)
	{
		if (i->ripBased)
		{
			redirected = FALSE;

			for (auto& j : insns)
			{
				if (j->address == i->address + i->length + *(pi32)(i->bytes + i->length - 4 - i->ripOffset))
				{
					i->relocate(i->length - 4 - i->ripOffset, j->addressEx + j->prefix * !j->withRel - i->addressEx - i->prefix - i->length);

					redirected = TRUE;

					break;
				}
			}

			if (!redirected)
			{
				i->relocate(i->length - 4 - i->ripOffset, *(pi32)(i->bytes + i->length - 4 - i->ripOffset) - i->addressEx - i->prefix + i->address);
			}
		}
	}

	if (getSectionIndex(".pdata") != -1)
	{
		RtlZeroMemory(sectionImages[getSectionIndex(".pdata")], getSection(".pdata").rawLen);
	}

	if (withCop)
	{
		for (size_t i = 2; i < insns.size(); i++)
		{
			if (insns[i - 2]->length == 5
				&& insns[i - 2]->bytes[0] == 0xE8
				&& *(pi32)(insns[i - 2]->bytes + 1) == 0
				&& insns[i - 1]->length == 1
				&& insns[i - 1]->bytes[0] == 0x58
				&& insns[i]->length == 6
				&& insns[i]->bytes[0] == 0x48
				&& insns[i]->bytes[1] == 0x05)
			{
				pointer = *(pi32)(insns[i]->bytesEx + insns[i]->prefix + 2) + insns[i - 1]->address;

				for (auto& j : insns)
				{
					if (BETWEEN(pointer, j->address, j->length))
					{
						insns[i]->relocate(2, j->addressEx + j->prefix * !j->withRel + pointer - j->address - insns[i - 1]->addressEx - insns[i - 1]->prefix * !insns[i - 1]->withRel);

						break;
					}
				}
			}
		}
	}

	for (auto& i : insns)
	{
		for (auto& j : i->pointers)
		{
			if (withRel)
			{
				pRelSec->input(i->addressEx + i->prefix + j - imageBase & 0xFFFFFFFFFFFFF000ULL, i->addressEx + i->prefix + j - imageBase & 0xFFFULL);
			};

			pointer = *(pi32)(i->bytesEx + i->prefix + j);

			for (auto& k : insns)
			{
				if (BETWEEN(pointer, k->address, k->length))
				{
					i->relocate(j, k->addressEx + k->prefix * !k->withRel + pointer - k->address);

					break;
				}
			}
		}
	}

	for (auto& i : relPtrAddr)
	{
		for (auto& j : sections)
		{
			if (BETWEEN(i, j.virBase, j.virLen))
			{
				sectionImage = sectionImages[getSectionIndex(j.name)];

				for (auto& k : insns)
				{
					if (BETWEEN(*(PULONG64)(i - j.virBase + sectionImage), k->address, k->length))
					{
						*(PULONG64)(i - j.virBase + sectionImage) += k->addressEx + k->prefix * !k->withRel - k->address;

						break;
					}
				}

				break;
			}
		}
	}

	textAddr = sectionImages[getSectionIndex(".text")];
	remainTextLen = getSection(".text").rawLen;
	RtlFillMemory(textAddr, remainTextLen, 0xCC);
	currInsn = insns[randIndex[insnIndex]];

	while (currInsn->lengthEx <= remainTextLen)
	{
		RtlCopyMemory(textAddr + insnLength, currInsn->bytesEx, currInsn->lengthEx);
		insnLength += currInsn->lengthEx;
		remainTextLen -= currInsn->lengthEx;

		currInsn = insns[randIndex[++insnIndex]];
	}

	insnLength = 0;

	for (size_t i = insnIndex; i < insns.size(); i++)
	{
		currInsn = insns[randIndex[i]];
		RtlCopyMemory(extraSectionImage + insnLength, currInsn->bytesEx, currInsn->lengthEx);

		insnLength += currInsn->lengthEx;
	}

	build64();
}

VOID COP::build64()
{
	PIMAGE_DOS_HEADER     pImageDosHeader{};
	PIMAGE_NT_HEADERS64   pImageNtHeader{};
	PIMAGE_SECTION_HEADER pImageSectionHeader{};
	PBYTE                 relImage{};
	PBYTE                 currImage{};
	size_t                relSize{};
	size_t                sectionCount{};
	IMAGE_SECTION_HEADER  tempHeader{};

	if (withRel)
	{
		relImage = pRelSec->output(&relSize);
	};

	fileSizeEx = fileSize + extraSectionSize + ALIGN(relSize);

	if (withCop)
	{
		fileSizeEx -= getSection(".cop").rawLen;
	}

	fileImageEx = new BYTE[fileSizeEx];

	currImage = fileImageEx;

	for (size_t i = 0; i < insns.size(); i++)
	{
		if (insns[i]->address == entryPoint)
		{
			pImageDosHeader = (PIMAGE_DOS_HEADER)fileHeaderImage;
			pImageNtHeader = (PIMAGE_NT_HEADERS64)(pImageDosHeader->e_lfanew + fileHeaderImage);
			sectionCount = pImageNtHeader->FileHeader.NumberOfSections;
			pImageNtHeader->OptionalHeader.AddressOfEntryPoint = insns[i]->addressEx + insns[i]->prefix * !insns[i]->withRel - imageBase;
			pImageNtHeader->OptionalHeader.SizeOfImage = pImageNtHeader->OptionalHeader.SizeOfImage + extraSectionSize + relSize;

			if (withCop)
			{
				pImageNtHeader->FileHeader.NumberOfSections--;
				pImageNtHeader->OptionalHeader.SizeOfImage -= getSection(".cop").virLen + ALIGN(getSection(".reloc").virLen);
			}
			else
			{
				pImageNtHeader->OptionalHeader.SizeOfImage -= getSection(".reloc").virLen;
			}

			if (withRel)
			{
				pImageNtHeader->FileHeader.NumberOfSections++;
				pImageNtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress = extraSectionBase + extraSectionSize - imageBase;
				pImageNtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size = relSize;
			}
			else
			{
				pImageNtHeader->OptionalHeader.DllCharacteristics &= ~IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE;
				pImageNtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress = 0;
				pImageNtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size = 0;
			}

			break;
		}
	}

	ASSERT(sectionCount != 0);

	RtlCopyMemory(currImage, fileHeaderImage, fileHeaderSize);
	currImage += fileHeaderSize;

	pImageSectionHeader = (PIMAGE_SECTION_HEADER)sectionHeaderImage + getSectionIndex(".reloc") - withCop;
	pImageSectionHeader->Characteristics = IMAGE_SCN_CNT_CODE | IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_READ;
	pImageSectionHeader->Misc.VirtualSize = extraSectionSize;
	RtlZeroMemory(pImageSectionHeader->Name, 8);
	RtlCopyMemory(pImageSectionHeader->Name, ".cop", 5);
	pImageSectionHeader->SizeOfRawData = extraSectionSize;
	pImageSectionHeader->VirtualAddress = extraSectionBase - imageBase;

	pImageSectionHeader++;

	if (withRel)
	{
		pImageSectionHeader->Characteristics = IMAGE_SCN_CNT_INITIALIZED_DATA | IMAGE_SCN_MEM_DISCARDABLE | IMAGE_SCN_MEM_READ;
		pImageSectionHeader->Misc.VirtualSize = relSize;
		RtlCopyMemory(pImageSectionHeader->Name, ".reloc", 7);
		pImageSectionHeader->PointerToRawData = (pImageSectionHeader - 1)->PointerToRawData + extraSectionSize;
		pImageSectionHeader->SizeOfRawData = ALIGN(relSize);
		pImageSectionHeader->VirtualAddress = extraSectionBase + extraSectionSize - imageBase;
	}
	else
	{
		RtlZeroMemory(pImageSectionHeader, sizeof(IMAGE_SECTION_HEADER));
	}

	RtlCopyMemory(currImage, sectionHeaderImage, sectionHeaderSize);
	currImage += sectionHeaderSize;

	for (size_t i = 0; i < sectionCount - 1 - withCop; i++)
	{
		RtlCopyMemory(currImage, sectionImages[i], sections[i].rawLen);
		currImage += sections[i].rawLen;
	}

	RtlCopyMemory(currImage, extraSectionImage, extraSectionSize);
	currImage += extraSectionSize;

	if (withRel)
	{
		RtlCopyMemory(currImage, relImage, relSize);
		currImage += relSize;

		RtlZeroMemory(currImage, ALIGN(relSize) - relSize);
	}
}

SECTION COP::getSection(string name)
{
	for (auto& i : sections)
	{
		if (i.name == name)
		{
			return i;
		}
	}
}

size_t COP::getSectionIndex(string name)
{
	for (size_t i = 0; i < sections.size(); i++)
	{
		if (sections[i].name == name)
		{
			return i;
		}
	}

	return -1;
}

size_t COP::getOffset(string mnemonic, string op, PBYTE bytes, size_t length)
{
	string sub{};
	size_t opValue{};
	size_t bytesValue{};

	if (op.find(",") == string::npos || op.find(",") < op.find("rip"))
	{
		return 0;
	}

	sub = op.substr(op.find(",") + 2);

	if (sub.find("x") != string::npos && sub.find("0x") == string::npos
		|| sub.find("r") != string::npos
		|| sub.find("i") != string::npos
		|| sub.find("p") != string::npos
		|| sub.find("h") != string::npos
		|| sub.find("l") != string::npos)
	{
		return 0;
	}

	sscanf_s(sub.c_str(), "%llx", &opValue);

	if (op.find("qword") != string::npos)
	{
		if (length > 8)
		{
			bytesValue = 0;
			RtlCopyMemory(&bytesValue, bytes + length - 8, 8);

			if (opValue == bytesValue)
			{
				return 8;
			}
		}

		bytesValue = 0;
		RtlCopyMemory(&bytesValue, bytes + length - 1, 1);

		if (bytesValue >> 7)
		{
			RtlFillMemory((PBYTE)&bytesValue + 1, 7, 0xFF);
		}

		if (opValue == bytesValue)
		{
			return 1;
		}
	}

	if (op.find("dword") != string::npos)
	{
		if (length > 4)
		{
			bytesValue = 0;
			RtlCopyMemory(&bytesValue, bytes + length - 4, 4);

			if (opValue == bytesValue)
			{
				return 4;
			}
		}

		bytesValue = 0;
		RtlCopyMemory(&bytesValue, bytes + length - 1, 1);

		if (bytesValue >> 7)
		{
			RtlFillMemory((PBYTE)&bytesValue + 1, 3, 0xFF);
		}

		if (opValue == bytesValue)
		{
			return 1;
		}
	}

	if (op.find("word") != string::npos)
	{
		if (length > 2)
		{
			bytesValue = 0;
			RtlCopyMemory(&bytesValue, bytes + length - 2, 2);

			if (opValue == bytesValue)
			{
				return 2;
			}
		}

		bytesValue = 0;
		RtlCopyMemory(&bytesValue, bytes + length - 1, 1);

		if (bytesValue >> 7)
		{
			RtlFillMemory((PBYTE)&bytesValue + 1, 1, 0xFF);
		}

		if (opValue == bytesValue)
		{
			return 1;
		}
	}

	if (op.find("byte") != string::npos)
	{
		bytesValue = 0;
		RtlCopyMemory(&bytesValue, bytes + length - 1, 1);

		if (opValue == bytesValue)
		{
			return 1;
		}
	}

	return 0;
}