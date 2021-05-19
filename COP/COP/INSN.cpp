#include "main.h"

INSN::INSN(BOOL withRel, PBYTE bytes, size_t length, size_t address, string mnemonic) :
	type(INSN_UNTRANSED),
	withRel(withRel),
	ripBased(FALSE),
	bytesEx(NULL),
	length(length),
	lengthEx(0),
	address(address),
	addressEx(0),
	targetEx(0),
	ripOffset(0)
{
	this->bytes = new BYTE[length];
	RtlCopyMemory(this->bytes, bytes, length);

	if (mnemonic.length() > 4 && mnemonic.substr(0, 4) == "bnd ")
	{
		bnd = TRUE;
		this->mnemonic = mnemonic.substr(4);
	}
	else
	{
		bnd = FALSE;
		this->mnemonic = mnemonic;
	}

	prefix = withRel ? rand() % 3 * 2 : rand() % 4 + 1;
}

INSN::~INSN()
{
	// TODO
}

VOID INSN::trans32()
{
	size_t jcc{};

	if (mnemonic == "jmp")
	{
		if (bytes[bnd] == 0xEB)
		{
			type = INSN_JMP_REL;
			lengthEx = prefix + FLOWER32_LEN + 1;
			bytesEx = new BYTE[lengthEx];

			flower();

			RtlCopyMemory(bytesEx + prefix, withRel ? flowerA32 : flowerB32, FLOWER32_LEN);

			bytesEx[prefix + FLOWER32_LEN] = 0xC3;

			targetEx = address + 2 + bnd + *(pi8)(bytes + 1 + bnd);
		}
		else if (bytes[bnd] == 0xE9)
		{
			type = INSN_JMP_REL;
			lengthEx = prefix + FLOWER32_LEN + 1;
			bytesEx = new BYTE[lengthEx];

			flower();

			RtlCopyMemory(bytesEx + prefix, withRel ? flowerA32 : flowerB32, FLOWER32_LEN);

			bytesEx[prefix + FLOWER32_LEN] = 0xC3;

			targetEx = address + 5 + bnd + *(pi32)(bytes + 1 + bnd);
		}
		else
		{
			type = INSN_JMP_ABS;
			lengthEx = prefix + length;
			bytesEx = new BYTE[lengthEx];

			flower();

			RtlCopyMemory(bytesEx + prefix, bytes, length);
		}
	}
	else if (mnemonic[0] == 'j')
	{
		if (mnemonic == "jno")
		{
			jcc = 0x70;
		}
		else if (mnemonic == "jo")
		{
			jcc = 0x71;
		}
		else if (mnemonic == "jnc" || mnemonic == "jnb" || mnemonic == "jae")
		{
			jcc = 0x72;
		}
		else if (mnemonic == "jc" || mnemonic == "jb" || mnemonic == "jnae")
		{
			jcc = 0x73;
		}
		else if (mnemonic == "jnz" || mnemonic == "jne")
		{
			jcc = 0x74;
		}
		else if (mnemonic == "jz" || mnemonic == "je")
		{
			jcc = 0x75;
		}
		else if (mnemonic == "jnbe" || mnemonic == "ja")
		{
			jcc = 0x76;
		}
		else if (mnemonic == "jbe" || mnemonic == "jna")
		{
			jcc = 0x77;
		}
		else if (mnemonic == "jns")
		{
			jcc = 0x78;
		}
		else if (mnemonic == "js")
		{
			jcc = 0x79;
		}
		else if (mnemonic == "jnp" || mnemonic == "jpo")
		{
			jcc = 0x7A;
		}
		else if (mnemonic == "jp" || mnemonic == "jpe")
		{
			jcc = 0x7B;
		}
		else if (mnemonic == "jnl" || mnemonic == "jge")
		{
			jcc = 0x7C;
		}
		else if (mnemonic == "jl" || mnemonic == "jnge")
		{
			jcc = 0x7D;
		}
		else if (mnemonic == "jnle" || mnemonic == "jg")
		{
			jcc = 0x7E;
		}
		else if (mnemonic == "jle" || mnemonic == "jng")
		{
			jcc = 0x7F;
		}

		type = INSN_JCC;
		lengthEx = prefix + 2 + FLOWER32_LEN + 1 + FLOWER32_LEN + 1;
		bytesEx = new BYTE[lengthEx];

		flower();

		bytesEx[prefix] = jcc;
		bytesEx[prefix + 1] = FLOWER32_LEN + 1;

		RtlCopyMemory(bytesEx + prefix + 2, withRel ? flowerA32 : flowerB32, FLOWER32_LEN);

		bytesEx[prefix + 2 + FLOWER32_LEN] = 0xC3;

		RtlCopyMemory(bytesEx + prefix + 2 + FLOWER32_LEN + 1, withRel ? flowerA32 : flowerB32, FLOWER32_LEN);

		bytesEx[prefix + 2 + FLOWER32_LEN + 1 + FLOWER32_LEN] = 0xC3;

		if (bytes[bnd] == 0x0F)
		{
			targetEx = address + 6 + bnd + *(pi32)(bytes + 2 + bnd);
		}
		else
		{
			targetEx = address + 2 + bnd + *(pi8)(bytes + 1 + bnd);
		}
	}
	else if (mnemonic == "call")
	{
		if (bytes[bnd] == 0xE8)
		{
			type = INSN_CALL_REL;
			lengthEx = prefix + FLOWER32_LEN + FLOWER32_LEN + 1;
			bytesEx = new BYTE[lengthEx];

			flower();

			RtlCopyMemory(bytesEx + prefix, withRel ? flowerA32 : flowerB32, FLOWER32_LEN);
			RtlCopyMemory(bytesEx + prefix + FLOWER32_LEN, withRel ? flowerA32 : flowerB32, FLOWER32_LEN);

			bytesEx[prefix + FLOWER32_LEN + FLOWER32_LEN] = 0xC3;

			targetEx = address + 5 + bnd + *(pi32)(bytes + 1 + bnd);
		}
		else
		{
			type = INSN_CALL_ABS;
			lengthEx = prefix + length + FLOWER32_LEN + 1;
			bytesEx = new BYTE[lengthEx];

			flower();

			RtlCopyMemory(bytesEx + prefix, bytes, length);
			RtlCopyMemory(bytesEx + prefix + length, withRel ? flowerA32 : flowerB32, FLOWER32_LEN);

			bytesEx[prefix + length + FLOWER32_LEN] = 0xC3;
		}
	}
	else if (mnemonic == "ret")
	{
		type = INSN_RET;
		lengthEx = prefix + length;
		bytesEx = new BYTE[lengthEx];

		flower();

		RtlCopyMemory(bytesEx + prefix, bytes, length);
	}
	else
	{
		type = INSN_NORMAL;
		lengthEx = prefix + length + FLOWER32_LEN + 1;
		bytesEx = new BYTE[lengthEx];

		flower();

		RtlCopyMemory(bytesEx + prefix, bytes, length);
		RtlCopyMemory(bytesEx + prefix + length, withRel ? flowerA32 : flowerB32, FLOWER32_LEN);

		bytesEx[prefix + length + FLOWER32_LEN] = 0xC3;
	}
}

VOID INSN::setTarget32(size_t target)
{
	if (withRel)
	{
		switch (type)
		{
		case INSN_NORMAL:
		case INSN_CALL_ABS:
			*(pi32)(bytesEx + prefix + length + FLOWER32_VALUE_OFFSET) = target - (addressEx + prefix + length + FLOWER32_ADDR_OFFSET);
			break;
		case INSN_CALL_REL:
			*(pi32)(bytesEx + prefix + FLOWER32_VALUE_OFFSET) = target - (addressEx + prefix + FLOWER32_ADDR_OFFSET);
			break;
		case INSN_JCC:
			*(pi32)(bytesEx + prefix + 2 + FLOWER32_LEN + 1 + FLOWER32_VALUE_OFFSET) = target - (addressEx + prefix + 2 + FLOWER32_LEN + 1 + FLOWER32_ADDR_OFFSET);
		}
	}
	else
	{
		switch (type)
		{
		case INSN_NORMAL:
		case INSN_CALL_ABS:
			*(pi32)(bytesEx + prefix + length + FLOWER32_VALUE_OFFSET) = target ^ addressEx + prefix + length + FLOWER32_ADDR_OFFSET;
			break;
		case INSN_CALL_REL:
			*(pi32)(bytesEx + prefix + FLOWER32_VALUE_OFFSET) = target ^ addressEx + prefix + FLOWER32_ADDR_OFFSET;
			break;
		case INSN_JCC:
			*(pi32)(bytesEx + prefix + 2 + FLOWER32_LEN + 1 + FLOWER32_VALUE_OFFSET) = target ^ addressEx + prefix + 2 + FLOWER32_LEN + 1 + FLOWER32_ADDR_OFFSET;
		}
	}
}

VOID INSN::setTargetEx32(size_t target)
{
	if (withRel)
	{
		switch (type)
		{
		case INSN_JMP_REL:
			*(pi32)(bytesEx + prefix + FLOWER32_VALUE_OFFSET) = target - (addressEx + prefix + FLOWER32_ADDR_OFFSET);
			break;
		case INSN_CALL_REL:
			*(pi32)(bytesEx + prefix + FLOWER32_LEN + FLOWER32_VALUE_OFFSET) = target - (addressEx + prefix + FLOWER32_LEN + FLOWER32_ADDR_OFFSET);
			break;
		case INSN_JCC:
			*(pi32)(bytesEx + prefix + 2 + FLOWER32_VALUE_OFFSET) = target - (addressEx + prefix + 2 + FLOWER32_ADDR_OFFSET);
		}
	}
	else
	{
		switch (type)
		{
		case INSN_JMP_REL:
			*(pi32)(bytesEx + prefix + FLOWER32_VALUE_OFFSET) = target ^ addressEx + prefix + FLOWER32_ADDR_OFFSET;
			break;
		case INSN_CALL_REL:
			*(pi32)(bytesEx + prefix + FLOWER32_LEN + FLOWER32_VALUE_OFFSET) = target ^ addressEx + prefix + FLOWER32_LEN + FLOWER32_ADDR_OFFSET;
			break;
		case INSN_JCC:
			*(pi32)(bytesEx + prefix + 2 + FLOWER32_VALUE_OFFSET) = target ^ addressEx + prefix + 2 + FLOWER32_ADDR_OFFSET;
		}
	}
}

VOID INSN::trans64()
{
	size_t jcc{};

	if (mnemonic == "jmp")
	{
		if (bytes[bnd] == 0xEB)
		{
			type = INSN_JMP_REL;
			lengthEx = prefix + FLOWER64_LEN + 1;
			bytesEx = new BYTE[lengthEx];

			flower();

			RtlCopyMemory(bytesEx + prefix, withRel ? flowerA64 : flowerB64, FLOWER64_LEN);

			bytesEx[prefix + FLOWER64_LEN] = 0xC3;

			targetEx = address + 2 + bnd + *(pi8)(bytes + 1 + bnd);
		}
		else if (bytes[bnd] == 0xE9)
		{
			type = INSN_JMP_REL;
			lengthEx = prefix + FLOWER64_LEN + 1;
			bytesEx = new BYTE[lengthEx];

			flower();

			RtlCopyMemory(bytesEx + prefix, withRel ? flowerA64 : flowerB64, FLOWER64_LEN);

			bytesEx[prefix + FLOWER64_LEN] = 0xC3;

			targetEx = address + 5 + bnd + *(pi32)(bytes + 1 + bnd);
		}
		else
		{
			type = INSN_JMP_ABS;
			lengthEx = prefix + length;
			bytesEx = new BYTE[lengthEx];

			flower();

			RtlCopyMemory(bytesEx + prefix, bytes, length);
		}
	}
	else if (mnemonic[0] == 'j')
	{
		if (mnemonic == "jno")
		{
			jcc = 0x70;
		}
		else if (mnemonic == "jo")
		{
			jcc = 0x71;
		}
		else if (mnemonic == "jnc" || mnemonic == "jnb" || mnemonic == "jae")
		{
			jcc = 0x72;
		}
		else if (mnemonic == "jc" || mnemonic == "jb" || mnemonic == "jnae")
		{
			jcc = 0x73;
		}
		else if (mnemonic == "jnz" || mnemonic == "jne")
		{
			jcc = 0x74;
		}
		else if (mnemonic == "jz" || mnemonic == "je")
		{
			jcc = 0x75;
		}
		else if (mnemonic == "jnbe" || mnemonic == "ja")
		{
			jcc = 0x76;
		}
		else if (mnemonic == "jbe" || mnemonic == "jna")
		{
			jcc = 0x77;
		}
		else if (mnemonic == "jns")
		{
			jcc = 0x78;
		}
		else if (mnemonic == "js")
		{
			jcc = 0x79;
		}
		else if (mnemonic == "jnp" || mnemonic == "jpo")
		{
			jcc = 0x7A;
		}
		else if (mnemonic == "jp" || mnemonic == "jpe")
		{
			jcc = 0x7B;
		}
		else if (mnemonic == "jnl" || mnemonic == "jge")
		{
			jcc = 0x7C;
		}
		else if (mnemonic == "jl" || mnemonic == "jnge")
		{
			jcc = 0x7D;
		}
		else if (mnemonic == "jnle" || mnemonic == "jg")
		{
			jcc = 0x7E;
		}
		else if (mnemonic == "jle" || mnemonic == "jng")
		{
			jcc = 0x7F;
		}

		type = INSN_JCC;
		lengthEx = prefix + 2 + FLOWER64_LEN + 1 + FLOWER64_LEN + 1;
		bytesEx = new BYTE[lengthEx];

		flower();

		bytesEx[prefix] = jcc;
		bytesEx[prefix + 1] = FLOWER64_LEN + 1;

		RtlCopyMemory(bytesEx + prefix + 2, withRel ? flowerA64 : flowerB64, FLOWER64_LEN);

		bytesEx[prefix + 2 + FLOWER64_LEN] = 0xC3;

		RtlCopyMemory(bytesEx + prefix + 2 + FLOWER64_LEN + 1, withRel ? flowerA64 : flowerB64, FLOWER64_LEN);

		bytesEx[prefix + 2 + FLOWER64_LEN + 1 + FLOWER64_LEN] = 0xC3;

		if (bytes[bnd] == 0x0F)
		{
			targetEx = address + 6 + bnd + *(pi32)(bytes + 2 + bnd);
		}
		else
		{
			targetEx = address + 2 + bnd + *(pi8)(bytes + 1 + bnd);
		}
	}
	else if (mnemonic == "call")
	{
		if (bytes[bnd] == 0xE8)
		{
			type = INSN_CALL_REL;
			lengthEx = prefix + FLOWER64_LEN + FLOWER64_LEN + 1;
			bytesEx = new BYTE[lengthEx];

			flower();

			RtlCopyMemory(bytesEx + prefix, withRel ? flowerA64 : flowerB64, FLOWER64_LEN);
			RtlCopyMemory(bytesEx + prefix + FLOWER64_LEN, withRel ? flowerA64 : flowerB64, FLOWER64_LEN);

			bytesEx[prefix + FLOWER64_LEN + FLOWER64_LEN] = 0xC3;

			targetEx = address + 5 + bnd + *(pi32)(bytes + 1 + bnd);
		}
		else
		{
			type = INSN_CALL_ABS;
			lengthEx = prefix + length + FLOWER64_LEN + 1;
			bytesEx = new BYTE[lengthEx];

			flower();

			RtlCopyMemory(bytesEx + prefix, bytes, length);
			RtlCopyMemory(bytesEx + prefix + length, withRel ? flowerA64 : flowerB64, FLOWER64_LEN);

			bytesEx[prefix + length + FLOWER64_LEN] = 0xC3;
		}
	}
	else if (mnemonic == "ret")
	{
		type = INSN_RET;
		lengthEx = prefix + length;
		bytesEx = new BYTE[lengthEx];

		flower();

		RtlCopyMemory(bytesEx + prefix, bytes, length);
	}
	else
	{
		type = INSN_NORMAL;
		lengthEx = prefix + length + FLOWER64_LEN + 1;
		bytesEx = new BYTE[lengthEx];

		flower();

		RtlCopyMemory(bytesEx + prefix, bytes, length);
		RtlCopyMemory(bytesEx + prefix + length, withRel ? flowerA64 : flowerB64, FLOWER64_LEN);

		bytesEx[prefix + length + FLOWER64_LEN] = 0xC3;
	}
}

VOID INSN::setTarget64(size_t target)
{
	if (withRel)
	{
		switch (type)
		{
		case INSN_NORMAL:
		case INSN_CALL_ABS:
			*(pi32)(bytesEx + prefix + length + FLOWER64_VALUE_OFFSET) = target - (addressEx + prefix + length + FLOWER64_ADDR_OFFSET);
			break;
		case INSN_CALL_REL:
			*(pi32)(bytesEx + prefix + FLOWER64_VALUE_OFFSET) = target - (addressEx + prefix + FLOWER64_ADDR_OFFSET);
			break;
		case INSN_JCC:
			*(pi32)(bytesEx + prefix + 2 + FLOWER64_LEN + 1 + FLOWER64_VALUE_OFFSET) = target - (addressEx + prefix + 2 + FLOWER64_LEN + 1 + FLOWER64_ADDR_OFFSET);
		}
	}
	else
	{
		switch (type)
		{
		case INSN_NORMAL:
		case INSN_CALL_ABS:
			*(pi32)(bytesEx + prefix + length + FLOWER64_VALUE_OFFSET) = target ^ addressEx + prefix + length + FLOWER64_ADDR_OFFSET;
			break;
		case INSN_CALL_REL:
			*(pi32)(bytesEx + prefix + FLOWER64_VALUE_OFFSET) = target ^ addressEx + prefix + FLOWER64_ADDR_OFFSET;
			break;
		case INSN_JCC:
			*(pi32)(bytesEx + prefix + 2 + FLOWER64_LEN + 1 + FLOWER64_VALUE_OFFSET) = target ^ addressEx + prefix + 2 + FLOWER64_LEN + 1 + FLOWER64_ADDR_OFFSET;
		}
	}
}

VOID INSN::setTargetEx64(size_t target)
{
	if (withRel)
	{
		switch (type)
		{
		case INSN_JMP_REL:
			*(pi32)(bytesEx + prefix + FLOWER64_VALUE_OFFSET) = target - (addressEx + prefix + FLOWER64_ADDR_OFFSET);
			break;
		case INSN_CALL_REL:
			*(pi32)(bytesEx + prefix + FLOWER64_LEN + FLOWER64_VALUE_OFFSET) = target - (addressEx + prefix + FLOWER64_LEN + FLOWER64_ADDR_OFFSET);
			break;
		case INSN_JCC:
			*(pi32)(bytesEx + prefix + 2 + FLOWER64_VALUE_OFFSET) = target - (addressEx + prefix + 2 + FLOWER64_ADDR_OFFSET);
		}
	}
	else
	{
		switch (type)
		{
		case INSN_JMP_REL:
			*(pi32)(bytesEx + prefix + FLOWER64_VALUE_OFFSET) = target ^ addressEx + prefix + FLOWER64_ADDR_OFFSET;
			break;
		case INSN_CALL_REL:
			*(pi32)(bytesEx + prefix + FLOWER64_LEN + FLOWER64_VALUE_OFFSET) = target ^ addressEx + prefix + FLOWER64_LEN + FLOWER64_ADDR_OFFSET;
			break;
		case INSN_JCC:
			*(pi32)(bytesEx + prefix + 2 + FLOWER64_VALUE_OFFSET) = target ^ addressEx + prefix + 2 + FLOWER64_ADDR_OFFSET;
		}
	}
}

VOID INSN::relocate(size_t offset, size_t value)
{
	RtlCopyMemory(bytesEx + offset + prefix, &value, 4);
}

VOID INSN::flower()
{
	if (withRel)
	{
		if (prefix == 2)
		{
			RtlCopyMemory(bytesEx, flowerC[rand() % 4], 2);
		}
		else if (prefix == 4)
		{
			RtlCopyMemory(bytesEx, flowerD[rand() % 32], 4);
		}
	}
	else
	{
		bytesEx[0] = 0xE8;

		for (size_t i = 1; i < prefix; i++)
		{
			bytesEx[i] = rand();
		}
	}
}