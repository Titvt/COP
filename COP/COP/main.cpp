#include "main.h"

int main()
{
	PCOP pCop = new COP("KCTF.exe");

	if (pCop->error)
	{
		cout << "ERROR!" << endl;

		return 0;
	}

	pCop->parse(TRUE);

	if (pCop->error)
	{
		cout << "ERROR!!" << endl;

		return 0;
	}

	pCop->output("output.exe");

	cout << "OK!" << endl;

	pCop = new COP("output.exe");

	if (pCop->error)
	{
		cout << "ERROR!!!" << endl;

		return 0;
	}

	pCop->parse(FALSE);

	if (pCop->error)
	{
		cout << "ERROR!!!!" << endl;

		return 0;
	}

	pCop->output("output2.exe");

	cout << "OK!!" << endl;

	return 0;
}