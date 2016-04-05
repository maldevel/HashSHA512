/*
HashSHA512 - Generate SHA512 hashes
Copyright (C) 2016  @maldevel

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#include <Windows.h>
#include <stdio.h>
#include <VersionHelpers.h>
#include "Hash.h"

int main(int argc, char **argv)
{
	HCRYPTPROV hCryptProv = 0;
	HCRYPTHASH hCryptHash = 0;
	unsigned char hash[SHA512_LENGTH] = { 0 };
	unsigned long hashLen = SHA512_LENGTH;

	if (argc != 2)
	{
		printf("usage: HashSHA512.exe <string to hash>\n");
		return EXIT_FAILURE;
	}

	if (!IsWindowsXPSP3OrGreater())//Win XP, Win XP SP1 and Win XP SP2 doesn't support SHA512
	{
		printf("Minimum supported OS, Windows XP SP3.\n");
	}

	printf("\nText: %s\n", argv[1]);

	if (!HashInit(&hCryptHash, &hCryptProv))
	{
		printf("Hash 512 generation failed\n");
		return EXIT_FAILURE;
	}

	if (GenerateHash(hCryptHash, hash, hashLen, (unsigned char*)argv[1], (unsigned long)strlen(argv[1])))
	{
		printf("Hash SHA 512: ");
		for (unsigned long i = 0; i < hashLen; i++) printf("%02X", hash[i]);
		printf("\n");
	}

	HashUninit(hCryptHash, hCryptProv);

	return EXIT_SUCCESS;
}
