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
#include <Wincrypt.h>
#define MY_ENCODING_TYPE  (PKCS_7_ASN_ENCODING | X509_ASN_ENCODING)
#include "Hash.h"

bool HashInit(HCRYPTHASH *hCryptHash, HCRYPTPROV *hCryptProv)
{
	if (!CryptAcquireContextW(hCryptProv, NULL, NULL, PROV_RSA_AES, CRYPT_VERIFYCONTEXT))
	{
		printf("Error: %d\n", GetLastError());
		return false;
	}

	if (!CryptCreateHash(*hCryptProv, CALG_SHA_512, 0, 0, hCryptHash))
	{
		printf("Error: %d\n", GetLastError());
		CryptReleaseContext(hCryptProv, 0);
		hCryptProv = NULL;
		return false;
	}

	return true;
}

bool GenerateHash(HCRYPTHASH hCryptHash, unsigned char *hash, unsigned long hashLen, const unsigned char *data, unsigned long dataLen)
{
	if (hCryptHash == NULL || data == NULL)
		return false;

	if (!CryptHashData(hCryptHash, data, dataLen, 0))
	{
		printf("Error: %d\n", GetLastError());
		return false;
	}

	if (hCryptHash == NULL)
		return false;

	if (!CryptGetHashParam(hCryptHash, HP_HASHVAL, hash, &hashLen, 0))
	{
		printf("Error: %d\n", GetLastError());
		return false;
	}

	return true;
}

void HashUninit(HCRYPTHASH hCryptHash, HCRYPTPROV hCryptProv)
{
	if (hCryptHash)	if (!CryptDestroyHash(hCryptHash)) printf("Error: %d\n", GetLastError());
	if (hCryptProv)	if (!CryptReleaseContext(hCryptProv, 0)) printf("Error: %d\n", GetLastError());
}
