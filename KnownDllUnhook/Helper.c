#include <Windows.h>

#include "Structs.h"





//-----------------------------------------------------------------------------------------------------------------------------------------------------------------//

PVOID _memcpy(PVOID Destination, CONST PVOID Source, SIZE_T Length)
{
	PBYTE D = (PBYTE)Destination;
	PBYTE S = (PBYTE)Source;

	while (Length--)
		*D++ = *S++;

	return Destination;
}

//-----------------------------------------------------------------------------------------------------------------------------------------------------------------//

void _RtlInitUnicodeString(PUNICODE_STRING target, PCWSTR source)
{
	if ((target->Buffer = (PWSTR)source))
	{
		unsigned int length = wcslen(source) * sizeof(WCHAR);
		if (length > 0xfffc)
			length = 0xfffc;

		target->Length = length;
		target->MaximumLength = target->Length + sizeof(WCHAR);
	}
	else target->Length = target->MaximumLength = 0;
}

//-----------------------------------------------------------------------------------------------------------------------------------------------------------------//

wchar_t* _strcpy(wchar_t* dest, const wchar_t* src)
{
	wchar_t* p;

	if ((dest == NULL) || (src == NULL))
		return dest;

	if (dest == src)
		return dest;

	p = dest;
	while (*src != 0) {
		*p = *src;
		p++;
		src++;
	}

	*p = 0;
	return dest;
}

//-----------------------------------------------------------------------------------------------------------------------------------------------------------------//

wchar_t* _strcat(wchar_t* dest, const wchar_t* src)
{
	if ((dest == NULL) || (src == NULL))
		return dest;

	while (*dest != 0)
		dest++;

	while (*src != 0) {
		*dest = *src;
		dest++;
		src++;
	}

	*dest = 0;
	return dest;
}