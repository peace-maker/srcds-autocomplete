/*
 * Module Scanner class by Didrole
 * Find signature patterns and symbols in any loaded module in memory.
 */

#include <string.h>
 
#ifdef _WIN32
	#define WIN32_LEAN_AND_MEAN
	#include <windows.h>
#else
	#include <dlfcn.h>
	#include <sys/types.h>
	#include <sys/stat.h> 

	#include <elf.h>
	#include <link.h>
	#include <stdio.h>

	#include <unistd.h> 
	#include <sys/mman.h>
#endif

#include "ModuleScanner.h"


CModuleScanner::CModuleScanner(void* hModule) : m_pAllocationBase(NULL), m_uSize(0)
{
	m_szFilename[0] = '\0';

	if(!hModule)
		return;

	#if defined(_WIN32)
		MEMORY_BASIC_INFORMATION basicInformation;

		if(!VirtualQuery(hModule, &basicInformation, sizeof(basicInformation)))
			return;

		const IMAGE_DOS_HEADER *pDOSHeader = (IMAGE_DOS_HEADER*)basicInformation.AllocationBase;
		const IMAGE_NT_HEADERS *pNTHeader = (IMAGE_NT_HEADERS*)(((unsigned char*)basicInformation.AllocationBase) + pDOSHeader->e_lfanew);

		if(pNTHeader->Signature != IMAGE_NT_SIGNATURE)
			return;

		m_pAllocationBase = basicInformation.AllocationBase;
		m_uSize = pNTHeader->OptionalHeader.SizeOfImage;

		GetModuleFileNameA((HMODULE)basicInformation.AllocationBase, m_szFilename, sizeof(m_szFilename));
	#elif defined(__linux__)
		Dl_info info;

		unsigned int uModuleAddr = 0;
		const char* cszModulePath = NULL;

		if(dladdr(hModule, &info))
		{
			uModuleAddr = (unsigned int)info.dli_fbase;
			cszModulePath = info.dli_fname;
		}
		else
		{
			const link_map* pLinkMap = (link_map*)hModule;
			uModuleAddr = (unsigned int)pLinkMap->l_addr;
			cszModulePath = pLinkMap->l_name;
		}

		if(strlen(cszModulePath) + 1 > sizeof(m_szFilename))
			return;

		strcpy(m_szFilename, cszModulePath);
		
		FILE* hFile = fopen("/proc/self/maps", "rb");
		if(!hFile)
			return;

		char szLine[1024];
		unsigned long long ullFrom, ullTo, ullOffset;
		char r, w, x, s;
		unsigned char uDevMinor, uDevMajor;
		unsigned int uINode;
		unsigned int uModuleINode = 0;

		while(!feof(hFile))
		{
			fgets(szLine, sizeof(szLine), hFile);
			if(sscanf(szLine, "%llx-%llx %c%c%c%c %x %x:%x %u", &ullFrom, &ullTo, &r, &w, &x, &s, &ullOffset, &uDevMinor, &uDevMajor, &uINode) == 10)
			{
				if(!m_pAllocationBase)
				{
					if(ullFrom == uModuleAddr)
					{
						m_pAllocationBase = (void*)uModuleAddr;
						m_uSize = ullTo - ullFrom;
						uModuleINode = uINode;
					}
				}
				else
				{
					if(ullFrom == uModuleAddr + m_uSize && uINode == uModuleINode && r == 'r')
					{
						m_uSize += ullTo - ullFrom;
					}
					else
					{
						break;
					}
				}
			}
		}
		
		if(!m_uSize)
		{
			fprintf(stderr, "%s: Unable to find the memory mapping of %s, using file size instead !\n", __FUNCTION__, m_szFilename);
			
			struct stat fileStat;
			if(stat(cszModulePath, &fileStat) == 0)
			{
				m_pAllocationBase = (void*)uModuleAddr;
				m_uSize = fileStat.st_size;
			}
			else
			{
				fprintf(stderr, "%s: Failed to find the file size !\n", __FUNCTION__);
			}
		}
		
		fclose(hFile);
				
	#else
		#error Unsupported platform
	#endif

	CacheSymbols();
}

#if defined(_WIN32)

void CModuleScanner::CacheSymbols()
{
	// TODO
}

#elif defined(__linux__)

void CModuleScanner::CacheSymbols()
{
	FILE* hFile = fopen(m_szFilename, "rb");
	if(!hFile)
		return;

	fseek(hFile, 0, SEEK_END);
	unsigned int uFileSize = ftell(hFile);
	
	unsigned char* pFileBase = (unsigned char*)mmap(NULL, uFileSize, PROT_READ, MAP_PRIVATE, fileno(hFile), 0);
	if(pFileBase == MAP_FAILED)
	{
		fclose(hFile);
		return;
	}

	const Elf32_Ehdr* pELFHeader = (Elf32_Ehdr*)pFileBase;

	if(pELFHeader->e_ident[EI_MAG0] != 0x7f || pELFHeader->e_ident[EI_MAG1] != 'E'
		|| pELFHeader->e_ident[EI_MAG2] != 'L' || pELFHeader->e_ident[EI_MAG3] != 'F')
	{
		munmap(pFileBase, uFileSize);
		fclose(hFile);
		return;
	}

	if(pELFHeader->e_ident[EI_CLASS] != ELFCLASS32)
	{
		munmap(pFileBase, uFileSize);
		fclose(hFile);
		return;
	}

	if(pELFHeader->e_ident[EI_DATA] != ELFDATA2LSB)
	{
		munmap(pFileBase, uFileSize);
		fclose(hFile);
		return;
	}

	if(pELFHeader->e_ident[EI_VERSION] != EV_CURRENT)
	{
		munmap(pFileBase, uFileSize);
		fclose(hFile);
		return;
	}

	if(pELFHeader->e_type != ET_EXEC && pELFHeader->e_type != ET_DYN)
	{
		munmap(pFileBase, uFileSize);
		fclose(hFile);
		return;
	}

	if(pELFHeader->e_machine != EM_386)
	{
		munmap(pFileBase, uFileSize);
		fclose(hFile);
		return;
	}

	if(pELFHeader->e_version != EV_CURRENT)
	{
		munmap(pFileBase, uFileSize);
		fclose(hFile);
		return;
	}

	const Elf32_Shdr *pSectionHeaders = (Elf32_Shdr*)(pFileBase + pELFHeader->e_shoff);

	if(pELFHeader->e_shstrndx == SHN_UNDEF)
	{
		munmap(pFileBase, uFileSize);
		fclose(hFile);
		return;
	}

	const Elf32_Shdr *pSectionNameStringTableHeader = &pSectionHeaders[pELFHeader->e_shstrndx];
	const char *pNameStringTable = (const char *)pFileBase + pSectionNameStringTableHeader->sh_offset;

	const Elf32_Sym *pSymbols = NULL;
	int nSymbols = 0;
	const char* pStrings = NULL;

	for (int i = 0; i < pELFHeader->e_shnum; i++)
	{
		if(pSectionHeaders[i].sh_type == SHT_SYMTAB && strcmp(pNameStringTable + pSectionHeaders[i].sh_name, ".symtab") == 0)
		{
			pSymbols = (const Elf32_Sym*)(pFileBase + pSectionHeaders[i].sh_offset);
			nSymbols = pSectionHeaders[i].sh_size / sizeof(*pSymbols);
		}
		else if(pSectionHeaders[i].sh_type == SHT_STRTAB && strcmp(pNameStringTable + pSectionHeaders[i].sh_name, ".strtab") == 0)
		{
			pStrings = (const char*)pFileBase + pSectionHeaders[i].sh_offset;
		}
	}

	if(!pSymbols || !pStrings)
	{
		munmap(pFileBase, uFileSize);
		fclose(hFile);
		return;
	}

	for(int i = 0; i < nSymbols; i++)
	{
		if(!pSymbols[i].st_value)
			continue;

		m_symbols[pStrings + pSymbols[i].st_name] = (unsigned char*)m_pAllocationBase + pSymbols[i].st_value;
	}

	munmap(pFileBase, uFileSize);
	fclose(hFile);
}

#else

	#error Unsupported platform

#endif

void* CModuleScanner::FindSignature(const unsigned char* pubSignature, const char* cszMask) const
{
	if(!m_pAllocationBase || !cszMask || !*cszMask)
		return NULL;

	unsigned char *pCurrent = (unsigned char *)m_pAllocationBase;
	unsigned char *pEnd = pCurrent + m_uSize;

	unsigned int i;
	unsigned int uSignatureLength = (unsigned int)strlen(cszMask);

	for(; pCurrent < pEnd && (unsigned long)(pEnd - pCurrent) >= uSignatureLength; pCurrent++)
	{
		for(i = 0; cszMask[i] != '\0'; i++)
		{
			if((cszMask[i] != '?') && (pubSignature[i] != pCurrent[i]))
				break;
		}
		if(cszMask[i] == '\0')
			return pCurrent;
	}
	return NULL;
}

void* CModuleScanner::FindSymbol(const char* cszSymbol) const
{
	std::map<std::string, void*>::const_iterator it = m_symbols.find(cszSymbol);

	if(it != m_symbols.end())
		return it->second;
	else
		return NULL;
}
