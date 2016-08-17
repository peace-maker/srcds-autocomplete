#ifndef _MODULESCANNER_H_
#pragma once

#include <amtl/am-hashmap.h>
#include <amtl/am-string.h>
#include <cstdio>

using namespace ke;



class CModuleScanner
{
public:
	// Pass any address in the module or the module handle itself to this function.
	CModuleScanner(void* hModule);

	void* FindSignature(const char* pubSignature, const char* cszMask);
	void* FindSignature(const unsigned char* pubSignature, const char* cszMask);

	void* FindSymbol(const char* cszSymbol);

private:
	void CacheSymbols();

	char m_szFilename[FILENAME_MAX];
	const void* m_pAllocationBase;
	unsigned int m_uSize;

	struct StringPolicy
	{
		static inline uint32_t hash(const char *key) {
			return FastHashCharSequence(key, strlen(key));
		}
		static inline bool matches(const char *find, const AString &key) {
			return key.compare(find) == 0;
		}
	};
	typedef HashMap<AString, void *, StringPolicy> SymbolMap;

	SymbolMap m_symbols;
};

inline void* CModuleScanner::FindSignature(const char* pubSignature, const char* cszMask)
{
	return FindSignature((const unsigned char*)pubSignature, cszMask);
}
#endif
