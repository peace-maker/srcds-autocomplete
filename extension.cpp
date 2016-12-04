/**
 * vim: set ts=4 :
 * =============================================================================
 * SourceMod Console Autocompletion Extension
 * Copyright (C) AlliedModders LLC.  All rights reserved.
 * =============================================================================
 *
 * This program is free software; you can redistribute it and/or modify it under
 * the terms of the GNU General Public License, version 3.0, as published by the
 * Free Software Foundation.
 * 
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
 * FOR A PARTICULAR PURPOSE.  See the GNU General Public License for more
 * details.
 *
 * You should have received a copy of the GNU General Public License along with
 * this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 * As a special exception, AlliedModders LLC gives you permission to link the
 * code of this program (as well as its derivative works) to "Half-Life 2," the
 * "Source Engine," the "SourcePawn JIT," and any Game MODs that run on software
 * by the Valve Corporation.  You must obey the GNU General Public License in
 * all respects for all other code used.  Additionally, AlliedModders LLC grants
 * this exception to all derivative works.  AlliedModders LLC defines further
 * exceptions, found in LICENSE.txt (as of this writing, version JULY-31-2007),
 * or <http://www.sourcemod.net/license.php>.
 *
 * Version: $Id$
 */

#include "extension.h"
#include "amtl/am-string.h"
#include "CDetour/detours.h"
#include "asm/asm.h"
#include <tier0/icommandline.h>
#include "textconsole.h"
#include "sourcehook.h"
#include "editline_stripped.h"

/**
 * @file extension.cpp
 * @brief Implement extension code here.
 */

static int DoAutocompletion(CTextConsole *tc, EditLine *el, const char *consoleText, int consoleTextLen);
#ifndef USE_EDITLINE
static void __stdcall ReceiveTab_Hack(CTextConsole *tc);
#endif

#if defined WIN32 && defined ORANGEBOX_GAME
// In Orangebox games, the Echo method isn't virtual :(
// CTextConsole::Echo function address
typedef void (*EchoFunc)(const char *, int);
EchoFunc g_EchoFunc = nullptr;
#endif // WIN32 && ORANGEBOX_GAME

#ifdef TAB_SWITCH_CASE_HACK
// Address inside CTextConsoleWin32::GetLine for '\t' case
uint8_t *g_pTabCase = nullptr;
uint8_t g_RestoreBytes[100];
uint32_t g_RestoreBytesCount;
#endif // TAB_SWITCH_CASE_HACK

#ifdef USE_EDITLINE
// CS:S linux dedicated_srv.so uses libedit/editline for the command prompt..

// Setup function pointers for required editline api helper methods
typedef const LineInfo* (*el_line_f)(EditLine *);
typedef int(*el_insertstr_f)(EditLine *, const char *);
el_line_f g_el_line = nullptr;
el_insertstr_f g_el_insertstr = nullptr;

static CTextConsole *console = nullptr;

CDetour *editlineComplete;
DETOUR_DECL_STATIC2(DetourEditlineComplete, unsigned char, EditLine *, el, int, ch)
{
	static char s_consoleText[MAX_CONSOLE_TEXTLEN];

	// Get the current's line content
	const LineInfo *li = (g_el_line)(el);
	// Empty line
	if (li->cursor <= li->buffer)
		return CC_ERROR;

	unsigned int len = li->cursor - li->buffer;
	if (len > MAX_CONSOLE_TEXTLEN)
		len = MAX_CONSOLE_TEXTLEN - 1;

	ke::SafeStrcpy(s_consoleText, len + 1, li->buffer);

	// See if any command matches the partial text
	// FIXME: This could race with the main thread - but we're not adding/removing ConCommandBases that often, so YOLO
	int matchCount = DoAutocompletion(console, el, s_consoleText, len);
	if (matchCount == 0)
		return CC_ERROR;

	if (matchCount == 1)
		return CC_REFRESH;

	if (matchCount > 1)
		return CC_REDISPLAY;

	return CC_ERROR;
}
#endif

#ifdef DETOUR_RECEIVE_TAB
CDetour *receiveTab;
DETOUR_DECL_MEMBER0(DetourReceiveTab, void)
{
	ReceiveTab_Hack((CTextConsole *)this);
}
#endif // _LINUX || L4D

ICvar *icvar = NULL;

AutoCompleteHook g_AutoCompleteHook;		/**< Global singleton for extension's main interface */

SMEXT_LINK(&g_AutoCompleteHook);

void *GetAddressFromKeyValues(void *pBaseAddr, IGameConfig *pGameConfig, const char *key)
{
	const char *value = pGameConfig->GetKeyValue(key);
	if (!value)
		return nullptr;

	// Got a symbol here.
	if (value[0] == '@')
		return memutils->ResolveSymbol(pBaseAddr, &value[1]);

	// Convert hex signature to byte pattern
	unsigned char signature[200];
	size_t real_bytes = UTIL_DecodeHexString(signature, sizeof(signature), value);
	if (real_bytes < 1)
		return nullptr;

	// Find that pattern in the pointed module.
	return memutils->FindPattern(pBaseAddr, (char *)signature, real_bytes);
}

bool AutoCompleteHook::SDK_OnMetamodLoad(ISmmAPI *ismm, char *error, size_t maxlen, bool late)
{
	GET_V_IFACE_CURRENT(GetEngineFactory, icvar, ICvar, CVAR_INTERFACE_VERSION);
	return true;
}

bool AutoCompleteHook::SDK_OnLoad(char *error, size_t maxlength, bool late)
{
	IGameConfig *pGameConfig;
	char conf_error[255];
	if (!gameconfs->LoadGameConfigFile("autocomplete.games", &pGameConfig, conf_error, sizeof(conf_error)))
	{
		ke::SafeSprintf(error, maxlength, "Could not read autocomplete.games gamedata: %s", conf_error);
		return false;
	}

	// Find dedicated library in memory.
#ifdef WIN32
	// The Windows SRCDS GUI already has its own auto completion feature.
	ICommandLine *commandline = gamehelpers->GetValveCommandLine();
	if (commandline && !commandline->FindParm("-console"))
	{
		ke::SafeStrcpy(error, maxlength, "This extension is only needed when running in -console mode.");
		return false;
	}

	// Find dedicated.dll module in memory
	HMODULE hDedicated = GetModuleHandleA("dedicated.dll");
	if (!hDedicated)
	{
		ke::SafeStrcpy(error, maxlength, "Failed to find dedicated library in memory.");
		return false;
	}
#else // WIN32
	void* hDedicated = dlopen("dedicated_srv.so", RTLD_LAZY);
	if (!hDedicated)
		hDedicated = dlopen("dedicated.so", RTLD_LAZY);

	if (!hDedicated)
	{
		ke::SafeStrcpy(error, maxlength, "Failed to find dedicated library in memory.");
		return false;
	}
#endif
	
	// MSVC optimized the ReceiveTab function away. It's still present in L4D though!
#ifdef TAB_SWITCH_CASE_HACK
	// Find GetLine function, which handles the console input
	void *pGetLine = GetAddressFromKeyValues(hDedicated, pGameConfig, "CTextConsole::GetLine" KEY_SUFFIX);
	if (!pGetLine)
	{
		ke::SafeStrcpy(error, maxlength, "Failed to find CTextConsoleWin32::GetLine signature in dedicated library");
		return false;
	}

	// Read offset to '\t' switch case in CTextConsoleWin32::GetLine
	int tabCaseOffset;
	if (!pGameConfig->GetOffset("TabCompleteSwitchCase", &tabCaseOffset))
	{
		ke::SafeStrcpy(error, maxlength, "Failed to get TabCompleteSwitchCase offset from gamedata.");
		return false;
	}

	// How many bytes to patch / nop
	int patchSize;
	if (!pGameConfig->GetOffset("TabCompletePatchSize", &patchSize))
	{
		ke::SafeStrcpy(error, maxlength, "Failed to get TabCompletePatchSize offset from gamedata.");
		return false;
	}

#ifdef ORANGEBOX_GAME
	// In this engine version CTextConsole::Echo isn't virtual :(
	void *pEcho = GetAddressFromKeyValues(hDedicated, pGameConfig, "CTextConsole::Echo" KEY_SUFFIX);
	if (!pEcho)
	{
		ke::SafeStrcpy(error, maxlength, "Failed to find CTextConsole::Echo signature in dedicated library");
		return false;
	}
	g_EchoFunc = (EchoFunc)pEcho;
#endif

	// Patch '\t' tab handling
	uint8_t *pTabCase = (uint8_t *)pGetLine + tabCaseOffset;

	// Save the real opcodes
	g_pTabCase = pTabCase;
	g_RestoreBytesCount = patchSize;
	for (uint32_t i = 0; i < g_RestoreBytesCount; i++)
	{
		g_RestoreBytes[i] = pTabCase[i];
	}

	SetMemPatchable(pTabCase, patchSize);

	// Patch in a call to our own method
	JitWriter wr;
	JitWriter *jit = &wr;

	wr.outbase = (jitcode_t)pTabCase;
	wr.outptr = wr.outbase;

	IA32_Push_Reg(jit, kREG_ESI); // push esi

	jitoffs_t call = IA32_Call_Imm32(jit, 0);
	IA32_Write_Jump32_Abs(jit, call, (unsigned char *)&ReceiveTab_Hack); // call &ReceiveTab_Hack;
	pTabCase += wr.get_outputpos();
	patchSize -= wr.get_outputpos();
	
	// nop the rest of the case handler
	fill_nop(pTabCase, patchSize);
#endif
	

#ifdef USE_EDITLINE
	// dedicated_srv.so in orangebox games use ncurses/editline to handle the command line.
	CDetourManager::Init(smutils->GetScriptingEngine(), nullptr);

	void *console_ptr = GetAddressFromKeyValues(hDedicated, pGameConfig, "console" KEY_SUFFIX);
	if (!console_ptr)
	{
		dlclose(hDedicated);
		ke::SafeStrcpy(error, maxlength, "Failed to find console symbol in dedicated library");
		return false;
	}
	console = (CTextConsole *)console_ptr;


	void *editline_complete = GetAddressFromKeyValues(hDedicated, pGameConfig, "editline_complete" KEY_SUFFIX);
	if (!editline_complete)
	{
		dlclose(hDedicated);
		ke::SafeStrcpy(error, maxlength, "Failed to find editline_complete symbol in dedicated library");
		return false;
	}

	void *el_insertstr = GetAddressFromKeyValues(hDedicated, pGameConfig, "el_insertstr" KEY_SUFFIX);
	if (!el_insertstr)
	{
		dlclose(hDedicated);
		ke::SafeStrcpy(error, maxlength, "Failed to find el_insertstr symbol in dedicated library");
		return false;
	}
	g_el_insertstr = (el_insertstr_f)el_insertstr;

	void *el_line = GetAddressFromKeyValues(hDedicated, pGameConfig, "el_line" KEY_SUFFIX);
	if (!el_line)
	{
		dlclose(hDedicated);
		ke::SafeStrcpy(error, maxlength, "Failed to find el_line symbol in dedicated library");
		return false;
	}
	g_el_line = (el_line_f)el_line;

	editlineComplete = DETOUR_CREATE_STATIC(DetourEditlineComplete, editline_complete);
	if (editlineComplete)
	{
		editlineComplete->EnableDetour();
	}
	else
	{
		dlclose(hDedicated);
		ke::SafeStrcpy(error, maxlength, "Failed to create detour for editline_complete in dedicated library");
		return false;
	}
#endif

#ifdef DETOUR_RECEIVE_TAB
	CDetourManager::Init(smutils->GetScriptingEngine(), nullptr);

	void *receiveTabAddr = GetAddressFromKeyValues(hDedicated, pGameConfig, "CTextConsole::ReceiveTab" KEY_SUFFIX);
	if (!receiveTabAddr)
	{
#ifdef _LINUX
		dlclose(hDedicated);
#endif // _LINUX
		ke::SafeStrcpy(error, maxlength, "Failed to find CTextConsole::ReceiveTab symbol in dedicated library");
		return false;
	}

	receiveTab = DETOUR_CREATE_MEMBER(DetourReceiveTab, receiveTabAddr);
	if (receiveTab)
	{
		receiveTab->EnableDetour();
	}
	else
	{
#ifdef _LINUX
		dlclose(hDedicated);
#endif // _LINUX
		ke::SafeStrcpy(error, maxlength, "Failed to create detour for CTextConsole::ReceiveTab in dedicated library");
		return false;
	}
#endif // DETOUR_RECEIVE_TAB

#ifdef _LINUX
	dlclose(hDedicated);
#endif // _LINUX

	gameconfs->CloseGameConfigFile(pGameConfig);

	return true;
}

void AutoCompleteHook::SDK_OnUnload()
{
#ifdef TAB_SWITCH_CASE_HACK
	// Restore patched opcodes..
	if (g_pTabCase)
	{
		for (uint32_t i = 0; i < g_RestoreBytesCount; i++)
		{
			g_pTabCase[i] = g_RestoreBytes[i];
		}
	}
#endif

#ifdef USE_EDITLINE
	if (editlineComplete)
		editlineComplete->Destroy();
#endif // USE_EDITLINE

#ifdef DETOUR_RECEIVE_TAB
	if (receiveTab)
		receiveTab->Destroy();
#endif // DETOUR_RECEIVE_TAB
}

static ConCommand *FindAutoCompleteCommmandFromPartial(const char *partial)
{
	char command[256];
	ke::SafeStrcpy(command, sizeof(command), partial);

	char *space = strstr(command, " ");
	if (space)
	{
		*space = 0;
	}

#if SOURCE_ENGINE >= SE_ORANGEBOX
	ConCommand *cmd = icvar->FindCommand(command);
#else
	ConCommand *cmd = nullptr;
	const ConCommandBase *pBase = icvar->GetCommands();
	while (pBase != nullptr)
	{
		if (pBase->IsCommand() && strcmp(pBase->GetName(), command) == 0)
		{
			cmd = (ConCommand *)pBase;
			break;
		}
		pBase = pBase->GetNext();
	}
#endif
	if (!cmd)
		return nullptr;

	if (!cmd->CanAutoComplete())
		return nullptr;

	return cmd;
}

static void GetSuggestions(const char *partial, const int numChars, CUtlVector<const char *> &matches)
{
	// Need to have this static, so the strings are still valid when added to |matches|
#if SOURCE_ENGINE >= SE_ORANGEBOX
	static CUtlVector< CUtlString > commands;
	commands.Purge();
#else
	static char commands[COMMAND_COMPLETION_MAXITEMS][COMMAND_COMPLETION_ITEM_LENGTH];
#endif

	// Already a space in the command, so try to display command completion suggestions.
	const char *space = strstr(partial, " ");
	if (space)
	{
		ConCommand *pCommand = FindAutoCompleteCommmandFromPartial(partial);
		if (!pCommand)
			return;

		int count = pCommand->AutoCompleteSuggest(partial, commands);
		for (int i = 0; i < count; i++)
		{
#if SOURCE_ENGINE >= SE_ORANGEBOX
			matches.AddToTail(commands[i].String());
#else
			matches.AddToTail(commands[i]);
#endif
		}
	}
	else
	{

		// Find all commands starting with the text typed in console yet
		// Scope needed for iterator in CSGO
		{
#if SOURCE_ENGINE < SE_LEFT4DEAD
			ConCommandBase const *cmd = (ConCommandBase const *)icvar->GetCommands();
			for (; cmd; cmd = cmd->GetNext())
			{
#else
			ICvar::Iterator iter(icvar);
			for (iter.SetFirst(); iter.IsValid(); iter.Next())
			{
				ConCommandBase *cmd = iter.Get();
#endif

#if SOURCE_ENGINE <= SE_DARKMESSIAH
				if (cmd->IsBitSet(FCVAR_LAUNCHER))
#else
				if (cmd->IsFlagSet(FCVAR_DEVELOPMENTONLY) || cmd->IsFlagSet(FCVAR_HIDDEN))
#endif
					continue;

				if (!Q_strnicmp(partial, cmd->GetName(), numChars))
				{
					matches.AddToTail(cmd->GetName());
				}
			}
		}
	}

	// Now sort the list by command name
	if (matches.Count() >= 2)
	{
		for (int i = 0; i < matches.Count(); i++)
		{
			for (int j = i + 1; j < matches.Count(); j++)
			{
				if (stricmp(matches[i], matches[j]) > 0)
				{
					const char *temp = matches[i];
					matches[i] = matches[j];
					matches[j] = temp;
				}
			}
		}
	}
}

static void Echo(CTextConsole *tc, const char *msg)
{
#ifdef ORANGEBOX_GAME
# ifdef WIN32
	__asm
	{
		push 0; // len
		push msg;
		mov ecx, tc;
		call g_EchoFunc;
	};
# else // !WIN32
	// editline writes to the output stream directly
	// Don't go through CTextConsoleUnix::Print, because we don't want the suggestions to be added to console.log.
	fwrite(msg, 1, strlen(msg), tc->m_outputStream);
# endif // !WIN32
#else
	tc->Echo(msg);
#endif
}

static bool InsertConsoleText(CTextConsole *tc, EditLine *el, const char *msg, bool echo)
{
#ifdef USE_EDITLINE
	int inserted = (g_el_insertstr)(el, msg);
	return inserted != -1;
#else
	if (echo)
		Echo(tc, msg);
	
	strncat(tc->m_szConsoleText, msg, MAX_CONSOLE_TEXTLEN - tc->m_nConsoleTextLen);
	tc->m_nConsoleTextLen += strlen(msg);
	return true;
#endif
}

static int DoAutocompletion(CTextConsole *tc, EditLine *el, const char *consoleText, int consoleTextLen)
{
	// See if any command matches the partial text
	CUtlVector<const char *> matches;
	GetSuggestions(consoleText, consoleTextLen, matches);

	// No matches. Don't change the input line.
	if (matches.Count() == 0)
		return 0;

	// Exactly one match. Fill in the rest of the command on the command line.
	if (matches.Count() == 1)
	{
		const char * pszCmdName = matches[0];
		const char * pszRest = &pszCmdName[consoleTextLen];

		if (pszRest)
		{
			if (!InsertConsoleText(tc, el, pszRest, true))
				return 0;
			if (!InsertConsoleText(tc, el, " ", true))
				return 0;
		}

		return 1;
	}
	
	// Find the longest suggestion to print cleanly
	int nLongestCmd = 0;
	const char *pszCurrentCmd = matches[0];
	for (int i = 0; i < matches.Count(); i++)
	{
		pszCurrentCmd = matches[i];

		if ((int)strlen(pszCurrentCmd) > nLongestCmd)
		{
			nLongestCmd = strlen(pszCurrentCmd);
		}
	}

	// See how many command suggestions fit in one console line considering the console window width.
	int nTotalColumns = (tc->GetWidth() - 1) / (nLongestCmd + 1);
	//nTotalColumns = (80 - 1) / (nLongestCmd + 1);
	int nCurrentColumn = 0;

	// Find the longest common prefix in all the commands
	char szLongestCommonPrefix[MAX_CONSOLE_TEXTLEN];
	ke::SafeStrcpy(szLongestCommonPrefix, MAX_CONSOLE_TEXTLEN, matches[0]);
	int nLongestPrefixLength = strlen(szLongestCommonPrefix);

	// Print all command suggestions as a table in the next line(s)
	Echo(tc, "\n");

	char szFormatCmd[256];
	int size, c;
	for (int i = 0; i < matches.Count(); i++)
	{
		pszCurrentCmd = matches[i];
		nCurrentColumn++;

		if (nCurrentColumn > nTotalColumns)
		{
			Echo(tc, "\n");
			nCurrentColumn = 1;
		}

		// Pad the command suggestion to the length of the longest suggestion
		ke::SafeSprintf(szFormatCmd, sizeof(szFormatCmd), "%-*s ", nLongestCmd, pszCurrentCmd);
		Echo(tc, szFormatCmd);

		// See if the commands overlap
		size = strlen(pszCurrentCmd);
		if (size > nLongestPrefixLength)
			size = nLongestPrefixLength;
		c = 0;
		for (; c < size; c++)
		{
			if (pszCurrentCmd[c] != szLongestCommonPrefix[c])
				break;
		}

		// New common prefix length
		nLongestPrefixLength = c;
		szLongestCommonPrefix[c] = 0;
	}

	// Tack on 'common' chars in all the matches, i.e. if I typed 'con' and all the
	// matches begin with 'connect_' then print the matches but also complete the
	// command up to that point at least.
	if (nLongestPrefixLength > consoleTextLen)
	{
		const char * pszRest = &szLongestCommonPrefix[consoleTextLen];
		if (pszRest)
		{
			InsertConsoleText(tc, el, pszRest, false);
		}
	}
	
	return matches.Count();
}

#ifndef USE_EDITLINE
static void __stdcall ReceiveTab_Hack(CTextConsole *tc)
{
	tc->m_szConsoleText[tc->m_nConsoleTextLen] = 0;

	if (tc->m_nConsoleTextLen == 0)
		return;

	// Process the autocompletion
	int matchCount = DoAutocompletion(tc, nullptr, tc->m_szConsoleText, tc->m_nConsoleTextLen);
	if (matchCount == 0)
		return;

	// Multiple possible matches shown.
	if (matchCount > 1)
	{
		// Provide the entered console text again for further editing.
		Echo(tc, "\n");
		Echo(tc, tc->m_szConsoleText);
	}

	tc->m_nCursorPosition = tc->m_nConsoleTextLen;
	tc->m_nBrowseLine = tc->m_nInputLine;
}
#endif

// From SM's stringutil.cpp
size_t UTIL_DecodeHexString(unsigned char *buffer, size_t maxlength, const char *hexstr)
{
	size_t written = 0;
	size_t length = strlen(hexstr);

	for (size_t i = 0; i < length; i++)
	{
		if (written >= maxlength)
			break;
		buffer[written++] = hexstr[i];
		if (hexstr[i] == '\\' && hexstr[i + 1] == 'x')
		{
			if (i + 3 >= length)
				continue;
			/* Get the hex part. */
			char s_byte[3];
			int r_byte;
			s_byte[0] = hexstr[i + 2];
			s_byte[1] = hexstr[i + 3];
			s_byte[2] = '\0';
			/* Read it as an integer */
			sscanf(s_byte, "%x", &r_byte);
			/* Save the value */
			buffer[written - 1] = r_byte;
			/* Adjust index */
			i += 3;
		}
	}

	return written;
}
