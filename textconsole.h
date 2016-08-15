#ifndef _TEXTCONSOLE_H_
#define	_TEXTCONSOLE_H_
#pragma once

#define MAX_CONSOLE_TEXTLEN 256
#define MAX_BUFFER_LINES	30

class CTextConsole
{
public:
	virtual ~CTextConsole() = 0;
	virtual bool Init() = 0;
	virtual void ShutDown() = 0;
	virtual void Print(char *msg) = 0;
	virtual void SetTitle(char *title) = 0;
	virtual void SetStatusLine(char *status) = 0;
	virtual void UpdateStatus() = 0;
#ifndef ORANGEBOX_GAME
	virtual void PrintRaw(char *msg, int len) = 0;
	virtual void Echo(const char *msg, int len = 0) = 0;
#endif
	virtual char *GetLine() = 0;
	virtual int GetWidth() = 0;
	virtual void SetVisible(bool visible) = 0;
	virtual bool IsVisible() = 0;

public:
#ifdef ORANGEBOX_GAME
	int		m_Unknown1;
#endif
	char	m_szConsoleText[MAX_CONSOLE_TEXTLEN];						// console text buffer
	int		m_nConsoleTextLen;											// console textbuffer length
	int		m_nCursorPosition;											// position in the current input line

																		// Saved input data when scrolling back through command history
	char	m_szSavedConsoleText[MAX_CONSOLE_TEXTLEN];				// console text buffer
	int		m_nSavedConsoleTextLen;										// console textbuffer length

	char	m_aszLineBuffer[MAX_BUFFER_LINES][MAX_CONSOLE_TEXTLEN];	// command buffer last MAX_BUFFER_LINES commands
	int		m_nInputLine;												// Current line being entered
	int		m_nBrowseLine;												// current buffer line for up/down arrow
	int		m_nTotalLines;												// # of nonempty lines in the buffer
	bool	m_ConsoleVisible;
};
#endif