#ifndef _EDITLINE_STRIPPED_H_
#define	_EDITLINE_STRIPPED_H_

typedef struct editline EditLine;

/*
* For user-defined function interface
*/
typedef struct lineinfo {
	const char	*buffer;
	const char	*cursor;
	const char	*lastchar;
} LineInfo;

/*
* EditLine editor function return codes.
* For user-defined function interface
*/
#define	CC_NORM		0
#define	CC_NEWLINE	1
#define	CC_EOF		2
#define	CC_ARGHACK	3
#define	CC_REFRESH	4
#define	CC_CURSOR	5
#define	CC_ERROR	6
#define	CC_FATAL	7
#define	CC_REDISPLAY	8
#define	CC_REFRESH_BEEP	9

#endif