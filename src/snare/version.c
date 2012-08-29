#ifndef VERSION
	#error "VERSION must be defined!"
#else

// Syntax minutae require keeping these three lines distinct!
const char REVISION[] =
	#include <svn.h>
;

const char Version[] = VERSION;
const char Compiler[] = "gcc-" __VERSION__;
const char Build_Date[] = __TIME__ " " __DATE__;
#endif
