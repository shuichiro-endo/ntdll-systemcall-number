/*
 * Title:  main.h
 * Author: Shuichiro Endo
 */

#pragma once

HMODULE myGetModuleHandleW(wchar_t * lpModuleName);
DWORD rvaToRaw(PIMAGE_SECTION_HEADER pSectionHeader, WORD numberOfSections, DWORD rva);
int getopt(int argc, char **argv, char *optstring);
void usage(char *filename);


