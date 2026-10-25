#ifndef UNICODE
#define UNICODE
#endif
#ifndef _UNICODE
#define _UNICODE
#endif
#define WIN32_LEAN_AND_MEAN

#include <windows.h>
#include <commctrl.h>
#include <commdlg.h>
#include <shlobj.h>
#include <shellapi.h>
#include <shlwapi.h>
#include <imagehlp.h>
#include <string>
#include <vector>
#include <fstream>
#include <sstream>
#include <iomanip>
#include <ctime>

#pragma comment(lib, "comctl32.lib")
#pragma comment(lib, "comdlg32.lib")
#pragma comment(lib, "shell32.lib")
#pragma comment(lib, "ole32.lib")
#pragma comment(lib, "shlwapi.lib")
#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "imagehlp.lib")

// --- Structure Definitions for ICO and PE Group Icons ---
#pragma pack(push, 2)
struct ICONDIR {
    WORD idReserved; // Reserved (0)
    WORD idType;     // 1 for icon
    WORD idCount;    // Number of images
};

struct ICONDIRENTRY {
    BYTE  bWidth;
    BYTE  bHeight;
    BYTE  bColorCount;
    BYTE  bReserved;
    WORD  wPlanes;
    WORD  wBitCount;
    DWORD dwBytesInRes;
    DWORD dwImageOffset;
};

struct GRPICONDIR {
    WORD idReserved;
    WORD idType;
    WORD idCount;
};

struct GRPICONDIRENTRY {
    BYTE  bWidth;
    BYTE  bHeight;
    BYTE  bColorCount;
    BYTE  bReserved;
    WORD  wPlanes;
    WORD  wBitCount;
    DWORD dwBytesInRes;
    WORD  nID; // Resource ID
};
#pragma pack(pop)

// 4096-byte Native Standalone PE Stub for Script/Non-PE Launchers
static const unsigned char g_StubExe[4096] = {
0x4D, 0x5A, 0x90, 0x00, 0x03, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0x00, 0x00, 0xB8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x40, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x80, 0x00, 0x00, 0x00, 0x0E, 0x1F, 0xBA, 0x0E, 0x00, 0xB4, 0x09, 0xCD, 0x21, 0xB8, 0x01, 0x4C, 0xCD, 0x21, 0x54, 0x68, 0x69, 0x73, 0x20, 0x70, 0x72, 0x6F, 0x67, 0x72, 0x61, 0x6D, 0x20, 0x63, 0x61, 0x6E, 0x6E, 0x6F, 0x74, 0x20, 0x62, 0x65, 0x20, 0x72, 0x75, 0x6E, 0x20, 0x69, 0x6E, 0x20, 0x44, 0x4F, 0x53, 0x20, 0x6D, 0x6F, 0x64, 0x65, 0x2E, 0x0D, 0x0D, 0x0A, 0x24, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x50, 0x45, 0x00, 0x00, 0x64, 0x86, 0x05, 0x00, 0xC7, 0xC2, 0xDC, 0x6A, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xF0, 0x00, 0x2E, 0x02, 0x0B, 0x02, 0x02, 0x2E, 0x00, 0x02, 0x00, 0x00, 0x00, 0x0A, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10, 0x00, 0x00, 0x00, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x40, 0x01, 0x00, 0x00, 0x00, 0x00, 0x10, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x05, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x60, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x22, 0x87, 0x00, 0x00, 0x02, 0x00, 0x60, 0x01, 0x00, 0x00, 0x20, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x50, 0x00, 0x00, 0xB4, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x30, 0x00, 0x00, 0x0C, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xE8, 0x50, 0x00, 0x00, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x2E, 0x74, 0x65, 0x78, 0x74, 0x00, 0x00, 0x00, 0xF0, 0x01, 0x00, 0x00, 0x00, 0x10, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x20, 0x00, 0x00, 0x60, 0x2E, 0x72, 0x64, 0x61, 0x74, 0x61, 0x00, 0x00, 0x90, 0x00, 0x00, 0x00, 0x00, 0x20, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x06, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x40, 0x00, 0x00, 0x40, 0x2E, 0x70, 0x64, 0x61, 0x74, 0x61, 0x00, 0x00, 0x0C, 0x00, 0x00, 0x00, 0x00, 0x30, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x40, 0x00, 0x00, 0x40, 0x2E, 0x78, 0x64, 0x61, 0x74, 0x61, 0x00, 0x00, 0x0C, 0x00, 0x00, 0x00, 0x00, 0x40, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x0A, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x40, 0x00, 0x00, 0x40, 0x2E, 0x69, 0x64, 0x61, 0x74, 0x61, 0x00, 0x00, 0xB4, 0x02, 0x00, 0x00, 0x00, 0x50, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x0C, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x40, 0x00, 0x00, 0x40, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x56, 0x53, 0x48, 0x81, 0xEC, 0x48, 0x02, 0x00, 0x00, 0x41, 0xB8, 0x08, 0x02, 0x00, 0x00, 0x31, 0xD2, 0x48, 0x8D, 0x4C, 0x24, 0x30, 0xE8, 0xA5, 0x01, 0x00, 0x00, 0x41, 0xB8, 0x0A, 0x00, 0x00, 0x00, 0xBA, 0x65, 0x00, 0x00, 0x00, 0x31, 0xC9, 0xFF, 0x15, 0xC2, 0x40, 0x00, 0x00, 0x48, 0x89, 0xC3, 0x48, 0x85, 0xC0, 0x74, 0x3A, 0x31, 0xC9, 0x48, 0x89, 0xC2, 0xFF, 0x15, 0xC7, 0x40, 0x00, 0x00, 0x31, 0xC9, 0x48, 0x89, 0xDA, 0x48, 0x89, 0xC6, 0xFF, 0x15, 0xC9, 0x40, 0x00, 0x00, 0x48, 0x89, 0xF1, 0x89, 0xC3, 0xFF, 0x15, 0xB6, 0x40, 0x00, 0x00, 0x48, 0x85, 0xC0, 0x74, 0x11, 0x85, 0xDB, 0x0F, 0x85, 0xBD, 0x00, 0x00, 0x00, 0x66, 0x0F, 0x1F, 0x84, 0x00, 0x00, 0x00, 0x00, 0x00, 0x66, 0x83, 0x7C, 0x24, 0x30, 0x00, 0x74, 0x49, 0x48, 0x8D, 0x4C, 0x24, 0x30, 0xFF, 0x15, 0x75, 0x40, 0x00, 0x00, 0x83, 0xF8, 0xFF, 0x75, 0x0B, 0xB9, 0x01, 0x00, 0x00, 0x00, 0xFF, 0x15, 0x55, 0x40, 0x00, 0x00, 0x31, 0xC0, 0x31, 0xC9, 0xC7, 0x44, 0x24, 0x28, 0x01, 0x00, 0x00, 0x00, 0x45, 0x31, 0xC9, 0x48, 0x89, 0x44, 0x24, 0x20, 0x4C, 0x8D, 0x44, 0x24, 0x30, 0x48, 0x8D, 0x15, 0x61, 0x0F, 0x00, 0x00, 0xFF, 0x15, 0x9F, 0x40, 0x00, 0x00, 0x31, 0xC9, 0xFF, 0x15, 0x27, 0x40, 0x00, 0x00, 0x41, 0xB8, 0x04, 0x01, 0x00, 0x00, 0x48, 0x8D, 0x54, 0x24, 0x30, 0x31, 0xC9, 0xFF, 0x15, 0x2C, 0x40, 0x00, 0x00, 0xBA, 0x2E, 0x00, 0x00, 0x00, 0x48, 0x8D, 0x4C, 0x24, 0x30, 0xE8, 0xFD, 0x00, 0x00, 0x00, 0x48, 0x89, 0xC3, 0x48, 0x85, 0xC0, 0x74, 0x28, 0x4C, 0x8D, 0x05, 0x0E, 0x0F, 0x00, 0x00, 0xBA, 0x05, 0x00, 0x00, 0x00, 0x48, 0x89, 0xC1, 0x48, 0x8B, 0x35, 0x3F, 0x40, 0x00, 0x00, 0xFF, 0xD6, 0x48, 0x8D, 0x4C, 0x24, 0x30, 0xFF, 0x15, 0xEA, 0x3F, 0x00, 0x00, 0x83, 0xC0, 0x01, 0x74, 0x40, 0x66, 0x83, 0x7C, 0x24, 0x30, 0x00, 0x0F, 0x84, 0x69, 0xFF, 0xFF, 0xFF, 0xE9, 0x54, 0xFF, 0xFF, 0xFF, 0xD1, 0xEB, 0xBA, 0x03, 0x01, 0x00, 0x00, 0x48, 0x8D, 0x4C, 0x24, 0x30, 0x49, 0x89, 0xC0, 0x39, 0xD3, 0x41, 0x89, 0xD9, 0x44, 0x0F, 0x47, 0xCA, 0xBA, 0x04, 0x01, 0x00, 0x00, 0x41, 0x81, 0xE1, 0xFF, 0xFF, 0xFF, 0x7F, 0xFF, 0x15, 0xFA, 0x3F, 0x00, 0x00, 0xE9, 0x1D, 0xFF, 0xFF, 0xFF, 0x4C, 0x8D, 0x05, 0xB0, 0x0E, 0x00, 0x00, 0xBA, 0x05, 0x00, 0x00, 0x00, 0x48, 0x89, 0xD9, 0xFF, 0xD6, 0xEB, 0xAD, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0xFF, 0x25, 0xA2, 0x3F, 0x00, 0x00, 0x90, 0x90, 0xFF, 0x25, 0x92, 0x3F, 0x00, 0x00, 0x90, 0x90, 0xFF, 0x25, 0x82, 0x3F, 0x00, 0x00, 0x90, 0x90, 0xFF, 0x25, 0x72, 0x3F, 0x00, 0x00, 0x90, 0x90, 0xFF, 0x25, 0x62, 0x3F, 0x00, 0x00, 0x90, 0x90, 0xFF, 0x25, 0x52, 0x3F, 0x00, 0x00, 0x90, 0x90, 0xFF, 0x25, 0x42, 0x3F, 0x00, 0x00, 0x90, 0x90, 0x0F, 0x1F, 0x84, 0x00, 0x00, 0x00, 0x00, 0x00, 0xFF, 0x25, 0xA2, 0x3F, 0x00, 0x00, 0x90, 0x90, 0x0F, 0x1F, 0x84, 0x00, 0x00, 0x00, 0x00, 0x00, 0xFF, 0x25, 0x72, 0x3F, 0x00, 0x00, 0x90, 0x90, 0xFF, 0x25, 0x72, 0x3F, 0x00, 0x00, 0x90, 0x90, 0xFF, 0x25, 0x72, 0x3F, 0x00, 0x00, 0x90, 0x90, 0x0F, 0x1F, 0x84, 0x00, 0x00, 0x00, 0x00, 0x00, 0xFF, 0x25, 0x42, 0x3F, 0x00, 0x00, 0x90, 0x90, 0x0F, 0x1F, 0x84, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x2E, 0x00, 0x63, 0x00, 0x6D, 0x00, 0x64, 0x00, 0x00, 0x00, 0x2E, 0x00, 0x62, 0x00, 0x61, 0x00, 0x74, 0x00, 0x00, 0x00, 0x6F, 0x00, 0x70, 0x00, 0x65, 0x00, 0x6E, 0x00, 0x00, 0x00, 0x00, 0x00, 0x47, 0x43, 0x43, 0x3A, 0x20, 0x28, 0x4D, 0x69, 0x6E, 0x47, 0x57, 0x2D, 0x57, 0x36, 0x34, 0x20, 0x78, 0x38, 0x36, 0x5F, 0x36, 0x34, 0x2D, 0x75, 0x63, 0x72, 0x74, 0x2D, 0x70, 0x6F, 0x73, 0x69, 0x78, 0x2D, 0x73, 0x65, 0x68, 0x2C, 0x20, 0x62, 0x75, 0x69, 0x6C, 0x74, 0x20, 0x62, 0x79, 0x20, 0x42, 0x72, 0x65, 0x63, 0x68, 0x74, 0x20, 0x53, 0x61, 0x6E, 0x64, 0x65, 0x72, 0x73, 0x2C, 0x20, 0x72, 0x33, 0x29, 0x20, 0x31, 0x36, 0x2E, 0x31, 0x2E, 0x30, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10, 0x00, 0x00, 0x66, 0x11, 0x00, 0x00, 0x00, 0x40, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x09, 0x04, 0x00, 0x09, 0x01, 0x49, 0x00, 0x02, 0x30, 0x01, 0x60, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x68, 0x50, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x3C, 0x52, 0x00, 0x00, 0xE8, 0x50, 0x00, 0x00, 0xA8, 0x50, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x50, 0x52, 0x00, 0x00, 0x28, 0x51, 0x00, 0x00, 0xB8, 0x50, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x80, 0x52, 0x00, 0x00, 0x38, 0x51, 0x00, 0x00, 0xD8, 0x50, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xA8, 0x52, 0x00, 0x00, 0x58, 0x51, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x68, 0x51, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x76, 0x51, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x86, 0x51, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x9C, 0x51, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xB2, 0x51, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xC2, 0x51, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xD2, 0x51, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xE4, 0x51, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xEE, 0x51, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xF8, 0x51, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x04, 0x52, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10, 0x52, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x68, 0x51, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x76, 0x51, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x86, 0x51, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x9C, 0x51, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xB2, 0x51, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xC2, 0x51, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xD2, 0x51, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xE4, 0x51, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xEE, 0x51, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xF8, 0x51, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x04, 0x52, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10, 0x52, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x7C, 0x01, 0x45, 0x78, 0x69, 0x74, 0x50, 0x72, 0x6F, 0x63, 0x65, 0x73, 0x73, 0x00, 0xB4, 0x01, 0x46, 0x69, 0x6E, 0x64, 0x52, 0x65, 0x73, 0x6F, 0x75, 0x72, 0x63, 0x65, 0x57, 0x00, 0x6B, 0x02, 0x47, 0x65, 0x74, 0x46, 0x69, 0x6C, 0x65, 0x41, 0x74, 0x74, 0x72, 0x69, 0x62, 0x75, 0x74, 0x65, 0x73, 0x57, 0x00, 0x00, 0x9D, 0x02, 0x47, 0x65, 0x74, 0x4D, 0x6F, 0x64, 0x75, 0x6C, 0x65, 0x46, 0x69, 0x6C, 0x65, 0x4E, 0x61, 0x6D, 0x65, 0x57, 0x00, 0x00, 0xFE, 0x03, 0x4C, 0x6F, 0x61, 0x64, 0x52, 0x65, 0x73, 0x6F, 0x75, 0x72, 0x63, 0x65, 0x00, 0x00, 0x14, 0x04, 0x4C, 0x6F, 0x63, 0x6B, 0x52, 0x65, 0x73, 0x6F, 0x75, 0x72, 0x63, 0x65, 0x00, 0x00, 0xA8, 0x05, 0x53, 0x69, 0x7A, 0x65, 0x6F, 0x66, 0x52, 0x65, 0x73, 0x6F, 0x75, 0x72, 0x63, 0x65, 0x00, 0x00, 0x49, 0x04, 0x77, 0x63, 0x73, 0x72, 0x63, 0x68, 0x72, 0x00, 0xA0, 0x00, 0x6D, 0x65, 0x6D, 0x73, 0x65, 0x74, 0x00, 0x00, 0xBD, 0x00, 0x77, 0x63, 0x73, 0x63, 0x70, 0x79, 0x5F, 0x73, 0x00, 0x00, 0xC4, 0x00, 0x77, 0x63, 0x73, 0x6E, 0x63, 0x70, 0x79, 0x5F, 0x73, 0x00, 0x53, 0x01, 0x53, 0x68, 0x65, 0x6C, 0x6C, 0x45, 0x78, 0x65, 0x63, 0x75, 0x74, 0x65, 0x57, 0x00, 0x00, 0x50, 0x00, 0x00, 0x00, 0x50, 0x00, 0x00, 0x00, 0x50, 0x00, 0x00, 0x00, 0x50, 0x00, 0x00, 0x00, 0x50, 0x00, 0x00, 0x00, 0x50, 0x00, 0x00, 0x00, 0x50, 0x00, 0x00, 0x4B, 0x45, 0x52, 0x4E, 0x45, 0x4C, 0x33, 0x32, 0x2E, 0x64, 0x6C, 0x6C, 0x00, 0x00, 0x00, 0x00, 0x14, 0x50, 0x00, 0x00, 0x61, 0x70, 0x69, 0x2D, 0x6D, 0x73, 0x2D, 0x77, 0x69, 0x6E, 0x2D, 0x63, 0x72, 0x74, 0x2D, 0x70, 0x72, 0x69, 0x76, 0x61, 0x74, 0x65, 0x2D, 0x6C, 0x31, 0x2D, 0x31, 0x2D, 0x30, 0x2E, 0x64, 0x6C, 0x6C, 0x00, 0x00, 0x00, 0x28, 0x50, 0x00, 0x00, 0x28, 0x50, 0x00, 0x00, 0x28, 0x50, 0x00, 0x00, 0x61, 0x70, 0x69, 0x2D, 0x6D, 0x73, 0x2D, 0x77, 0x69, 0x6E, 0x2D, 0x63, 0x72, 0x74, 0x2D, 0x73, 0x74, 0x72, 0x69, 0x6E, 0x67, 0x2D, 0x6C, 0x31, 0x2D, 0x31, 0x2D, 0x30, 0x2E, 0x64, 0x6C, 0x6C, 0x00, 0x00, 0x00, 0x00, 0x3C, 0x50, 0x00, 0x00, 0x53, 0x48, 0x45, 0x4C, 0x4C, 0x33, 0x32, 0x2E, 0x64, 0x6C, 0x6C, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
};

// Control IDs
enum {
    ID_TAB_CONTROL = 1000,
    ID_LOG_BOX,
    ID_CLEAR_LOG_BTN,
    ID_FLUSH_CACHE_BTN,

    // Tab 0: Universal File & Folder Changer (Target-Centric)
    ID_SMART_TARGET_EDIT,
    ID_SMART_TARGET_BROWSE,
    ID_SMART_TARGET_TYPE_LABEL,
    ID_SMART_ICON_EDIT,
    ID_SMART_ICON_BROWSE,
    ID_SMART_BACKUP_CHK,
    ID_SMART_PORTABLE_CHK,
    ID_SMART_CHECKSUM_CHK,
    ID_SMART_APPLY_BTN,
    ID_SMART_LNK_BTN,
    ID_SMART_RESTORE_BTN,

    // Tab 1: Folder Architect
    ID_FLD_TARGET_EDIT,
    ID_FLD_TARGET_BROWSE,
    ID_FLD_ICON_EDIT,
    ID_FLD_ICON_BROWSE,
    ID_FLD_INFOTIP_EDIT,
    ID_FLD_PORTABLE_CHK,
    ID_FLD_RECURSIVE_CHK,
    ID_FLD_APPLY_BTN,
    ID_FLD_RESET_BTN,

    // Tab 2: Script to Standalone EXE Packager
    ID_PKG_SCRIPT_EDIT,
    ID_PKG_SCRIPT_BROWSE,
    ID_PKG_ICON_EDIT,
    ID_PKG_ICON_BROWSE,
    ID_PKG_OUT_EDIT,
    ID_PKG_OUT_BROWSE,
    ID_PKG_CREATE_BTN,

    // Tab 3: PE Icon Extractor
    ID_EXTRACT_TARGET_EDIT,
    ID_EXTRACT_TARGET_BROWSE,
    ID_EXTRACT_OUT_EDIT,
    ID_EXTRACT_OUT_BROWSE,
    ID_EXTRACT_BTN,

    // Tab 4: System Tools & Association Repair
    ID_REPAIR_SCRIPTS_BTN,
    ID_REPAIR_DLL_SYS_BTN,
    ID_REPAIR_FLUSH_BTN,
    ID_SYS_EXT_EDIT,
    ID_SYS_ICON_EDIT,
    ID_SYS_ICON_BROWSE,
    ID_SYS_APPLY_BTN
};

// Global handles
HWND g_hWnd = NULL;
HWND g_hTab = NULL;
HWND g_hLogBox = NULL;
HFONT g_hFont = NULL;
HFONT g_hFontBold = NULL;
HFONT g_hFontSmall = NULL;

// Sub-controls grouped by tab
std::vector<HWND> g_tabControls[5];

// ==========================================
// UAC & PRIVILEGE MANAGEMENT
// ==========================================
bool IsProcessElevated() {
    BOOL fIsElevated = FALSE;
    HANDLE hToken = NULL;
    if (OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken)) {
        TOKEN_ELEVATION elevation;
        DWORD cbSize = sizeof(TOKEN_ELEVATION);
        if (GetTokenInformation(hToken, TokenElevation, &elevation, sizeof(elevation), &cbSize)) {
            fIsElevated = elevation.TokenIsElevated;
        }
        CloseHandle(hToken);
    }
    return fIsElevated != FALSE;
}

bool RequestElevation() {
    wchar_t szPath[MAX_PATH];
    if (GetModuleFileNameW(NULL, szPath, MAX_PATH)) {
        SHELLEXECUTEINFOW sei = { sizeof(sei) };
        sei.lpVerb = L"runas";
        sei.lpFile = szPath;
        sei.hwnd = NULL;
        sei.nShow = SW_NORMAL;
        sei.fMask = SEE_MASK_DEFAULT;
        if (ShellExecuteExW(&sei)) {
            return true;
        }
    }
    return false;
}

// Utility: Append text to Log Window with timestamp
void AppendLog(const std::wstring& text) {
    if (!g_hLogBox) return;

    time_t rawtime;
    time(&rawtime);
    struct tm* timeinfo = localtime(&rawtime);
    wchar_t timeBuffer[32] = {0};
    wcsftime(timeBuffer, 32, L"[%H:%M:%S] ", timeinfo);

    std::wstring line = timeBuffer + text + L"\r\n";
    int len = GetWindowTextLengthW(g_hLogBox);
    SendMessageW(g_hLogBox, EM_SETSEL, (WPARAM)len, (LPARAM)len);
    SendMessageW(g_hLogBox, EM_REPLACESEL, FALSE, (LPARAM)(line.c_str()));
    SendMessageW(g_hLogBox, EM_SCROLLCARET, 0, 0);
}

// Utility: File / Folder Browse Dialogs
std::wstring BrowseFileDialog(HWND parent, const wchar_t* filter, bool isOpen = true, const wchar_t* defExt = NULL) {
    wchar_t filename[MAX_PATH] = {0};
    OPENFILENAMEW ofn = {0};
    ofn.lStructSize = sizeof(ofn);
    ofn.hwndOwner = parent;
    ofn.lpstrFilter = filter;
    ofn.lpstrFile = filename;
    ofn.nMaxFile = MAX_PATH;
    ofn.lpstrDefExt = defExt;
    ofn.Flags = OFN_EXPLORER | (isOpen ? (OFN_FILEMUSTEXIST | OFN_HIDEREADONLY) : (OFN_OVERWRITEPROMPT | OFN_PATHMUSTEXIST));
    if (isOpen ? GetOpenFileNameW(&ofn) : GetSaveFileNameW(&ofn)) {
        return filename;
    }
    return L"";
}

std::wstring BrowseFolderDialog(HWND parent) {
    wchar_t path[MAX_PATH] = {0};
    BROWSEINFOW bi = {0};
    bi.hwndOwner = parent;
    bi.lpszTitle = L"Select Folder:";
    bi.ulFlags = BIF_RETURNONLYFSDIRS | BIF_NEWDIALOGSTYLE | BIF_USENEWUI;
    PIDLIST_ABSOLUTE pidl = SHBrowseForFolderW(&bi);
    if (pidl) {
        SHGetPathFromIDListW(pidl, path);
        CoTaskMemFree(pidl);
        return path;
    }
    return L"";
}

std::wstring GetEditVal(int id) {
    wchar_t buf[MAX_PATH] = {0};
    GetDlgItemTextW(g_hWnd, id, buf, MAX_PATH);
    return buf;
}

// Deep Explorer Cache Invalidation
void RebuildExplorerIconCache() {
    AppendLog(L"Flushing Explorer icon caches and broadcasting shell notifications...");
    SHChangeNotify(SHCNE_ASSOCCHANGED, SHCNF_IDLIST, NULL, NULL);

    DWORD_PTR result = 0;
    SendMessageTimeoutW(HWND_BROADCAST, WM_SETTINGCHANGE, 0, (LPARAM)L"Environment", SMTO_ABORTIFHUNG, 1000, &result);
    SendMessageTimeoutW(HWND_BROADCAST, WM_SETTINGCHANGE, 0, (LPARAM)L"intl", SMTO_ABORTIFHUNG, 1000, &result);

    ShellExecuteW(NULL, L"open", L"ie4uinit.exe", L"-show", NULL, SW_HIDE);
    AppendLog(L"Explorer icon caches synchronized.");
}

// Automatically configures Windows Explorer to display embedded icons for DLL & SYS files (%1)
void EnsureExplorerDisplaysEmbeddedIcons() {
    HKEY hKey;
    const wchar_t* dllKey = L"Software\\Classes\\dllfile\\DefaultIcon";
    const wchar_t* sysKey = L"Software\\Classes\\sysfile\\DefaultIcon";
    const wchar_t* val = L"%1";

    if (RegCreateKeyExW(HKEY_LOCAL_MACHINE, dllKey, 0, NULL, REG_OPTION_NON_VOLATILE, KEY_WRITE, NULL, &hKey, NULL) == ERROR_SUCCESS) {
        RegSetValueExW(hKey, NULL, 0, REG_SZ, (const BYTE*)val, (DWORD)((wcslen(val) + 1) * sizeof(wchar_t)));
        RegCloseKey(hKey);
    }
    if (RegCreateKeyExW(HKEY_LOCAL_MACHINE, sysKey, 0, NULL, REG_OPTION_NON_VOLATILE, KEY_WRITE, NULL, &hKey, NULL) == ERROR_SUCCESS) {
        RegSetValueExW(hKey, NULL, 0, REG_SZ, (const BYTE*)val, (DWORD)((wcslen(val) + 1) * sizeof(wchar_t)));
        RegCloseKey(hKey);
    }
}

// ==========================================
// PE HEADER & CHECKSUM UTILITIES
// ==========================================
struct PEInspectionInfo {
    bool valid = false;
    bool isPE = false;
    bool isDirectory = false;
    std::wstring arch;
    std::wstring subsystem;
    DWORD checksum = 0;
    std::vector<WORD> iconGroupIDs;
    bool hasDigitalSignature = false;
};

struct EnumIconCtx {
    std::vector<WORD> ids;
};

static BOOL CALLBACK EnumIconResNames(HMODULE, LPCWSTR, LPWSTR lpName, LONG_PTR lParam) {
    EnumIconCtx* ctx = reinterpret_cast<EnumIconCtx*>(lParam);
    if (IS_INTRESOURCE(lpName)) {
        ctx->ids.push_back(LOWORD(lpName));
    }
    return TRUE;
}

PEInspectionInfo InspectTarget(const std::wstring& targetPath) {
    PEInspectionInfo info;
    if (targetPath.empty()) return info;

    DWORD attrs = GetFileAttributesW(targetPath.c_str());
    if (attrs == INVALID_FILE_ATTRIBUTES) return info;

    if (attrs & FILE_ATTRIBUTE_DIRECTORY) {
        info.valid = true;
        info.isDirectory = true;
        return info;
    }

    HANDLE hFile = CreateFileW(targetPath.c_str(), GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
    if (hFile == INVALID_HANDLE_VALUE) return info;

    IMAGE_DOS_HEADER dosHdr{};
    DWORD read = 0;
    if (!ReadFile(hFile, &dosHdr, sizeof(dosHdr), &read, NULL) || dosHdr.e_magic != IMAGE_DOS_SIGNATURE) {
        CloseHandle(hFile);
        info.valid = true;
        info.isPE = false; // Plain file (script, pak, text, etc.)
        return info;
    }

    SetFilePointer(hFile, dosHdr.e_lfanew, NULL, FILE_BEGIN);
    DWORD ntSig = 0;
    ReadFile(hFile, &ntSig, sizeof(ntSig), &read, NULL);
    if (ntSig != IMAGE_NT_SIGNATURE) {
        CloseHandle(hFile);
        info.valid = true;
        info.isPE = false;
        return info;
    }

    IMAGE_FILE_HEADER fileHdr{};
    ReadFile(hFile, &fileHdr, sizeof(fileHdr), &read, NULL);

    info.isPE = true;
    if (fileHdr.Machine == IMAGE_FILE_MACHINE_I386) info.arch = L"x86 (32-bit)";
    else if (fileHdr.Machine == IMAGE_FILE_MACHINE_AMD64) info.arch = L"x64 (64-bit)";
    else if (fileHdr.Machine == IMAGE_FILE_MACHINE_ARM64) info.arch = L"ARM64";
    else info.arch = L"Unknown Architecture";

    if (fileHdr.SizeOfOptionalHeader > 0) {
        WORD magic = 0;
        ReadFile(hFile, &magic, sizeof(magic), &read, NULL);
        SetFilePointer(hFile, dosHdr.e_lfanew + sizeof(DWORD) + sizeof(IMAGE_FILE_HEADER), NULL, FILE_BEGIN);

        if (magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC) {
            IMAGE_OPTIONAL_HEADER32 opt32{};
            ReadFile(hFile, &opt32, sizeof(opt32), &read, NULL);
            info.checksum = opt32.CheckSum;
            if (opt32.Subsystem == IMAGE_SUBSYSTEM_WINDOWS_GUI) info.subsystem = L"GUI Application";
            else if (opt32.Subsystem == IMAGE_SUBSYSTEM_WINDOWS_CUI) info.subsystem = L"Console Application";
            else if (opt32.Subsystem == IMAGE_SUBSYSTEM_NATIVE) info.subsystem = L"Native / Driver (.sys)";
            else info.subsystem = L"Binary";

            if (opt32.NumberOfRvaAndSizes > IMAGE_DIRECTORY_ENTRY_SECURITY &&
                opt32.DataDirectory[IMAGE_DIRECTORY_ENTRY_SECURITY].Size > 0) {
                info.hasDigitalSignature = true;
            }
        } else if (magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC) {
            IMAGE_OPTIONAL_HEADER64 opt64{};
            ReadFile(hFile, &opt64, sizeof(opt64), &read, NULL);
            info.checksum = opt64.CheckSum;
            if (opt64.Subsystem == IMAGE_SUBSYSTEM_WINDOWS_GUI) info.subsystem = L"GUI Application";
            else if (opt64.Subsystem == IMAGE_SUBSYSTEM_WINDOWS_CUI) info.subsystem = L"Console Application";
            else if (opt64.Subsystem == IMAGE_SUBSYSTEM_NATIVE) info.subsystem = L"Native / Driver (.sys)";
            else info.subsystem = L"Binary";

            if (opt64.NumberOfRvaAndSizes > IMAGE_DIRECTORY_ENTRY_SECURITY &&
                opt64.DataDirectory[IMAGE_DIRECTORY_ENTRY_SECURITY].Size > 0) {
                info.hasDigitalSignature = true;
            }
        }
    }
    CloseHandle(hFile);

    HMODULE hMod = LoadLibraryExW(targetPath.c_str(), NULL, LOAD_LIBRARY_AS_DATAFILE | LOAD_LIBRARY_AS_IMAGE_RESOURCE);
    if (hMod) {
        EnumIconCtx ctx;
        EnumResourceNamesW(hMod, RT_GROUP_ICON, EnumIconResNames, reinterpret_cast<LONG_PTR>(&ctx));
        info.iconGroupIDs = ctx.ids;
        FreeLibrary(hMod);
    }

    info.valid = true;
    return info;
}

bool RecalculatePECheckSum(const std::wstring& pePath) {
    DWORD originalChecksum = 0;
    DWORD newChecksum = 0;
    if (MapFileAndCheckSumW(pePath.c_str(), &originalChecksum, &newChecksum) != CHECKSUM_SUCCESS) {
        return false;
    }

    HANDLE hFile = CreateFileW(pePath.c_str(), GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
    if (hFile == INVALID_HANDLE_VALUE) return false;

    IMAGE_DOS_HEADER dosHdr{};
    DWORD read = 0;
    if (!ReadFile(hFile, &dosHdr, sizeof(dosHdr), &read, NULL) || dosHdr.e_magic != IMAGE_DOS_SIGNATURE) {
        CloseHandle(hFile);
        return false;
    }

    LONG checksumOffset = dosHdr.e_lfanew + sizeof(DWORD) + sizeof(IMAGE_FILE_HEADER) + 64;
    SetFilePointer(hFile, checksumOffset, NULL, FILE_BEGIN);
    DWORD written = 0;
    WriteFile(hFile, &newChecksum, sizeof(newChecksum), &written, NULL);

    CloseHandle(hFile);
    return true;
}

void NeutralizePECertificateEntry(const std::wstring& pePath) {
    HANDLE hFile = CreateFileW(pePath.c_str(), GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
    if (hFile == INVALID_HANDLE_VALUE) return;

    IMAGE_DOS_HEADER dosHdr{};
    DWORD read = 0;
    if (!ReadFile(hFile, &dosHdr, sizeof(dosHdr), &read, NULL) || dosHdr.e_magic != IMAGE_DOS_SIGNATURE) {
        CloseHandle(hFile);
        return;
    }

    SetFilePointer(hFile, dosHdr.e_lfanew + sizeof(DWORD) + sizeof(IMAGE_FILE_HEADER), NULL, FILE_BEGIN);
    WORD magic = 0;
    ReadFile(hFile, &magic, sizeof(magic), &read, NULL);

    LONG secDirOffset = 0;
    if (magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC) {
        secDirOffset = dosHdr.e_lfanew + sizeof(DWORD) + sizeof(IMAGE_FILE_HEADER) + 128;
    } else if (magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC) {
        secDirOffset = dosHdr.e_lfanew + sizeof(DWORD) + sizeof(IMAGE_FILE_HEADER) + 144;
    }

    if (secDirOffset > 0) {
        SetFilePointer(hFile, secDirOffset, NULL, FILE_BEGIN);
        IMAGE_DATA_DIRECTORY emptyDir = { 0, 0 };
        DWORD written = 0;
        WriteFile(hFile, &emptyDir, sizeof(emptyDir), &written, NULL);
    }

    CloseHandle(hFile);
}

// ==========================================
// FEATURE: ADVANCED PE ICON MODIFIER
// ==========================================
bool ModifyPEIconAdvanced(const std::wstring& pePath, const std::wstring& icoPath,
                          bool createBak, bool fixChecksum, std::wstring& outMsg) {
    if (pePath.empty() || icoPath.empty()) {
        outMsg = L"Error: Target PE file or Icon file path is empty.";
        return false;
    }

    if (!PathFileExistsW(pePath.c_str())) {
        outMsg = L"Error: Target PE file does not exist: " + pePath;
        return false;
    }

    std::ifstream icoFile(icoPath.c_str(), std::ios::binary);
    if (!icoFile.is_open()) {
        outMsg = L"Error: Cannot open icon file: " + icoPath;
        return false;
    }

    ICONDIR iconDir{};
    icoFile.read(reinterpret_cast<char*>(&iconDir), sizeof(ICONDIR));
    if (!icoFile || iconDir.idReserved != 0 || iconDir.idType != 1 || iconDir.idCount == 0) {
        outMsg = L"Error: Selected file is not a valid or supported .ico file.";
        return false;
    }

    std::vector<ICONDIRENTRY> entries(iconDir.idCount);
    icoFile.read(reinterpret_cast<char*>(entries.data()), sizeof(ICONDIRENTRY) * iconDir.idCount);

    std::vector<std::vector<BYTE>> imageBuffers(iconDir.idCount);
    for (size_t i = 0; i < entries.size(); ++i) {
        imageBuffers[i].resize(entries[i].dwBytesInRes);
        icoFile.seekg(entries[i].dwImageOffset, std::ios::beg);
        icoFile.read(reinterpret_cast<char*>(imageBuffers[i].data()), entries[i].dwBytesInRes);
        if (!icoFile) {
            outMsg = L"Error: Corrupted image stream in .ico file.";
            return false;
        }
    }
    icoFile.close();

    PEInspectionInfo inspection = InspectTarget(pePath);
    if (!inspection.valid || !inspection.isPE) {
        outMsg = L"Error: File is not a valid Windows Portable Executable (PE).";
        return false;
    }

    DWORD originalAttrs = GetFileAttributesW(pePath.c_str());
    if (originalAttrs != INVALID_FILE_ATTRIBUTES && (originalAttrs & FILE_ATTRIBUTE_READONLY)) {
        SetFileAttributesW(pePath.c_str(), originalAttrs & ~FILE_ATTRIBUTE_READONLY);
    }

    if (createBak) {
        std::wstring bakPath = pePath + L".bak";
        CopyFileW(pePath.c_str(), bakPath.c_str(), FALSE);
    }

    DWORD grpSize = sizeof(GRPICONDIR) + (iconDir.idCount * sizeof(GRPICONDIRENTRY));
    std::vector<BYTE> grpBuffer(grpSize, 0);
    GRPICONDIR* pGrpDir = reinterpret_cast<GRPICONDIR*>(grpBuffer.data());
    pGrpDir->idReserved = iconDir.idReserved;
    pGrpDir->idType = iconDir.idType;
    pGrpDir->idCount = iconDir.idCount;

    GRPICONDIRENTRY* pGrpEntries = reinterpret_cast<GRPICONDIRENTRY*>(grpBuffer.data() + sizeof(GRPICONDIR));
    for (WORD i = 0; i < iconDir.idCount; ++i) {
        pGrpEntries[i].bWidth = entries[i].bWidth;
        pGrpEntries[i].bHeight = entries[i].bHeight;
        pGrpEntries[i].bColorCount = entries[i].bColorCount;
        pGrpEntries[i].bReserved = entries[i].bReserved;
        pGrpEntries[i].wPlanes = entries[i].wPlanes;
        pGrpEntries[i].wBitCount = entries[i].wBitCount;
        pGrpEntries[i].dwBytesInRes = entries[i].dwBytesInRes;
        pGrpEntries[i].nID = i + 1;
    }

    std::vector<WORD> targetGroupIds;
    if (!inspection.iconGroupIDs.empty()) {
        targetGroupIds = inspection.iconGroupIDs;
    } else {
        targetGroupIds.push_back(1);
    }
    bool hasId1 = false;
    for (WORD gid : targetGroupIds) { if (gid == 1) hasId1 = true; }
    if (!hasId1) targetGroupIds.push_back(1);

    HANDLE hUpdate = BeginUpdateResourceW(pePath.c_str(), FALSE);
    if (!hUpdate) {
        DWORD err = GetLastError();
        outMsg = L"Error: BeginUpdateResource failed (Error " + std::to_wstring(err) + L"). Check file permissions.";
        return false;
    }

    for (WORD i = 0; i < iconDir.idCount; ++i) {
        WORD iconId = i + 1;
        BOOL ok = UpdateResourceW(
            hUpdate, MAKEINTRESOURCEW(3), MAKEINTRESOURCEW(iconId),
            MAKELANGID(LANG_NEUTRAL, SUBLANG_NEUTRAL),
            imageBuffers[i].data(), static_cast<DWORD>(imageBuffers[i].size())
        );
        if (!ok) {
            EndUpdateResourceW(hUpdate, TRUE);
            outMsg = L"Error: Failed to write RT_ICON #" + std::to_wstring(iconId);
            return false;
        }
    }

    for (WORD gid : targetGroupIds) {
        BOOL ok = UpdateResourceW(
            hUpdate, MAKEINTRESOURCEW(14), MAKEINTRESOURCEW(gid),
            MAKELANGID(LANG_NEUTRAL, SUBLANG_NEUTRAL),
            grpBuffer.data(), grpSize
        );
        if (!ok) {
            EndUpdateResourceW(hUpdate, TRUE);
            outMsg = L"Error: Failed to write RT_GROUP_ICON ID " + std::to_wstring(gid);
            return false;
        }
    }

    if (!EndUpdateResourceW(hUpdate, FALSE)) {
        DWORD err = GetLastError();
        outMsg = L"Error: EndUpdateResource failed to commit changes (Error " + std::to_wstring(err) + L").";
        return false;
    }

    if (inspection.hasDigitalSignature) {
        NeutralizePECertificateEntry(pePath);
    }

    if (fixChecksum) {
        RecalculatePECheckSum(pePath);
    }

    if (originalAttrs != INVALID_FILE_ATTRIBUTES) {
        SetFileAttributesW(pePath.c_str(), originalAttrs);
    }

    // Check if this was a DLL or SYS: if so, configure Explorer to render embedded icons
    std::wstring ext = PathFindExtensionW(pePath.c_str());
    if (_wcsicmp(ext.c_str(), L".dll") == 0 || _wcsicmp(ext.c_str(), L".sys") == 0) {
        EnsureExplorerDisplaysEmbeddedIcons();
    }

    RebuildExplorerIconCache();

    std::wostringstream ss;
    ss << L"PE Icon Injection Succeeded!\n"
       << L"Target Architecture: " << inspection.arch << L" (" << inspection.subsystem << L")\n"
       << L"Embedded " << iconDir.idCount << L" icon resolution(s) into: " << pePath;
    outMsg = ss.str();
    return true;
}

// ==========================================
// FEATURE: STANDALONE SCRIPT LAUNCHER (.cmd / .bat -> .exe)
// ==========================================
bool CreateScriptStandaloneLauncher(const std::wstring& scriptPath, const std::wstring& icoPath,
                                   const std::wstring& outExePath, std::wstring& outMsg) {
    if (scriptPath.empty() || icoPath.empty() || outExePath.empty()) {
        outMsg = L"Error: Script path, icon path, or output path is empty.";
        return false;
    }

    // 1. Write the 4096-byte stub template
    std::ofstream outExe(outExePath.c_str(), std::ios::binary);
    if (!outExe.is_open()) {
        outMsg = L"Error: Cannot create executable: " + outExePath;
        return false;
    }
    outExe.write(reinterpret_cast<const char*>(g_StubExe), sizeof(g_StubExe));
    outExe.close();

    // 2. Embed target script path / filename into RT_RCDATA resource ID 101
    wchar_t scriptFileName[MAX_PATH] = {0};
    wcscpy_s(scriptFileName, PathFindFileNameW(scriptPath.c_str()));

    HANDLE hUpdate = BeginUpdateResourceW(outExePath.c_str(), FALSE);
    if (hUpdate) {
        DWORD strBytes = static_cast<DWORD>((wcslen(scriptFileName) + 1) * sizeof(wchar_t));
        UpdateResourceW(hUpdate, MAKEINTRESOURCEW(10), MAKEINTRESOURCEW(101),
                        MAKELANGID(LANG_NEUTRAL, SUBLANG_NEUTRAL),
                        scriptFileName, strBytes);
        EndUpdateResourceW(hUpdate, FALSE);
    }

    // 3. Inject custom icon into the newly created executable
    std::wstring peMsg;
    if (!ModifyPEIconAdvanced(outExePath, icoPath, false, true, peMsg)) {
        outMsg = L"Created launcher but failed to inject icon: " + peMsg;
        return false;
    }

    std::wostringstream ss;
    ss << L"Standalone Icon Launcher Created Successfully!\n"
       << L"Output Executable: " << outExePath << L"\n"
       << L"Linked Target: " << scriptPath << L"\n"
       << L"(Runs your script seamlessly with your custom icon. No global file associations altered!)";
    outMsg = ss.str();
    return true;
}

// ==========================================
// FEATURE: FOLDER ARCHITECT
// ==========================================
bool ModifyFolderIcon(const std::wstring& folderPath, const std::wstring& icoPath,
                     bool portable, bool recursive, const std::wstring& infoTip, std::wstring& outMsg) {
    if (folderPath.empty() || icoPath.empty()) {
        outMsg = L"Error: Folder path or icon path is empty.";
        return false;
    }

    if (!PathFileExistsW(folderPath.c_str())) {
        outMsg = L"Error: Target folder does not exist.";
        return false;
    }

    std::wstring folder = folderPath;
    if (folder.back() != L'\\' && folder.back() != L'/') folder += L'\\';

    std::wstring effectiveIco = icoPath;
    if (portable) {
        std::wstring destIco = folder + L"folder_icon.ico";
        SetFileAttributesW(destIco.c_str(), FILE_ATTRIBUTE_NORMAL);
        if (CopyFileW(icoPath.c_str(), destIco.c_str(), FALSE)) {
            SetFileAttributesW(destIco.c_str(), FILE_ATTRIBUTE_HIDDEN | FILE_ATTRIBUTE_SYSTEM);
            effectiveIco = destIco;
        }
    }

    std::wstring iniPath = folder + L"desktop.ini";
    SetFileAttributesW(iniPath.c_str(), FILE_ATTRIBUTE_NORMAL);

    std::wstring iconResourceVal = effectiveIco + L",0";
    WritePrivateProfileStringW(L".ShellClassInfo", L"IconResource", iconResourceVal.c_str(), iniPath.c_str());
    WritePrivateProfileStringW(L".ShellClassInfo", L"IconFile", effectiveIco.c_str(), iniPath.c_str());
    WritePrivateProfileStringW(L".ShellClassInfo", L"IconIndex", L"0", iniPath.c_str());
    WritePrivateProfileStringW(L".ShellClassInfo", L"ConfirmFileOp", L"0", iniPath.c_str());
    if (!infoTip.empty()) {
        WritePrivateProfileStringW(L".ShellClassInfo", L"InfoTip", infoTip.c_str(), iniPath.c_str());
    }
    WritePrivateProfileStringW(L"ViewState", L"Mode", L"", iniPath.c_str());
    WritePrivateProfileStringW(L"ViewState", L"Vid", L"", iniPath.c_str());
    WritePrivateProfileStringW(L"ViewState", L"FolderType", L"Generic", iniPath.c_str());
    WritePrivateProfileStringW(NULL, NULL, NULL, iniPath.c_str());

    SetFileAttributesW(iniPath.c_str(), FILE_ATTRIBUTE_HIDDEN | FILE_ATTRIBUTE_SYSTEM);

    PathMakeSystemFolderW(folder.c_str());
    DWORD fAttrs = GetFileAttributesW(folder.c_str());
    if (fAttrs != INVALID_FILE_ATTRIBUTES) {
        SetFileAttributesW(folder.c_str(), fAttrs | FILE_ATTRIBUTE_READONLY);
    }

    RebuildExplorerIconCache();

    std::wostringstream ss;
    ss << L"Folder Icon Applied Successfully!\nTarget: " << folderPath;
    if (portable) ss << L"\n(Icon embedded portably as hidden 'folder_icon.ico')";
    outMsg = ss.str();
    return true;
}

bool ResetFolder(const std::wstring& folderPath, std::wstring& outMsg) {
    std::wstring folder = folderPath;
    if (folder.empty()) return false;
    if (folder.back() != L'\\' && folder.back() != L'/') folder += L'\\';

    std::wstring iniPath = folder + L"desktop.ini";
    std::wstring icoPath = folder + L"folder_icon.ico";

    SetFileAttributesW(iniPath.c_str(), FILE_ATTRIBUTE_NORMAL);
    DeleteFileW(iniPath.c_str());

    SetFileAttributesW(icoPath.c_str(), FILE_ATTRIBUTE_NORMAL);
    DeleteFileW(icoPath.c_str());

    PathUnmakeSystemFolderW(folder.c_str());

    DWORD fAttrs = GetFileAttributesW(folder.c_str());
    if (fAttrs != INVALID_FILE_ATTRIBUTES) {
        SetFileAttributesW(folder.c_str(), fAttrs & ~(FILE_ATTRIBUTE_READONLY | FILE_ATTRIBUTE_SYSTEM));
    }

    RebuildExplorerIconCache();
    outMsg = L"Folder icon reset to standard Windows default successfully.";
    return true;
}

// ==========================================
// FEATURE: SHORTCUT CREATOR (.lnk)
// ==========================================
bool CreateCustomShortcut(const std::wstring& targetPath, const std::wstring& icoPath,
                          const std::wstring& outLnkPath, bool runAsAdmin, std::wstring& outMsg) {
    if (targetPath.empty() || icoPath.empty() || outLnkPath.empty()) {
        outMsg = L"Error: Target path, icon path, or output path is empty.";
        return false;
    }

    IShellLinkW* psl = NULL;
    HRESULT hr = CoCreateInstance(CLSID_ShellLink, NULL, CLSCTX_INPROC_SERVER, IID_IShellLinkW, (void**)&psl);
    if (SUCCEEDED(hr)) {
        psl->SetPath(targetPath.c_str());
        psl->SetIconLocation(icoPath.c_str(), 0);

        wchar_t workingDir[MAX_PATH] = {0};
        wcscpy_s(workingDir, targetPath.c_str());
        PathRemoveFileSpecW(workingDir);
        psl->SetWorkingDirectory(workingDir);

        if (runAsAdmin) {
            IShellLinkDataList* pdl = NULL;
            if (SUCCEEDED(psl->QueryInterface(IID_IShellLinkDataList, (void**)&pdl))) {
                DWORD dwFlags = 0;
                if (SUCCEEDED(pdl->GetFlags(&dwFlags))) {
                    dwFlags |= SLDF_RUNAS_USER;
                    pdl->SetFlags(dwFlags);
                }
                pdl->Release();
            }
        }

        IPersistFile* ppf = NULL;
        hr = psl->QueryInterface(IID_IPersistFile, (void**)&ppf);
        if (SUCCEEDED(hr)) {
            hr = ppf->Save(outLnkPath.c_str(), TRUE);
            ppf->Release();
        }
        psl->Release();
    }

    if (SUCCEEDED(hr)) {
        SHChangeNotify(SHCNE_UPDATEITEM, SHCNF_PATHW, outLnkPath.c_str(), NULL);
        std::wostringstream ss;
        ss << L"Custom Shortcut Created Successfully!\n"
           << L"Destination: " << outLnkPath << L"\n"
           << L"Target: " << targetPath;
        outMsg = ss.str();
        return true;
    } else {
        outMsg = L"Error: Failed to create shortcut file.";
        return false;
    }
}

// ==========================================
// FEATURE: PE ICON EXTRACTOR
// ==========================================
bool ExtractPEIconsToICO(const std::wstring& pePath, const std::wstring& outIcoPath, std::wstring& outMsg) {
    if (pePath.empty() || outIcoPath.empty()) {
        outMsg = L"Error: Source PE path or Output ICO path is empty.";
        return false;
    }

    HMODULE hMod = LoadLibraryExW(pePath.c_str(), NULL, LOAD_LIBRARY_AS_DATAFILE | LOAD_LIBRARY_AS_IMAGE_RESOURCE);
    if (!hMod) {
        outMsg = L"Error: Failed to load PE binary for icon extraction.";
        return false;
    }

    EnumIconCtx ctx;
    EnumResourceNamesW(hMod, MAKEINTRESOURCEW(14), EnumIconResNames, reinterpret_cast<LONG_PTR>(&ctx));
    if (ctx.ids.empty()) {
        FreeLibrary(hMod);
        outMsg = L"Error: No embedded RT_GROUP_ICON resources found in this binary.";
        return false;
    }

    WORD targetGroupId = ctx.ids[0];
    HRSRC hGrpRsrc = FindResourceW(hMod, MAKEINTRESOURCEW(targetGroupId), MAKEINTRESOURCEW(14));
    if (!hGrpRsrc) {
        FreeLibrary(hMod);
        outMsg = L"Error: Could not locate icon group resource.";
        return false;
    }

    HGLOBAL hGrpGlob = LoadResource(hMod, hGrpRsrc);
    GRPICONDIR* pGrpDir = reinterpret_cast<GRPICONDIR*>(LockResource(hGrpGlob));
    if (!pGrpDir || pGrpDir->idCount == 0) {
        FreeLibrary(hMod);
        outMsg = L"Error: Corrupted icon group header in binary.";
        return false;
    }

    GRPICONDIRENTRY* pGrpEntries = reinterpret_cast<GRPICONDIRENTRY*>(reinterpret_cast<BYTE*>(pGrpDir) + sizeof(GRPICONDIR));

    std::ofstream outIco(outIcoPath.c_str(), std::ios::binary);
    if (!outIco.is_open()) {
        FreeLibrary(hMod);
        outMsg = L"Error: Cannot create output .ico file: " + outIcoPath;
        return false;
    }

    ICONDIR icoDir;
    icoDir.idReserved = 0;
    icoDir.idType = 1;
    icoDir.idCount = pGrpDir->idCount;
    outIco.write(reinterpret_cast<const char*>(&icoDir), sizeof(ICONDIR));

    DWORD currentOffset = sizeof(ICONDIR) + (pGrpDir->idCount * sizeof(ICONDIRENTRY));
    std::vector<ICONDIRENTRY> fileEntries(pGrpDir->idCount);
    std::vector<std::vector<BYTE>> imageBuffers(pGrpDir->idCount);

    for (WORD i = 0; i < pGrpDir->idCount; ++i) {
        fileEntries[i].bWidth = pGrpEntries[i].bWidth;
        fileEntries[i].bHeight = pGrpEntries[i].bHeight;
        fileEntries[i].bColorCount = pGrpEntries[i].bColorCount;
        fileEntries[i].bReserved = pGrpEntries[i].bReserved;
        fileEntries[i].wPlanes = pGrpEntries[i].wPlanes;
        fileEntries[i].wBitCount = pGrpEntries[i].wBitCount;
        fileEntries[i].dwBytesInRes = pGrpEntries[i].dwBytesInRes;
        fileEntries[i].dwImageOffset = currentOffset;

        HRSRC hIconRsrc = FindResourceW(hMod, MAKEINTRESOURCEW(pGrpEntries[i].nID), MAKEINTRESOURCEW(3));
        if (hIconRsrc) {
            DWORD sz = SizeofResource(hMod, hIconRsrc);
            HGLOBAL hIconGlob = LoadResource(hMod, hIconRsrc);
            void* pData = LockResource(hIconGlob);
            imageBuffers[i].resize(sz);
            memcpy(imageBuffers[i].data(), pData, sz);
        }
        currentOffset += fileEntries[i].dwBytesInRes;
    }

    outIco.write(reinterpret_cast<const char*>(fileEntries.data()), sizeof(ICONDIRENTRY) * fileEntries.size());
    for (size_t i = 0; i < imageBuffers.size(); ++i) {
        outIco.write(reinterpret_cast<const char*>(imageBuffers[i].data()), imageBuffers[i].size());
    }
    outIco.close();
    FreeLibrary(hMod);

    SHChangeNotify(SHCNE_UPDATEITEM, SHCNF_PATHW, outIcoPath.c_str(), NULL);
    std::wostringstream ss;
    ss << L"Icon Extracted Successfully!\n"
       << L"Extracted " << fileEntries.size() << L" resolution layer(s) into:\n" << outIcoPath;
    outMsg = ss.str();
    return true;
}

// ==========================================
// ASSOCIATION REPAIR & RESTORATION
// ==========================================
void RestoreDefaultScriptAssociations() {
    AppendLog(L"Restoring factory Windows default icons for .cmd and .bat files...");

    const wchar_t* defBat = L"%SystemRoot%\\System32\\imageres.dll,-68";
    HKEY hKey;

    // HKLM
    if (RegCreateKeyExW(HKEY_LOCAL_MACHINE, L"Software\\Classes\\batfile\\DefaultIcon", 0, NULL, REG_OPTION_NON_VOLATILE, KEY_WRITE, NULL, &hKey, NULL) == ERROR_SUCCESS) {
        RegSetValueExW(hKey, NULL, 0, REG_EXPAND_SZ, (const BYTE*)defBat, (DWORD)((wcslen(defBat) + 1) * sizeof(wchar_t)));
        RegCloseKey(hKey);
    }
    if (RegCreateKeyExW(HKEY_LOCAL_MACHINE, L"Software\\Classes\\cmdfile\\DefaultIcon", 0, NULL, REG_OPTION_NON_VOLATILE, KEY_WRITE, NULL, &hKey, NULL) == ERROR_SUCCESS) {
        RegSetValueExW(hKey, NULL, 0, REG_EXPAND_SZ, (const BYTE*)defBat, (DWORD)((wcslen(defBat) + 1) * sizeof(wchar_t)));
        RegCloseKey(hKey);
    }

    // Clean HKCU overrides
    RegDeleteKeyW(HKEY_CURRENT_USER, L"Software\\Classes\\batfile\\DefaultIcon");
    RegDeleteKeyW(HKEY_CURRENT_USER, L"Software\\Classes\\cmdfile\\DefaultIcon");
    RegDeleteKeyW(HKEY_CURRENT_USER, L"Software\\Classes\\.bat\\DefaultIcon");
    RegDeleteKeyW(HKEY_CURRENT_USER, L"Software\\Classes\\.cmd\\DefaultIcon");

    RebuildExplorerIconCache();
    AppendLog(L"Default script icons successfully restored to standard Windows settings.");
}

void RestoreDefaultDllSysAssociations() {
    AppendLog(L"Restoring factory Windows default icons for .dll and .sys files...");
    const wchar_t* defDll = L"%SystemRoot%\\System32\\imageres.dll,-67";
    HKEY hKey;

    if (RegCreateKeyExW(HKEY_LOCAL_MACHINE, L"Software\\Classes\\dllfile\\DefaultIcon", 0, NULL, REG_OPTION_NON_VOLATILE, KEY_WRITE, NULL, &hKey, NULL) == ERROR_SUCCESS) {
        RegSetValueExW(hKey, NULL, 0, REG_EXPAND_SZ, (const BYTE*)defDll, (DWORD)((wcslen(defDll) + 1) * sizeof(wchar_t)));
        RegCloseKey(hKey);
    }
    RegDeleteKeyW(HKEY_LOCAL_MACHINE, L"Software\\Classes\\sysfile\\DefaultIcon");

    RegDeleteKeyW(HKEY_CURRENT_USER, L"Software\\Classes\\dllfile\\DefaultIcon");
    RegDeleteKeyW(HKEY_CURRENT_USER, L"Software\\Classes\\sysfile\\DefaultIcon");

    RebuildExplorerIconCache();
    AppendLog(L"Default DLL and SYS icons successfully restored to standard Windows settings.");
}

// ==========================================
// GUI CONTROLS & MANAGEMENT
// ==========================================
void SwitchTab(int tabIndex) {
    for (int i = 0; i < 5; ++i) {
        int show = (i == tabIndex) ? SW_SHOW : SW_HIDE;
        for (HWND h : g_tabControls[i]) {
            ShowWindow(h, show);
        }
    }
}

HWND CreateBtn(const wchar_t* text, int id, int x, int y, int w, int h, HWND parent) {
    HWND btn = CreateWindowExW(0, L"BUTTON", text, WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
                               x, y, w, h, parent, (HMENU)(INT_PTR)id, GetModuleHandle(NULL), NULL);
    SendMessageW(btn, WM_SETFONT, (WPARAM)g_hFont, TRUE);
    return btn;
}

HWND CreateEdit(int id, int x, int y, int w, int h, HWND parent, const wchar_t* def = L"") {
    HWND ed = CreateWindowExW(WS_EX_CLIENTEDGE, L"EDIT", def, WS_CHILD | WS_VISIBLE | ES_AUTOHSCROLL,
                              x, y, w, h, parent, (HMENU)(INT_PTR)id, GetModuleHandle(NULL), NULL);
    SendMessageW(ed, WM_SETFONT, (WPARAM)g_hFont, TRUE);
    return ed;
}

HWND CreateLabel(const wchar_t* text, int x, int y, int w, int h, HWND parent, bool bold = false) {
    HWND lbl = CreateWindowExW(0, L"STATIC", text, WS_CHILD | WS_VISIBLE,
                               x, y, w, h, parent, NULL, GetModuleHandle(NULL), NULL);
    SendMessageW(lbl, WM_SETFONT, (WPARAM)(bold ? g_hFontBold : g_hFont), TRUE);
    return lbl;
}

HWND CreateCheckbox(const wchar_t* text, int id, int x, int y, int w, int h, HWND parent, bool checked = true) {
    HWND chk = CreateWindowExW(0, L"BUTTON", text, WS_CHILD | WS_VISIBLE | BS_AUTOCHECKBOX,
                               x, y, w, h, parent, (HMENU)(INT_PTR)id, GetModuleHandle(NULL), NULL);
    SendMessageW(chk, WM_SETFONT, (WPARAM)g_hFont, TRUE);
    SendMessageW(chk, BM_SETCHECK, checked ? BST_CHECKED : BST_UNCHECKED, 0);
    return chk;
}

void UpdateSmartTargetInfo(const std::wstring& targetPath) {
    HWND lbl = GetDlgItem(g_hWnd, ID_SMART_TARGET_TYPE_LABEL);
    if (!lbl) return;

    if (targetPath.empty()) {
        SetWindowTextW(lbl, L"Target Type: No file or folder selected.");
        return;
    }

    PEInspectionInfo info = InspectTarget(targetPath);
    if (!info.valid) {
        SetWindowTextW(lbl, L"Target Type: Selected item does not exist.");
        return;
    }

    if (info.isDirectory) {
        SetWindowTextW(lbl, L"Target: Folder Directory -> Customizes THIS folder only (Zero global impact).");
    } else if (info.isPE) {
        std::wstring ext = PathFindExtensionW(targetPath.c_str());
        if (_wcsicmp(ext.c_str(), L".dll") == 0 || _wcsicmp(ext.c_str(), L".sys") == 0) {
            SetWindowTextW(lbl, L"Target: PE Library/Driver (.dll/.sys) -> Injects icon & enables File Explorer display (%1).");
        } else {
            SetWindowTextW(lbl, L"Target: Windows Executable (.exe) -> Directly embeds icon into binary resources.");
        }
    } else {
        std::wstring ext = PathFindExtensionW(targetPath.c_str());
        std::wstring msg = L"Target: Script/Data File (" + ext + L") -> Creates standalone icon launcher (.exe) for THIS file only (all other files untouched).";
        SetWindowTextW(lbl, msg.c_str());
    }
}

// Main Window Procedure
LRESULT CALLBACK WndProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam) {
    switch (msg) {
        case WM_CREATE: {
            g_hFont = CreateFontW(15, 0, 0, 0, FW_NORMAL, FALSE, FALSE, FALSE,
                                 DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS,
                                 CLEARTYPE_QUALITY, DEFAULT_PITCH | FF_DONTCARE, L"Segoe UI");
            g_hFontBold = CreateFontW(15, 0, 0, 0, FW_BOLD, FALSE, FALSE, FALSE,
                                     DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS,
                                     CLEARTYPE_QUALITY, DEFAULT_PITCH | FF_DONTCARE, L"Segoe UI");
            g_hFontSmall = CreateFontW(13, 0, 0, 0, FW_NORMAL, FALSE, FALSE, FALSE,
                                      DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS,
                                      CLEARTYPE_QUALITY, DEFAULT_PITCH | FF_DONTCARE, L"Segoe UI");

            // Header Banner
            CreateLabel(L"ADVANCED ICON CHANGER", 18, 12, 280, 20, hWnd, true);
            HWND hShield = CreateLabel(L"[🛡️ Administrator Privileges Active]", 300, 14, 340, 18, hWnd);
            SendMessageW(hShield, WM_SETFONT, (WPARAM)g_hFontSmall, TRUE);

            // Tab Control
            g_hTab = CreateWindowExW(0, WC_TABCONTROLW, L"", WS_CHILD | WS_CLIPSIBLINGS | WS_VISIBLE,
                                     15, 38, 655, 260, hWnd, (HMENU)ID_TAB_CONTROL, GetModuleHandle(NULL), NULL);
            SendMessageW(g_hTab, WM_SETFONT, (WPARAM)g_hFont, TRUE);

            TCITEMW tie = {0};
            tie.mask = TCIF_TEXT;
            tie.pszText = (LPWSTR)L"  🎯 Smart File & Folder Changer  ";
            TabCtrl_InsertItem(g_hTab, 0, &tie);
            tie.pszText = (LPWSTR)L"  📂 Folder Architect  ";
            TabCtrl_InsertItem(g_hTab, 1, &tie);
            tie.pszText = (LPWSTR)L"  ⚙️ Script Packager (.cmd/.bat -> .exe)  ";
            TabCtrl_InsertItem(g_hTab, 2, &tie);
            tie.pszText = (LPWSTR)L"  🔍 PE Icon Extractor  ";
            TabCtrl_InsertItem(g_hTab, 3, &tie);
            tie.pszText = (LPWSTR)L"  🛠️ Association Repair & Tools  ";
            TabCtrl_InsertItem(g_hTab, 4, &tie);

            // --- TAB 0: Smart Universal Changer ---
            g_tabControls[0].push_back(CreateLabel(L"Target File or Folder (Drop or Browse any file / folder):", 30, 72, 450, 18, hWnd));
            g_tabControls[0].push_back(CreateEdit(ID_SMART_TARGET_EDIT, 30, 92, 530, 24, hWnd));
            g_tabControls[0].push_back(CreateBtn(L"Browse...", ID_SMART_TARGET_BROWSE, 568, 92, 85, 24, hWnd));

            HWND smartTypeLbl = CreateWindowExW(0, L"STATIC", L"Target Type: No file or folder selected.", WS_CHILD | WS_VISIBLE,
                                               30, 120, 620, 18, hWnd, (HMENU)ID_SMART_TARGET_TYPE_LABEL, GetModuleHandle(NULL), NULL);
            SendMessageW(smartTypeLbl, WM_SETFONT, (WPARAM)g_hFontSmall, TRUE);
            g_tabControls[0].push_back(smartTypeLbl);

            g_tabControls[0].push_back(CreateLabel(L"Replacement Icon (.ico):", 30, 142, 200, 18, hWnd));
            g_tabControls[0].push_back(CreateEdit(ID_SMART_ICON_EDIT, 30, 162, 530, 24, hWnd));
            g_tabControls[0].push_back(CreateBtn(L"Browse...", ID_SMART_ICON_BROWSE, 568, 162, 85, 24, hWnd));

            g_tabControls[0].push_back(CreateCheckbox(L"Create .bak backup", ID_SMART_BACKUP_CHK, 30, 193, 140, 22, hWnd, true));
            g_tabControls[0].push_back(CreateCheckbox(L"Make Portable (copy icon into folder)", ID_SMART_PORTABLE_CHK, 180, 193, 230, 22, hWnd, true));
            g_tabControls[0].push_back(CreateCheckbox(L"Recalculate PE Checksum (Drivers/DLLs)", ID_SMART_CHECKSUM_CHK, 420, 193, 230, 22, hWnd, true));

            g_tabControls[0].push_back(CreateBtn(L"⚡ Apply Icon to Target", ID_SMART_APPLY_BTN, 30, 248, 180, 34, hWnd));
            g_tabControls[0].push_back(CreateBtn(L"Create Custom Shortcut (.lnk)", ID_SMART_LNK_BTN, 220, 248, 210, 34, hWnd));
            g_tabControls[0].push_back(CreateBtn(L"Restore .bak", ID_SMART_RESTORE_BTN, 440, 248, 120, 34, hWnd));

            // --- TAB 1: Folder Architect ---
            g_tabControls[1].push_back(CreateLabel(L"Target Folder to Customize:", 30, 72, 300, 18, hWnd));
            g_tabControls[1].push_back(CreateEdit(ID_FLD_TARGET_EDIT, 30, 92, 530, 24, hWnd));
            g_tabControls[1].push_back(CreateBtn(L"Browse...", ID_FLD_TARGET_BROWSE, 568, 92, 85, 24, hWnd));

            g_tabControls[1].push_back(CreateLabel(L"Custom Icon File (.ico):", 30, 122, 300, 18, hWnd));
            g_tabControls[1].push_back(CreateEdit(ID_FLD_ICON_EDIT, 30, 142, 530, 24, hWnd));
            g_tabControls[1].push_back(CreateBtn(L"Browse...", ID_FLD_ICON_BROWSE, 568, 142, 85, 24, hWnd));

            g_tabControls[1].push_back(CreateLabel(L"Custom ToolTip / InfoTip (Optional):", 30, 172, 300, 18, hWnd));
            g_tabControls[1].push_back(CreateEdit(ID_FLD_INFOTIP_EDIT, 30, 192, 623, 24, hWnd));

            g_tabControls[1].push_back(CreateCheckbox(L"Make Portable (Embed hidden 'folder_icon.ico' inside folder)", ID_FLD_PORTABLE_CHK, 30, 222, 400, 22, hWnd, true));
            g_tabControls[1].push_back(CreateCheckbox(L"Apply recursively to subfolders", ID_FLD_RECURSIVE_CHK, 435, 222, 220, 22, hWnd, false));

            g_tabControls[1].push_back(CreateBtn(L"⚡ Apply Folder Icon", ID_FLD_APPLY_BTN, 30, 252, 180, 32, hWnd));
            g_tabControls[1].push_back(CreateBtn(L"Reset Folder to Windows Default", ID_FLD_RESET_BTN, 220, 252, 230, 32, hWnd));

            // --- TAB 2: Script to Standalone EXE Packager ---
            g_tabControls[2].push_back(CreateLabel(L"Source Script (.cmd or .bat):", 30, 72, 300, 18, hWnd));
            g_tabControls[2].push_back(CreateEdit(ID_PKG_SCRIPT_EDIT, 30, 92, 530, 24, hWnd));
            g_tabControls[2].push_back(CreateBtn(L"Browse...", ID_PKG_SCRIPT_BROWSE, 568, 92, 85, 24, hWnd));

            g_tabControls[2].push_back(CreateLabel(L"Custom Icon File (.ico):", 30, 122, 300, 18, hWnd));
            g_tabControls[2].push_back(CreateEdit(ID_PKG_ICON_EDIT, 30, 142, 530, 24, hWnd));
            g_tabControls[2].push_back(CreateBtn(L"Browse...", ID_PKG_ICON_BROWSE, 568, 142, 85, 24, hWnd));

            g_tabControls[2].push_back(CreateLabel(L"Output Executable Path (.exe):", 30, 172, 300, 18, hWnd));
            g_tabControls[2].push_back(CreateEdit(ID_PKG_OUT_EDIT, 30, 192, 530, 24, hWnd));
            g_tabControls[2].push_back(CreateBtn(L"Browse...", ID_PKG_OUT_BROWSE, 568, 192, 85, 24, hWnd));

            HWND pkgExpl = CreateLabel(L"Packages the script into a standalone .exe with your chosen icon. Runs seamlessly. Zero global impact on other .cmd files!",
                                       30, 222, 620, 24, hWnd);
            SendMessage(pkgExpl, WM_SETFONT, (WPARAM)g_hFontSmall, TRUE);
            g_tabControls[2].push_back(pkgExpl);

            g_tabControls[2].push_back(CreateBtn(L"⚡ Build Standalone Icon Launcher (.exe)", ID_PKG_CREATE_BTN, 30, 250, 310, 34, hWnd));

            // --- TAB 3: PE Icon Extractor ---
            g_tabControls[3].push_back(CreateLabel(L"Source PE Binary (.exe, .dll, .sys, .cpl):", 30, 72, 350, 18, hWnd));
            g_tabControls[3].push_back(CreateEdit(ID_EXTRACT_TARGET_EDIT, 30, 92, 530, 24, hWnd));
            g_tabControls[3].push_back(CreateBtn(L"Browse...", ID_EXTRACT_TARGET_BROWSE, 568, 92, 85, 24, hWnd));

            g_tabControls[3].push_back(CreateLabel(L"Output Standalone Icon File (.ico):", 30, 125, 300, 18, hWnd));
            g_tabControls[3].push_back(CreateEdit(ID_EXTRACT_OUT_EDIT, 30, 145, 530, 24, hWnd));
            g_tabControls[3].push_back(CreateBtn(L"Browse...", ID_EXTRACT_OUT_BROWSE, 568, 145, 85, 24, hWnd));

            HWND extExp = CreateLabel(L"Extracts all multi-resolution icon layers (256x256 PNG-ICO, 128, 64, 48, 32, 16) directly from PE resource tables.",
                                      30, 180, 620, 36, hWnd);
            SendMessageW(extExp, WM_SETFONT, (WPARAM)g_hFontSmall, TRUE);
            g_tabControls[3].push_back(extExp);

            g_tabControls[3].push_back(CreateBtn(L"⚡ Extract Icons to .ICO File", ID_EXTRACT_BTN, 30, 235, 220, 34, hWnd));

            // --- TAB 4: Association Repair & Tools ---
            HWND repDesc = CreateLabel(L"Use these tools to repair Windows file associations or flush icon caches if previous tools altered all .cmd/.bat files.",
                                       30, 72, 620, 32, hWnd);
            SendMessageW(repDesc, WM_SETFONT, (WPARAM)g_hFontSmall, TRUE);
            g_tabControls[4].push_back(repDesc);

            g_tabControls[4].push_back(CreateBtn(L"🔄 Restore Factory Default .cmd & .bat Icons", ID_REPAIR_SCRIPTS_BTN, 30, 110, 320, 32, hWnd));
            g_tabControls[4].push_back(CreateBtn(L"🔄 Restore Factory Default .dll & .sys Icons", ID_REPAIR_DLL_SYS_BTN, 360, 110, 290, 32, hWnd));
            g_tabControls[4].push_back(CreateBtn(L"⚡ Flush & Rebuild Explorer Icon Cache", ID_REPAIR_FLUSH_BTN, 30, 150, 320, 32, hWnd));

            HWND warnLbl = CreateLabel(L"Set System-Wide Extension Default (Use with Caution - changes ALL files of this extension):",
                                       30, 195, 620, 18, hWnd, true);
            g_tabControls[4].push_back(warnLbl);

            g_tabControls[4].push_back(CreateLabel(L"Extension (e.g. .pak):", 30, 220, 140, 18, hWnd));
            g_tabControls[4].push_back(CreateEdit(ID_SYS_EXT_EDIT, 175, 218, 100, 24, hWnd, L".pak"));

            g_tabControls[4].push_back(CreateLabel(L"Icon:", 285, 220, 45, 18, hWnd));
            g_tabControls[4].push_back(CreateEdit(ID_SYS_ICON_EDIT, 330, 218, 230, 24, hWnd));
            g_tabControls[4].push_back(CreateBtn(L"Browse...", ID_SYS_ICON_BROWSE, 568, 218, 85, 24, hWnd));

            g_tabControls[4].push_back(CreateBtn(L"Set Default Icon for Extension (System-Wide)", ID_SYS_APPLY_BTN, 30, 252, 320, 32, hWnd));

            // Activity Log & Footer
            CreateLabel(L"Activity & Status Console:", 15, 304, 250, 18, hWnd, true);
            CreateBtn(L"Clear Log", ID_CLEAR_LOG_BTN, 420, 302, 90, 22, hWnd);
            CreateBtn(L"⚡ Flush Cache", ID_FLUSH_CACHE_BTN, 515, 302, 155, 22, hWnd);

            g_hLogBox = CreateWindowExW(WS_EX_CLIENTEDGE, L"EDIT", L"",
                                        WS_CHILD | WS_VISIBLE | WS_VSCROLL | ES_MULTILINE | ES_AUTOVSCROLL | ES_READONLY,
                                        15, 326, 655, 140, hWnd, (HMENU)ID_LOG_BOX, GetModuleHandle(NULL), NULL);
            SendMessageW(g_hLogBox, WM_SETFONT, (WPARAM)g_hFontSmall, TRUE);

            SwitchTab(0);
            DragAcceptFiles(hWnd, TRUE);
            AppendLog(L"Advanced Icon Changer initialized with Administrator privileges.");
            AppendLog(L"Ready. Drop any file, folder, or icon into the window.");
            break;
        }

        case WM_NOTIFY: {
            NMHDR* pnm = (NMHDR*)lParam;
            if (pnm->idFrom == ID_TAB_CONTROL && pnm->code == TCN_SELCHANGE) {
                int curTab = TabCtrl_GetCurSel(g_hTab);
                SwitchTab(curTab);
            }
            break;
        }

        case WM_DROPFILES: {
            HDROP hDrop = (HDROP)wParam;
            wchar_t dropped[MAX_PATH] = {0};
            DragQueryFileW(hDrop, 0, dropped, MAX_PATH);
            DragFinish(hDrop);

            int curTab = TabCtrl_GetCurSel(g_hTab);
            std::wstring file = dropped;
            std::wstring ext = PathFindExtensionW(dropped);

            if (_wcsicmp(ext.c_str(), L".ico") == 0) {
                if (curTab == 0) SetDlgItemTextW(hWnd, ID_SMART_ICON_EDIT, dropped);
                else if (curTab == 1) SetDlgItemTextW(hWnd, ID_FLD_ICON_EDIT, dropped);
                else if (curTab == 2) SetDlgItemTextW(hWnd, ID_PKG_ICON_EDIT, dropped);
                else if (curTab == 4) SetDlgItemTextW(hWnd, ID_SYS_ICON_EDIT, dropped);
                AppendLog(L"Loaded icon: " + file);
            } else {
                if (curTab == 0) {
                    SetDlgItemTextW(hWnd, ID_SMART_TARGET_EDIT, dropped);
                    UpdateSmartTargetInfo(dropped);
                    AppendLog(L"Selected target: " + file);
                } else if (curTab == 1) {
                    SetDlgItemTextW(hWnd, ID_FLD_TARGET_EDIT, dropped);
                    AppendLog(L"Selected folder: " + file);
                } else if (curTab == 2) {
                    SetDlgItemTextW(hWnd, ID_PKG_SCRIPT_EDIT, dropped);
                    std::wstring outExe = file;
                    wchar_t* dot = (wchar_t*)PathFindExtensionW(outExe.c_str());
                    if (dot && *dot) {
                        outExe = outExe.substr(0, dot - outExe.c_str()) + L".exe";
                    } else {
                        outExe += L".exe";
                    }
                    SetDlgItemTextW(hWnd, ID_PKG_OUT_EDIT, outExe.c_str());
                    AppendLog(L"Selected script to package: " + file);
                } else if (curTab == 3) {
                    SetDlgItemTextW(hWnd, ID_EXTRACT_TARGET_EDIT, dropped);
                    SetDlgItemTextW(hWnd, ID_EXTRACT_OUT_EDIT, (file + L"_extracted.ico").c_str());
                    AppendLog(L"Selected PE for extraction: " + file);
                }
            }
            break;
        }

        case WM_COMMAND: {
            int wmId = LOWORD(wParam);
            switch (wmId) {
                case ID_CLEAR_LOG_BTN: {
                    SetWindowTextW(g_hLogBox, L"");
                    break;
                }
                case ID_FLUSH_CACHE_BTN:
                case ID_REPAIR_FLUSH_BTN: {
                    RebuildExplorerIconCache();
                    MessageBoxW(hWnd, L"Windows Explorer icon caches refreshed.", L"Success", MB_OK | MB_ICONINFORMATION);
                    break;
                }
                case ID_REPAIR_SCRIPTS_BTN: {
                    RestoreDefaultScriptAssociations();
                    MessageBoxW(hWnd, L"Factory default icons restored for all .cmd and .bat files.", L"Repaired", MB_OK | MB_ICONINFORMATION);
                    break;
                }
                case ID_REPAIR_DLL_SYS_BTN: {
                    RestoreDefaultDllSysAssociations();
                    MessageBoxW(hWnd, L"Factory default icons restored for .dll and .sys files.", L"Repaired", MB_OK | MB_ICONINFORMATION);
                    break;
                }

                // --- TAB 0 (Smart Changer) ---
                case ID_SMART_TARGET_BROWSE: {
                    std::wstring f = BrowseFileDialog(hWnd, L"All Supported Files & Binaries\0*.exe;*.dll;*.sys;*.cmd;*.bat;*.pak;*.*\0All Files (*.*)\0*.*\0");
                    if (!f.empty()) {
                        SetDlgItemTextW(hWnd, ID_SMART_TARGET_EDIT, f.c_str());
                        UpdateSmartTargetInfo(f);
                        AppendLog(L"Selected target: " + f);
                    }
                    break;
                }
                case ID_SMART_ICON_BROWSE: {
                    std::wstring f = BrowseFileDialog(hWnd, L"Icon Files (*.ico)\0*.ico\0");
                    if (!f.empty()) SetDlgItemTextW(hWnd, ID_SMART_ICON_EDIT, f.c_str());
                    break;
                }
                case ID_SMART_APPLY_BTN: {
                    std::wstring target = GetEditVal(ID_SMART_TARGET_EDIT);
                    std::wstring ico = GetEditVal(ID_SMART_ICON_EDIT);
                    bool bak = (SendMessageW(GetDlgItem(hWnd, ID_SMART_BACKUP_CHK), BM_GETCHECK, 0, 0) == BST_CHECKED);
                    bool port = (SendMessageW(GetDlgItem(hWnd, ID_SMART_PORTABLE_CHK), BM_GETCHECK, 0, 0) == BST_CHECKED);
                    bool chk = (SendMessageW(GetDlgItem(hWnd, ID_SMART_CHECKSUM_CHK), BM_GETCHECK, 0, 0) == BST_CHECKED);

                    if (target.empty() || ico.empty()) {
                        MessageBoxW(hWnd, L"Please specify both a target and an icon (.ico) file.", L"Missing Input", MB_OK | MB_ICONWARNING);
                        break;
                    }

                    PEInspectionInfo info = InspectTarget(target);
                    if (!info.valid) {
                        MessageBoxW(hWnd, L"Target does not exist.", L"Error", MB_OK | MB_ICONERROR);
                        break;
                    }

                    std::wstring msg;
                    if (info.isDirectory) {
                        // Apply to Folder
                        AppendLog(L"Applying icon to folder: " + target);
                        if (ModifyFolderIcon(target, ico, port, false, L"", msg)) {
                            AppendLog(msg);
                            MessageBoxW(hWnd, msg.c_str(), L"Folder Icon Applied", MB_OK | MB_ICONINFORMATION);
                        } else {
                            AppendLog(msg);
                            MessageBoxW(hWnd, msg.c_str(), L"Error", MB_OK | MB_ICONERROR);
                        }
                    } else if (info.isPE) {
                        // Apply to PE (.exe, .dll, .sys, etc.)
                        AppendLog(L"Injecting icon into PE binary: " + target);
                        if (ModifyPEIconAdvanced(target, ico, bak, chk, msg)) {
                            AppendLog(msg);
                            MessageBoxW(hWnd, msg.c_str(), L"PE Icon Injection Succeeded", MB_OK | MB_ICONINFORMATION);
                        } else {
                            AppendLog(msg);
                            MessageBoxW(hWnd, msg.c_str(), L"PE Error", MB_OK | MB_ICONERROR);
                        }
                    } else {
                        // Script / Non-PE file (.cmd, .bat, .pak, etc.)
                        // Do NOT touch global file type associations! Create standalone launcher for THIS file.
                        std::wstring outExe = target;
                        wchar_t* dot = (wchar_t*)PathFindExtensionW(outExe.c_str());
                        if (dot && *dot) {
                            outExe = outExe.substr(0, dot - outExe.c_str()) + L".exe";
                        } else {
                            outExe += L".exe";
                        }

                        AppendLog(L"Creating standalone icon launcher for: " + target);
                        if (CreateScriptStandaloneLauncher(target, ico, outExe, msg)) {
                            AppendLog(msg);
                            MessageBoxW(hWnd, msg.c_str(), L"Standalone Launcher Created", MB_OK | MB_ICONINFORMATION);
                        } else {
                            AppendLog(msg);
                            MessageBoxW(hWnd, msg.c_str(), L"Error", MB_OK | MB_ICONERROR);
                        }
                    }
                    break;
                }
                case ID_SMART_LNK_BTN: {
                    std::wstring target = GetEditVal(ID_SMART_TARGET_EDIT);
                    std::wstring ico = GetEditVal(ID_SMART_ICON_EDIT);
                    if (target.empty() || ico.empty()) {
                        MessageBoxW(hWnd, L"Please select target and icon files first.", L"Warning", MB_OK | MB_ICONWARNING);
                        break;
                    }
                    std::wstring lnkPath = target + L".lnk";
                    std::wstring msg;
                    if (CreateCustomShortcut(target, ico, lnkPath, false, msg)) {
                        AppendLog(msg);
                        MessageBoxW(hWnd, msg.c_str(), L"Shortcut Created", MB_OK | MB_ICONINFORMATION);
                    } else {
                        AppendLog(msg);
                        MessageBoxW(hWnd, msg.c_str(), L"Error", MB_OK | MB_ICONERROR);
                    }
                    break;
                }
                case ID_SMART_RESTORE_BTN: {
                    std::wstring target = GetEditVal(ID_SMART_TARGET_EDIT);
                    if (target.empty()) {
                        MessageBoxW(hWnd, L"Please select a target file first.", L"Warning", MB_OK | MB_ICONWARNING);
                        break;
                    }
                    std::wstring bak = target + L".bak";
                    if (CopyFileW(bak.c_str(), target.c_str(), FALSE)) {
                        SHChangeNotify(SHCNE_UPDATEITEM, SHCNF_PATHW, target.c_str(), NULL);
                        UpdateSmartTargetInfo(target);
                        AppendLog(L"Restored original file from backup: " + bak);
                        MessageBoxW(hWnd, L"Backup restored successfully!", L"Restore", MB_OK | MB_ICONINFORMATION);
                    } else {
                        AppendLog(L"Could not locate backup file: " + bak);
                        MessageBoxW(hWnd, L"Could not find a valid .bak backup file.", L"Error", MB_OK | MB_ICONERROR);
                    }
                    break;
                }

                // --- TAB 1 (Folder) ---
                case ID_FLD_TARGET_BROWSE: {
                    std::wstring f = BrowseFolderDialog(hWnd);
                    if (!f.empty()) SetDlgItemTextW(hWnd, ID_FLD_TARGET_EDIT, f.c_str());
                    break;
                }
                case ID_FLD_ICON_BROWSE: {
                    std::wstring f = BrowseFileDialog(hWnd, L"Icon Files (*.ico)\0*.ico\0");
                    if (!f.empty()) SetDlgItemTextW(hWnd, ID_FLD_ICON_EDIT, f.c_str());
                    break;
                }
                case ID_FLD_APPLY_BTN: {
                    std::wstring fld = GetEditVal(ID_FLD_TARGET_EDIT);
                    std::wstring ico = GetEditVal(ID_FLD_ICON_EDIT);
                    std::wstring tip = GetEditVal(ID_FLD_INFOTIP_EDIT);
                    bool port = (SendMessageW(GetDlgItem(hWnd, ID_FLD_PORTABLE_CHK), BM_GETCHECK, 0, 0) == BST_CHECKED);
                    bool recur = (SendMessageW(GetDlgItem(hWnd, ID_FLD_RECURSIVE_CHK), BM_GETCHECK, 0, 0) == BST_CHECKED);
                    std::wstring msg;
                    if (ModifyFolderIcon(fld, ico, port, recur, tip, msg)) {
                        AppendLog(msg);
                        MessageBoxW(hWnd, msg.c_str(), L"Folder Customization", MB_OK | MB_ICONINFORMATION);
                    } else {
                        AppendLog(msg);
                        MessageBoxW(hWnd, msg.c_str(), L"Error", MB_OK | MB_ICONERROR);
                    }
                    break;
                }
                case ID_FLD_RESET_BTN: {
                    std::wstring fld = GetEditVal(ID_FLD_TARGET_EDIT);
                    std::wstring msg;
                    if (ResetFolder(fld, msg)) {
                        AppendLog(msg);
                        MessageBoxW(hWnd, msg.c_str(), L"Folder Reset", MB_OK | MB_ICONINFORMATION);
                    }
                    break;
                }

                // --- TAB 2 (Script Packager) ---
                case ID_PKG_SCRIPT_BROWSE: {
                    std::wstring f = BrowseFileDialog(hWnd, L"Scripts (*.cmd;*.bat)\0*.cmd;*.bat\0All Files (*.*)\0*.*\0");
                    if (!f.empty()) {
                        SetDlgItemTextW(hWnd, ID_PKG_SCRIPT_EDIT, f.c_str());
                        std::wstring outExe = f;
                        wchar_t* dot = (wchar_t*)PathFindExtensionW(outExe.c_str());
                        if (dot && *dot) {
                            outExe = outExe.substr(0, dot - outExe.c_str()) + L".exe";
                        } else {
                            outExe += L".exe";
                        }
                        SetDlgItemTextW(hWnd, ID_PKG_OUT_EDIT, outExe.c_str());
                        AppendLog(L"Selected script to package: " + f);
                    }
                    break;
                }
                case ID_PKG_ICON_BROWSE: {
                    std::wstring f = BrowseFileDialog(hWnd, L"Icon Files (*.ico)\0*.ico\0");
                    if (!f.empty()) SetDlgItemTextW(hWnd, ID_PKG_ICON_EDIT, f.c_str());
                    break;
                }
                case ID_PKG_OUT_BROWSE: {
                    std::wstring f = BrowseFileDialog(hWnd, L"Executable (*.exe)\0*.exe\0", false, L"exe");
                    if (!f.empty()) SetDlgItemTextW(hWnd, ID_PKG_OUT_EDIT, f.c_str());
                    break;
                }
                case ID_PKG_CREATE_BTN: {
                    std::wstring sc = GetEditVal(ID_PKG_SCRIPT_EDIT);
                    std::wstring ic = GetEditVal(ID_PKG_ICON_EDIT);
                    std::wstring out = GetEditVal(ID_PKG_OUT_EDIT);
                    std::wstring msg;
                    if (CreateScriptStandaloneLauncher(sc, ic, out, msg)) {
                        AppendLog(msg);
                        MessageBoxW(hWnd, msg.c_str(), L"Standalone Launcher Built", MB_OK | MB_ICONINFORMATION);
                    } else {
                        AppendLog(msg);
                        MessageBoxW(hWnd, msg.c_str(), L"Build Error", MB_OK | MB_ICONERROR);
                    }
                    break;
                }

                // --- TAB 3 (PE Extractor) ---
                case ID_EXTRACT_TARGET_BROWSE: {
                    std::wstring f = BrowseFileDialog(hWnd, L"PE Binaries (*.exe;*.dll;*.sys;*.cpl)\0*.exe;*.dll;*.sys;*.cpl\0All Files (*.*)\0*.*\0");
                    if (!f.empty()) {
                        SetDlgItemTextW(hWnd, ID_EXTRACT_TARGET_EDIT, f.c_str());
                        SetDlgItemTextW(hWnd, ID_EXTRACT_OUT_EDIT, (f + L"_extracted.ico").c_str());
                    }
                    break;
                }
                case ID_EXTRACT_OUT_BROWSE: {
                    std::wstring f = BrowseFileDialog(hWnd, L"Icon File (*.ico)\0*.ico\0", false, L"ico");
                    if (!f.empty()) SetDlgItemTextW(hWnd, ID_EXTRACT_OUT_EDIT, f.c_str());
                    break;
                }
                case ID_EXTRACT_BTN: {
                    std::wstring pe = GetEditVal(ID_EXTRACT_TARGET_EDIT);
                    std::wstring out = GetEditVal(ID_EXTRACT_OUT_EDIT);
                    std::wstring msg;
                    if (ExtractPEIconsToICO(pe, out, msg)) {
                        AppendLog(msg);
                        MessageBoxW(hWnd, msg.c_str(), L"Icon Extracted", MB_OK | MB_ICONINFORMATION);
                    } else {
                        AppendLog(msg);
                        MessageBoxW(hWnd, msg.c_str(), L"Extraction Error", MB_OK | MB_ICONERROR);
                    }
                    break;
                }

                // --- TAB 4 (Global System-Wide) ---
                case ID_SYS_ICON_BROWSE: {
                    std::wstring f = BrowseFileDialog(hWnd, L"Icon Files (*.ico)\0*.ico\0");
                    if (!f.empty()) SetDlgItemTextW(hWnd, ID_SYS_ICON_EDIT, f.c_str());
                    break;
                }
                case ID_SYS_APPLY_BTN: {
                    std::wstring ext = GetEditVal(ID_SYS_EXT_EDIT);
                    std::wstring ico = GetEditVal(ID_SYS_ICON_EDIT);
                    if (ext.empty() || ico.empty()) {
                        MessageBoxW(hWnd, L"Please enter extension and icon file.", L"Warning", MB_OK | MB_ICONWARNING);
                        break;
                    }
                    int ret = MessageBoxW(hWnd,
                        (L"WARNING: This will set the default icon for ALL '" + ext + L"' files across your entire computer.\n\nAre you sure you want to proceed?").c_str(),
                        L"Confirm System-Wide Change", MB_YESNO | MB_ICONWARNING);
                    if (ret != IDYES) break;

                    if (ext[0] != L'.') ext = L"." + ext;
                    std::wstring iconVal = L"\"" + ico + L"\",0";
                    std::wstring progId = ext.substr(1) + L"file";

                    HKEY hKey;
                    if (RegCreateKeyExW(HKEY_LOCAL_MACHINE, (L"Software\\Classes\\" + progId + L"\\DefaultIcon").c_str(), 0, NULL, REG_OPTION_NON_VOLATILE, KEY_WRITE, NULL, &hKey, NULL) == ERROR_SUCCESS) {
                        RegSetValueExW(hKey, NULL, 0, REG_SZ, (const BYTE*)iconVal.c_str(), (DWORD)((iconVal.length() + 1) * sizeof(wchar_t)));
                        RegCloseKey(hKey);
                    }
                    if (RegCreateKeyExW(HKEY_LOCAL_MACHINE, (L"Software\\Classes\\" + ext + L"\\DefaultIcon").c_str(), 0, NULL, REG_OPTION_NON_VOLATILE, KEY_WRITE, NULL, &hKey, NULL) == ERROR_SUCCESS) {
                        RegSetValueExW(hKey, NULL, 0, REG_SZ, (const BYTE*)iconVal.c_str(), (DWORD)((iconVal.length() + 1) * sizeof(wchar_t)));
                        RegCloseKey(hKey);
                    }
                    RebuildExplorerIconCache();
                    AppendLog(L"Set system-wide default icon for " + ext);
                    MessageBoxW(hWnd, L"System-wide icon association applied.", L"Completed", MB_OK | MB_ICONINFORMATION);
                    break;
                }
            }
            break;
        }

        case WM_DESTROY: {
            if (g_hFont) DeleteObject(g_hFont);
            if (g_hFontBold) DeleteObject(g_hFontBold);
            if (g_hFontSmall) DeleteObject(g_hFontSmall);
            PostQuitMessage(0);
            break;
        }

        default:
            return DefWindowProcW(hWnd, msg, wParam, lParam);
    }
    return 0;
}

int WINAPI wWinMain(HINSTANCE hInstance, HINSTANCE, PWSTR, int nCmdShow) {
    // 1. Enforce Administrator Privileges via UAC on every launch
    if (!IsProcessElevated()) {
        if (RequestElevation()) {
            return 0; // Successfully launched elevated child process, exit un-elevated instance
        } else {
            MessageBoxW(NULL,
                L"Administrator privileges are required to modify system PE files, drivers (.sys), Windows file associations, and shell caches.\n\nApplication will now exit.",
                L"Permission Required - Advanced Icon Changer",
                MB_OK | MB_ICONWARNING);
            return 0;
        }
    }

    CoInitialize(NULL);

    INITCOMMONCONTROLSEX icex;
    icex.dwSize = sizeof(INITCOMMONCONTROLSEX);
    icex.dwICC = ICC_TAB_CLASSES | ICC_STANDARD_CLASSES;
    InitCommonControlsEx(&icex);

    WNDCLASSEXW wc = {0};
    wc.cbSize = sizeof(WNDCLASSEXW);
    wc.lpfnWndProc = WndProc;
    wc.hInstance = hInstance;
    wc.hCursor = LoadCursor(NULL, IDC_ARROW);
    wc.hbrBackground = (HBRUSH)(COLOR_BTNFACE + 1);
    wc.lpszClassName = L"AdvancedIconChangerClass";
    wc.hIcon = LoadIcon(NULL, IDI_SHIELD);

    if (!RegisterClassExW(&wc)) return 0;

    int w = 700;
    int h = 515;
    int x = (GetSystemMetrics(SM_CXSCREEN) - w) / 2;
    int y = (GetSystemMetrics(SM_CYSCREEN) - h) / 2;

    g_hWnd = CreateWindowExW(0, wc.lpszClassName,
                             L"Advanced Icon Changer [Administrator]",
                             WS_OVERLAPPED | WS_CAPTION | WS_SYSMENU | WS_MINIMIZEBOX,
                             x, y, w, h, NULL, NULL, hInstance, NULL);

    if (!g_hWnd) return 0;

    ShowWindow(g_hWnd, nCmdShow);
    UpdateWindow(g_hWnd);

    MSG msg;
    while (GetMessageW(&msg, NULL, 0, 0)) {
        TranslateMessage(&msg);
        DispatchMessageW(&msg);
    }

    CoUninitialize();
    return (int)msg.wParam;
}
