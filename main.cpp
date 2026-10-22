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
#include <string>
#include <vector>
#include <fstream>
#include <sstream>

#pragma comment(lib, "comctl32.lib")
#pragma comment(lib, "shell32.lib")
#pragma comment(lib, "ole32.lib")
#pragma comment(lib, "shlwapi.lib")
#pragma comment(lib, "advapi32.lib")

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

// Control IDs
enum {
    ID_TAB_CONTROL = 1000,
    ID_LOG_BOX,
    ID_PREVIEW_OLD,
    ID_PREVIEW_NEW,
    
    // Tab 1: PE Files
    ID_PE_TARGET_EDIT,
    ID_PE_TARGET_BROWSE,
    ID_PE_ICON_EDIT,
    ID_PE_ICON_BROWSE,
    ID_PE_BACKUP_CHK,
    ID_PE_APPLY_BTN,
    ID_PE_RESTORE_BTN,

    // Tab 2: Folder
    ID_FLD_TARGET_EDIT,
    ID_FLD_TARGET_BROWSE,
    ID_FLD_ICON_EDIT,
    ID_FLD_ICON_BROWSE,
    ID_FLD_PORTABLE_CHK,
    ID_FLD_APPLY_BTN,
    ID_FLD_RESET_BTN,

    // Tab 3: File Extension (.pak, .bat, .cmd)
    ID_EXT_TYPE_EDIT,
    ID_EXT_ICON_EDIT,
    ID_EXT_ICON_BROWSE,
    ID_EXT_APPLY_BTN,
    ID_EXT_RESET_BTN,

    // Tab 4: Shortcut Maker
    ID_LNK_TARGET_EDIT,
    ID_LNK_TARGET_BROWSE,
    ID_LNK_ICON_EDIT,
    ID_LNK_ICON_BROWSE,
    ID_LNK_OUT_EDIT,
    ID_LNK_OUT_BROWSE,
    ID_LNK_CREATE_BTN
};

// Global handles
HWND g_hWnd = NULL;
HWND g_hTab = NULL;
HWND g_hLogBox = NULL;
HFONT g_hFont = NULL;
HICON g_hIconTarget = NULL;
HICON g_hIconNew = NULL;

// Sub-controls grouped by tab
std::vector<HWND> g_tabControls[4];

// Utility: Append text to Log Window
void AppendLog(const std::wstring& text) {
    if (!g_hLogBox) return;
    int len = GetWindowTextLengthW(g_hLogBox);
    SendMessageW(g_hLogBox, EM_SETSEL, (WPARAM)len, (LPARAM)len);
    SendMessageW(g_hLogBox, EM_REPLACESEL, FALSE, (LPARAM)(text + L"\r\n").c_str());
    SendMessageW(g_hLogBox, EM_SCROLLCARET, 0, 0);
}

// Utility: File / Folder Browse Dialogs
std::wstring BrowseFileDialog(HWND parent, const wchar_t* filter, bool isOpen = true) {
    wchar_t filename[MAX_PATH] = {0};
    OPENFILENAMEW ofn = {0};
    ofn.lStructSize = sizeof(ofn);
    ofn.hwndOwner = parent;
    ofn.lpstrFilter = filter;
    ofn.lpstrFile = filename;
    ofn.nMaxFile = MAX_PATH;
    ofn.Flags = OFN_EXPLORER | OFN_FILEMUSTEXIST | OFN_HIDEREADONLY;
    if (isOpen ? GetOpenFileNameW(&ofn) : GetSaveFileNameW(&ofn)) {
        return filename;
    }
    return L"";
}

std::wstring BrowseFolderDialog(HWND parent) {
    wchar_t path[MAX_PATH] = {0};
    BROWSEINFOW bi = {0};
    bi.hwndOwner = parent;
    bi.lpszTitle = L"Select Folder to Change Icon:";
    bi.ulFlags = BIF_RETURNONLYFSDIRS | BIF_NEWDIALOGSTYLE;
    PIDLIST_ABSOLUTE pidl = SHBrowseForFolderW(&bi);
    if (pidl) {
        SHGetPathFromIDListW(pidl, path);
        CoTaskMemFree(pidl);
        return path;
    }
    return L"";
}

// Helper: Extract preview icon from file
void UpdatePreviews(const std::wstring& targetPath, const std::wstring& iconPath) {
    if (g_hIconTarget) { DestroyIcon(g_hIconTarget); g_hIconTarget = NULL; }
    if (g_hIconNew) { DestroyIcon(g_hIconNew); g_hIconNew = NULL; }

    if (!targetPath.empty()) {
        SHFILEINFOW sfi = {0};
        if (SHGetFileInfoW(targetPath.c_str(), 0, &sfi, sizeof(sfi), SHGFI_ICON | SHGFI_LARGEICON)) {
            g_hIconTarget = sfi.hIcon;
        }
    }
    if (!iconPath.empty()) {
        g_hIconNew = (HICON)LoadImageW(NULL, iconPath.c_str(), IMAGE_ICON, 48, 48, LR_LOADFROMFILE);
        if (!g_hIconNew) {
            SHFILEINFOW sfi = {0};
            if (SHGetFileInfoW(iconPath.c_str(), 0, &sfi, sizeof(sfi), SHGFI_ICON | SHGFI_LARGEICON)) {
                g_hIconNew = sfi.hIcon;
            }
        }
    }

    InvalidateRect(g_hWnd, NULL, TRUE);
}

// ==========================================
// FEATURE 1: PE Icon Modifier (.exe, .dll, .sys)
// ==========================================
bool ModifyPEIcon(const std::wstring& pePath, const std::wstring& icoPath, bool createBak, std::wstring& outMsg) {
    if (pePath.empty() || icoPath.empty()) {
        outMsg = L"Error: Target PE file or Icon file path is empty.";
        return false;
    }

    std::ifstream icoFile(icoPath.c_str(), std::ios::binary);
    if (!icoFile.is_open()) {
        outMsg = L"Error: Cannot open icon file.";
        return false;
    }

    ICONDIR iconDir{};
    icoFile.read((char*)&iconDir, sizeof(ICONDIR));
    if (!icoFile || iconDir.idReserved != 0 || iconDir.idType != 1 || iconDir.idCount == 0) {
        outMsg = L"Error: Selected file is not a valid .ico file.";
        return false;
    }

    std::vector<ICONDIRENTRY> entries(iconDir.idCount);
    icoFile.read((char*)entries.data(), sizeof(ICONDIRENTRY) * iconDir.idCount);

    std::vector<std::vector<BYTE>> imageBuffers(iconDir.idCount);
    for (size_t i = 0; i < entries.size(); ++i) {
        imageBuffers[i].resize(entries[i].dwBytesInRes);
        icoFile.seekg(entries[i].dwImageOffset, std::ios::beg);
        icoFile.read((char*)imageBuffers[i].data(), entries[i].dwBytesInRes);
    }
    icoFile.close();

    // Create .bak backup
    if (createBak) {
        std::wstring bakPath = pePath + L".bak";
        CopyFileW(pePath.c_str(), bakPath.c_str(), FALSE);
    }

    // Build GRPICONDIR resource structure
    DWORD grpSize = sizeof(GRPICONDIR) + (iconDir.idCount * sizeof(GRPICONDIRENTRY));
    std::vector<BYTE> grpBuffer(grpSize, 0);
    GRPICONDIR* pGrpDir = (GRPICONDIR*)grpBuffer.data();
    pGrpDir->idReserved = iconDir.idReserved;
    pGrpDir->idType = iconDir.idType;
    pGrpDir->idCount = iconDir.idCount;

    GRPICONDIRENTRY* pGrpEntries = (GRPICONDIRENTRY*)(grpBuffer.data() + sizeof(GRPICONDIR));
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

    HANDLE hUpdate = BeginUpdateResourceW(pePath.c_str(), FALSE);
    if (!hUpdate) {
        DWORD err = GetLastError();
        outMsg = L"Error: Cannot modify PE resources (Error " + std::to_wstring(err) + L"). Check file permissions.";
        return false;
    }

    for (WORD i = 0; i < iconDir.idCount; ++i) {
        UpdateResourceW(hUpdate, RT_ICON, MAKEINTRESOURCEW(i + 1),
                        MAKELANGID(LANG_NEUTRAL, SUBLANG_NEUTRAL),
                        imageBuffers[i].data(), (DWORD)imageBuffers[i].size());
    }

    // Target group ID 1 (standard main icon group for Windows PE)
    UpdateResourceW(hUpdate, RT_GROUP_ICON, MAKEINTRESOURCEW(1),
                    MAKELANGID(LANG_NEUTRAL, SUBLANG_NEUTRAL),
                    grpBuffer.data(), grpSize);

    if (!EndUpdateResourceW(hUpdate, FALSE)) {
        outMsg = L"Error: Failed to write PE icon changes. Error: " + std::to_wstring(GetLastError());
        return false;
    }

    SHChangeNotify(SHCNE_UPDATEITEM, SHCNF_PATHW, pePath.c_str(), NULL);
    SHChangeNotify(SHCNE_ASSOCCHANGED, SHCNF_IDLIST, NULL, NULL);

    outMsg = L"Success! Updated PE resource icons (" + std::to_wstring(iconDir.idCount) + L" formats embedded).";
    return true;
}

// ==========================================
// FEATURE 2: Folder Icon Changer
// ==========================================
bool ModifyFolderIcon(const std::wstring& folderPath, const std::wstring& icoPath, bool portable, std::wstring& outMsg) {
    if (folderPath.empty() || icoPath.empty()) {
        outMsg = L"Error: Folder path or icon path is empty.";
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

    std::wofstream ini(iniPath.c_str(), std::ios::trunc);
    if (!ini.is_open()) {
        outMsg = L"Error: Failed to create desktop.ini inside folder.";
        return false;
    }

    ini << L"[.ShellClassInfo]\n";
    ini << L"IconResource=" << effectiveIco << L",0\n";
    ini << L"IconFile=" << effectiveIco << L"\n";
    ini << L"IconIndex=0\n";
    ini << L"[ViewState]\nMode=\nVid=\nFolderType=Generic\n";
    ini.close();

    SetFileAttributesW(iniPath.c_str(), FILE_ATTRIBUTE_HIDDEN | FILE_ATTRIBUTE_SYSTEM);

    // Folder itself MUST have ReadOnly or System attribute for Windows Explorer to process desktop.ini
    DWORD fAttrs = GetFileAttributesW(folder.c_str());
    SetFileAttributesW(folder.c_str(), fAttrs | FILE_ATTRIBUTE_READONLY);

    SHChangeNotify(SHCNE_UPDATEITEM, SHCNF_PATHW, folder.c_str(), NULL);
    SHChangeNotify(SHCNE_ASSOCCHANGED, SHCNF_IDLIST, NULL, NULL);

    outMsg = L"Success! Folder icon set to: " + effectiveIco;
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

    DWORD fAttrs = GetFileAttributesW(folder.c_str());
    if (fAttrs != INVALID_FILE_ATTRIBUTES) {
        SetFileAttributesW(folder.c_str(), fAttrs & ~FILE_ATTRIBUTE_READONLY);
    }

    SHChangeNotify(SHCNE_UPDATEITEM, SHCNF_PATHW, folder.c_str(), NULL);
    SHChangeNotify(SHCNE_ASSOCCHANGED, SHCNF_IDLIST, NULL, NULL);

    outMsg = L"Folder icon reset to default.";
    return true;
}

// ==========================================
// FEATURE 3: File Type Association (.pak, .bat, .cmd)
// ==========================================
bool ModifyExtensionIcon(const std::wstring& rawExt, const std::wstring& icoPath, std::wstring& outMsg) {
    if (rawExt.empty() || icoPath.empty()) {
        outMsg = L"Error: Extension or icon path is empty.";
        return false;
    }
    std::wstring ext = rawExt;
    if (ext[0] != L'.') ext = L"." + ext;

    std::wstring iconVal = L"\"" + icoPath + L"\",0";

    // Write to HKCU\Software\Classes\<ext>\DefaultIcon
    std::wstring keyPath = L"Software\\Classes\\" + ext + L"\\DefaultIcon";
    HKEY hKey;
    if (RegCreateKeyExW(HKEY_CURRENT_USER, keyPath.c_str(), 0, NULL,
                        REG_OPTION_NON_VOLATILE, KEY_WRITE, NULL, &hKey, NULL) == ERROR_SUCCESS) {
        RegSetValueExW(hKey, NULL, 0, REG_SZ, (const BYTE*)iconVal.c_str(),
                       (DWORD)((iconVal.length() + 1) * sizeof(wchar_t)));
        RegCloseKey(hKey);
    } else {
        outMsg = L"Error: Could not write HKCU registry key.";
        return false;
    }

    SHChangeNotify(SHCNE_ASSOCCHANGED, SHCNF_IDLIST, NULL, NULL);
    outMsg = L"Success! Icon associated with " + ext + L" in HKCU\\Software\\Classes.";
    return true;
}

bool ResetExtension(const std::wstring& rawExt, std::wstring& outMsg) {
    std::wstring ext = rawExt;
    if (ext.empty()) return false;
    if (ext[0] != L'.') ext = L"." + ext;

    std::wstring keyPath = L"Software\\Classes\\" + ext + L"\\DefaultIcon";
    RegDeleteKeyW(HKEY_CURRENT_USER, keyPath.c_str());

    SHChangeNotify(SHCNE_ASSOCCHANGED, SHCNF_IDLIST, NULL, NULL);
    outMsg = L"Extension " + ext + L" icon reset to default.";
    return true;
}

// ==========================================
// FEATURE 4: Shortcut (.lnk) Maker
// ==========================================
bool CreateCustomShortcut(const std::wstring& targetPath, const std::wstring& icoPath, const std::wstring& outLnkPath, std::wstring& outMsg) {
    if (targetPath.empty() || icoPath.empty() || outLnkPath.empty()) {
        outMsg = L"Error: Target path, icon path, or output path is empty.";
        return false;
    }

    IShellLinkW* psl = NULL;
    HRESULT hr = CoCreateInstance(CLSID_ShellLink, NULL, CLSCTX_INPROC_SERVER, IID_IShellLinkW, (void**)&psl);
    if (SUCCEEDED(hr)) {
        psl->SetPath(targetPath.c_str());
        psl->SetIconLocation(icoPath.c_str(), 0);

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
        outMsg = L"Shortcut created successfully:\n" + outLnkPath;
        return true;
    } else {
        outMsg = L"Error: Failed to create shortcut file.";
        return false;
    }
}

// Helper: Show/Hide controls based on selected Tab
void SwitchTab(int tabIndex) {
    for (int i = 0; i < 4; ++i) {
        int show = (i == tabIndex) ? SW_SHOW : SW_HIDE;
        for (HWND h : g_tabControls[i]) {
            ShowWindow(h, show);
        }
    }
}

// GUI Creation helper
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

HWND CreateLabel(const wchar_t* text, int x, int y, int w, int h, HWND parent) {
    HWND lbl = CreateWindowExW(0, L"STATIC", text, WS_CHILD | WS_VISIBLE,
                               x, y, w, h, parent, NULL, GetModuleHandle(NULL), NULL);
    SendMessageW(lbl, WM_SETFONT, (WPARAM)g_hFont, TRUE);
    return lbl;
}

HWND CreateCheckbox(const wchar_t* text, int id, int x, int y, int w, int h, HWND parent, bool checked = true) {
    HWND chk = CreateWindowExW(0, L"BUTTON", text, WS_CHILD | WS_VISIBLE | BS_AUTOCHECKBOX,
                               x, y, w, h, parent, (HMENU)(INT_PTR)id, GetModuleHandle(NULL), NULL);
    SendMessageW(chk, WM_SETFONT, (WPARAM)g_hFont, TRUE);
    SendMessageW(chk, BM_SETCHECK, checked ? BST_CHECKED : BST_UNCHECKED, 0);
    return chk;
}

std::wstring GetEditVal(int id) {
    wchar_t buf[MAX_PATH] = {0};
    GetDlgItemTextW(g_hWnd, id, buf, MAX_PATH);
    return buf;
}

// Main Window Procedure
LRESULT CALLBACK WndProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam) {
    switch (msg) {
        case WM_CREATE: {
            g_hFont = CreateFontW(16, 0, 0, 0, FW_NORMAL, FALSE, FALSE, FALSE,
                                 DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS,
                                 CLEARTYPE_QUALITY, DEFAULT_PITCH | FF_DONTCARE, L"Segoe UI");

            // Tab Control
            g_hTab = CreateWindowExW(0, WC_TABCONTROLW, L"", WS_CHILD | WS_CLIPSIBLINGS | WS_VISIBLE,
                                     15, 15, 590, 220, hWnd, (HMENU)ID_TAB_CONTROL, GetModuleHandle(NULL), NULL);
            SendMessageW(g_hTab, WM_SETFONT, (WPARAM)g_hFont, TRUE);

            TCITEMW tie = {0};
            tie.mask = TCIF_TEXT;
            tie.pszText = (LPWSTR)L"  PE Files (.exe/.dll/.sys)  ";
            TabCtrl_InsertItem(g_hTab, 0, &tie);
            tie.pszText = (LPWSTR)L"  Folder Changer  ";
            TabCtrl_InsertItem(g_hTab, 1, &tie);
            tie.pszText = (LPWSTR)L"  File Types (.pak/.bat/.cmd)  ";
            TabCtrl_InsertItem(g_hTab, 2, &tie);
            tie.pszText = (LPWSTR)L"  Custom Shortcut (.lnk)  ";
            TabCtrl_InsertItem(g_hTab, 3, &tie);

            // --- TAB 0: PE Files ---
            g_tabControls[0].push_back(CreateLabel(L"Target PE File (.exe, .dll, .sys):", 30, 55, 300, 18, hWnd));
            g_tabControls[0].push_back(CreateEdit(ID_PE_TARGET_EDIT, 30, 75, 470, 24, hWnd));
            g_tabControls[0].push_back(CreateBtn(L"Browse...", ID_PE_TARGET_BROWSE, 508, 75, 80, 24, hWnd));

            g_tabControls[0].push_back(CreateLabel(L"New Icon File (.ico):", 30, 108, 300, 18, hWnd));
            g_tabControls[0].push_back(CreateEdit(ID_PE_ICON_EDIT, 30, 128, 470, 24, hWnd));
            g_tabControls[0].push_back(CreateBtn(L"Browse...", ID_PE_ICON_BROWSE, 508, 128, 80, 24, hWnd));

            g_tabControls[0].push_back(CreateCheckbox(L"Create .bak backup of original file", ID_PE_BACKUP_CHK, 30, 160, 250, 22, hWnd, true));
            g_tabControls[0].push_back(CreateBtn(L"Apply Icon to PE File", ID_PE_APPLY_BTN, 30, 190, 180, 30, hWnd));
            g_tabControls[0].push_back(CreateBtn(L"Restore from Backup (.bak)", ID_PE_RESTORE_BTN, 220, 190, 180, 30, hWnd));

            // --- TAB 1: Folder ---
            g_tabControls[1].push_back(CreateLabel(L"Target Folder to Customize:", 30, 55, 300, 18, hWnd));
            g_tabControls[1].push_back(CreateEdit(ID_FLD_TARGET_EDIT, 30, 75, 470, 24, hWnd));
            g_tabControls[1].push_back(CreateBtn(L"Browse...", ID_FLD_TARGET_BROWSE, 508, 75, 80, 24, hWnd));

            g_tabControls[1].push_back(CreateLabel(L"Icon File (.ico):", 30, 108, 300, 18, hWnd));
            g_tabControls[1].push_back(CreateEdit(ID_FLD_ICON_EDIT, 30, 128, 470, 24, hWnd));
            g_tabControls[1].push_back(CreateBtn(L"Browse...", ID_FLD_ICON_BROWSE, 508, 128, 80, 24, hWnd));

            g_tabControls[1].push_back(CreateCheckbox(L"Embed icon inside folder (Portable - stays when moved/copied)", ID_FLD_PORTABLE_CHK, 30, 160, 450, 22, hWnd, true));
            g_tabControls[1].push_back(CreateBtn(L"Apply Folder Icon", ID_FLD_APPLY_BTN, 30, 190, 180, 30, hWnd));
            g_tabControls[1].push_back(CreateBtn(L"Reset Folder to Default", ID_FLD_RESET_BTN, 220, 190, 180, 30, hWnd));

            // --- TAB 2: File Types (.pak, .bat, etc.) ---
            g_tabControls[2].push_back(CreateLabel(L"File Extension (e.g. .pak, .bat, .cmd, .sys):", 30, 55, 350, 18, hWnd));
            g_tabControls[2].push_back(CreateEdit(ID_EXT_TYPE_EDIT, 30, 75, 200, 24, hWnd, L".pak"));

            g_tabControls[2].push_back(CreateLabel(L"New Default Icon (.ico):", 30, 108, 300, 18, hWnd));
            g_tabControls[2].push_back(CreateEdit(ID_EXT_ICON_EDIT, 30, 128, 470, 24, hWnd));
            g_tabControls[2].push_back(CreateBtn(L"Browse...", ID_EXT_ICON_BROWSE, 508, 128, 80, 24, hWnd));

            g_tabControls[2].push_back(CreateBtn(L"Set File Type Icon", ID_EXT_APPLY_BTN, 30, 185, 180, 32, hWnd));
            g_tabControls[2].push_back(CreateBtn(L"Reset to Windows Default", ID_EXT_RESET_BTN, 220, 185, 180, 32, hWnd));

            // --- TAB 3: Custom Shortcut ---
            g_tabControls[3].push_back(CreateLabel(L"Target Script or Data File (.bat, .cmd, .pak, any file):", 30, 55, 400, 18, hWnd));
            g_tabControls[3].push_back(CreateEdit(ID_LNK_TARGET_EDIT, 30, 75, 470, 24, hWnd));
            g_tabControls[3].push_back(CreateBtn(L"Browse...", ID_LNK_TARGET_BROWSE, 508, 75, 80, 24, hWnd));

            g_tabControls[3].push_back(CreateLabel(L"Custom Icon (.ico):", 30, 105, 300, 18, hWnd));
            g_tabControls[3].push_back(CreateEdit(ID_LNK_ICON_EDIT, 30, 125, 470, 24, hWnd));
            g_tabControls[3].push_back(CreateBtn(L"Browse...", ID_LNK_ICON_BROWSE, 508, 125, 80, 24, hWnd));

            g_tabControls[3].push_back(CreateLabel(L"Output Shortcut Path (.lnk):", 30, 155, 300, 18, hWnd));
            g_tabControls[3].push_back(CreateEdit(ID_LNK_OUT_EDIT, 30, 175, 470, 24, hWnd));
            g_tabControls[3].push_back(CreateBtn(L"Browse...", ID_LNK_OUT_BROWSE, 508, 175, 80, 24, hWnd));

            g_tabControls[3].push_back(CreateBtn(L"Create Custom Shortcut", ID_LNK_CREATE_BTN, 30, 203, 190, 28, hWnd));

            // Activity Log Box
            CreateLabel(L"Activity & Status Log:", 15, 245, 200, 18, hWnd);
            g_hLogBox = CreateWindowExW(WS_EX_CLIENTEDGE, L"EDIT", L"",
                                        WS_CHILD | WS_VISIBLE | WS_VSCROLL | ES_MULTILINE | ES_AUTOVSCROLL | ES_READONLY,
                                        15, 265, 590, 120, hWnd, (HMENU)ID_LOG_BOX, GetModuleHandle(NULL), NULL);
            SendMessageW(g_hLogBox, WM_SETFONT, (WPARAM)g_hFont, TRUE);

            SwitchTab(0);
            DragAcceptFiles(hWnd, TRUE);
            AppendLog(L"IconCraft Studio initialized. Ready.");
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
                if (curTab == 0) SetDlgItemTextW(hWnd, ID_PE_ICON_EDIT, dropped);
                else if (curTab == 1) SetDlgItemTextW(hWnd, ID_FLD_ICON_EDIT, dropped);
                else if (curTab == 2) SetDlgItemTextW(hWnd, ID_EXT_ICON_EDIT, dropped);
                else if (curTab == 3) SetDlgItemTextW(hWnd, ID_LNK_ICON_EDIT, dropped);
                AppendLog(L"Dropped icon: " + file);
            } else {
                if (curTab == 0) {
                    SetDlgItemTextW(hWnd, ID_PE_TARGET_EDIT, dropped);
                    AppendLog(L"Selected PE target: " + file);
                } else if (curTab == 1) {
                    SetDlgItemTextW(hWnd, ID_FLD_TARGET_EDIT, dropped);
                    AppendLog(L"Selected folder: " + file);
                } else if (curTab == 2) {
                    SetDlgItemTextW(hWnd, ID_EXT_TYPE_EDIT, ext.c_str());
                    AppendLog(L"Extracted extension: " + ext);
                } else if (curTab == 3) {
                    SetDlgItemTextW(hWnd, ID_LNK_TARGET_EDIT, dropped);
                    SetDlgItemTextW(hWnd, ID_LNK_OUT_EDIT, (file + L".lnk").c_str());
                    AppendLog(L"Selected file for shortcut: " + file);
                }
            }
            break;
        }

        case WM_COMMAND: {
            int wmId = LOWORD(wParam);
            switch (wmId) {
                // Tab 0 Browsers
                case ID_PE_TARGET_BROWSE: {
                    std::wstring f = BrowseFileDialog(hWnd, L"Executables & PE (*.exe;*.dll;*.sys;*.scr)\0*.exe;*.dll;*.sys;*.scr\0All Files (*.*)\0*.*\0");
                    if (!f.empty()) SetDlgItemTextW(hWnd, ID_PE_TARGET_EDIT, f.c_str());
                    break;
                }
                case ID_PE_ICON_BROWSE: {
                    std::wstring f = BrowseFileDialog(hWnd, L"Icon Files (*.ico)\0*.ico\0");
                    if (!f.empty()) SetDlgItemTextW(hWnd, ID_PE_ICON_EDIT, f.c_str());
                    break;
                }
                case ID_PE_APPLY_BTN: {
                    std::wstring pe = GetEditVal(ID_PE_TARGET_EDIT);
                    std::wstring ico = GetEditVal(ID_PE_ICON_EDIT);
                    bool bak = (SendMessageW(GetDlgItem(hWnd, ID_PE_BACKUP_CHK), BM_GETCHECK, 0, 0) == BST_CHECKED);
                    std::wstring msg;
                    AppendLog(L"Applying icon to: " + pe);
                    if (ModifyPEIcon(pe, ico, bak, msg)) {
                        AppendLog(msg);
                        MessageBoxW(hWnd, msg.c_str(), L"Success", MB_OK | MB_ICONINFORMATION);
                    } else {
                        AppendLog(msg);
                        MessageBoxW(hWnd, msg.c_str(), L"Error", MB_OK | MB_ICONERROR);
                    }
                    break;
                }
                case ID_PE_RESTORE_BTN: {
                    std::wstring pe = GetEditVal(ID_PE_TARGET_EDIT);
                    if (pe.empty()) {
                        MessageBoxW(hWnd, L"Please enter or select a target file first.", L"Warning", MB_OK | MB_ICONWARNING);
                        break;
                    }
                    std::wstring bak = pe + L".bak";
                    if (CopyFileW(bak.c_str(), pe.c_str(), FALSE)) {
                        SHChangeNotify(SHCNE_UPDATEITEM, SHCNF_PATHW, pe.c_str(), NULL);
                        AppendLog(L"Restored original file from: " + bak);
                        MessageBoxW(hWnd, L"Backup restored successfully!", L"Restored", MB_OK | MB_ICONINFORMATION);
                    } else {
                        AppendLog(L"Error: Could not find or copy " + bak);
                        MessageBoxW(hWnd, L"Could not find a valid .bak file to restore.", L"Error", MB_OK | MB_ICONERROR);
                    }
                    break;
                }

                // Tab 1 Browsers
                case ID_FLD_TARGET_BROWSE: {
                    std::wstring f = BrowseFolderDialog(hWnd);
                    if (!f.empty()) SetDlgItemTextW(hWnd, ID_FLD_TARGET_EDIT, f.c_str());
                    break;
                }
                case ID_FLD_ICON_BROWSE: {
                    std::wstring f = BrowseFileDialog(hWnd, L"Icon Files (*.ico)\0*.ico\0All Files (*.*)\0*.*\0");
                    if (!f.empty()) SetDlgItemTextW(hWnd, ID_FLD_ICON_EDIT, f.c_str());
                    break;
                }
                case ID_FLD_APPLY_BTN: {
                    std::wstring fld = GetEditVal(ID_FLD_TARGET_EDIT);
                    std::wstring ico = GetEditVal(ID_FLD_ICON_EDIT);
                    bool port = (SendMessageW(GetDlgItem(hWnd, ID_FLD_PORTABLE_CHK), BM_GETCHECK, 0, 0) == BST_CHECKED);
                    std::wstring msg;
                    if (ModifyFolderIcon(fld, ico, port, msg)) {
                        AppendLog(msg);
                        MessageBoxW(hWnd, msg.c_str(), L"Success", MB_OK | MB_ICONINFORMATION);
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
                        MessageBoxW(hWnd, msg.c_str(), L"Reset", MB_OK | MB_ICONINFORMATION);
                    }
                    break;
                }

                // Tab 2 Browsers
                case ID_EXT_ICON_BROWSE: {
                    std::wstring f = BrowseFileDialog(hWnd, L"Icon Files (*.ico)\0*.ico\0");
                    if (!f.empty()) SetDlgItemTextW(hWnd, ID_EXT_ICON_EDIT, f.c_str());
                    break;
                }
                case ID_EXT_APPLY_BTN: {
                    std::wstring ext = GetEditVal(ID_EXT_TYPE_EDIT);
                    std::wstring ico = GetEditVal(ID_EXT_ICON_EDIT);
                    std::wstring msg;
                    if (ModifyExtensionIcon(ext, ico, msg)) {
                        AppendLog(msg);
                        MessageBoxW(hWnd, msg.c_str(), L"Success", MB_OK | MB_ICONINFORMATION);
                    } else {
                        AppendLog(msg);
                        MessageBoxW(hWnd, msg.c_str(), L"Error", MB_OK | MB_ICONERROR);
                    }
                    break;
                }
                case ID_EXT_RESET_BTN: {
                    std::wstring ext = GetEditVal(ID_EXT_TYPE_EDIT);
                    std::wstring msg;
                    if (ResetExtension(ext, msg)) {
                        AppendLog(msg);
                        MessageBoxW(hWnd, msg.c_str(), L"Reset", MB_OK | MB_ICONINFORMATION);
                    }
                    break;
                }

                // Tab 3 Browsers
                case ID_LNK_TARGET_BROWSE: {
                    std::wstring f = BrowseFileDialog(hWnd, L"All Files (*.*)\0*.*\0");
                    if (!f.empty()) {
                        SetDlgItemTextW(hWnd, ID_LNK_TARGET_EDIT, f.c_str());
                        SetDlgItemTextW(hWnd, ID_LNK_OUT_EDIT, (f + L".lnk").c_str());
                    }
                    break;
                }
                case ID_LNK_ICON_BROWSE: {
                    std::wstring f = BrowseFileDialog(hWnd, L"Icon Files (*.ico)\0*.ico\0");
                    if (!f.empty()) SetDlgItemTextW(hWnd, ID_LNK_ICON_EDIT, f.c_str());
                    break;
                }
                case ID_LNK_OUT_BROWSE: {
                    std::wstring f = BrowseFileDialog(hWnd, L"Shortcut (*.lnk)\0*.lnk\0", false);
                    if (!f.empty()) SetDlgItemTextW(hWnd, ID_LNK_OUT_EDIT, f.c_str());
                    break;
                }
                case ID_LNK_CREATE_BTN: {
                    std::wstring tgt = GetEditVal(ID_LNK_TARGET_EDIT);
                    std::wstring ico = GetEditVal(ID_LNK_ICON_EDIT);
                    std::wstring out = GetEditVal(ID_LNK_OUT_EDIT);
                    std::wstring msg;
                    if (CreateCustomShortcut(tgt, ico, out, msg)) {
                        AppendLog(msg);
                        MessageBoxW(hWnd, msg.c_str(), L"Shortcut Created", MB_OK | MB_ICONINFORMATION);
                    } else {
                        AppendLog(msg);
                        MessageBoxW(hWnd, msg.c_str(), L"Error", MB_OK | MB_ICONERROR);
                    }
                    break;
                }
            }
            break;
        }

        case WM_DESTROY: {
            if (g_hFont) DeleteObject(g_hFont);
            PostQuitMessage(0);
            break;
        }

        default:
            return DefWindowProcW(hWnd, msg, wParam, lParam);
    }
    return 0;
}

int WINAPI wWinMain(HINSTANCE hInstance, HINSTANCE, PWSTR, int nCmdShow) {
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
    wc.lpszClassName = L"IconCraftStudioClass";
    wc.hIcon = LoadIcon(NULL, IDI_APPLICATION);

    if (!RegisterClassExW(&wc)) return 0;

    int w = 635;
    int h = 435;
    int x = (GetSystemMetrics(SM_CXSCREEN) - w) / 2;
    int y = (GetSystemMetrics(SM_CYSCREEN) - h) / 2;

    g_hWnd = CreateWindowExW(0, wc.lpszClassName,
                             L"IconCraft Studio - Universal Icon Changer",
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
