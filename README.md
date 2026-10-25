# Advanced icon changer - Universal Windows Icon Changer

A lightweight, standalone, single-file C++ GUI application for modifying icons across Windows.

---

## 🌟 Key Features

1. **PE Binary Executables (`.exe`, `.dll`, `.sys`, `.scr`)**
   - Directly injects multi-resolution `.ico` images into the PE resource table (`RT_GROUP_ICON` & `RT_ICON`).
   - Automatic `.bak` backup creation and 1-click restore functionality.
   - Refreshes Windows Explorer shell cache instantly.

2. **Folder Icon Customization**
   - Sets custom folder icons using `desktop.ini` and proper folder attributes (`FILE_ATTRIBUTE_READONLY`).
   - **Portable Mode**: Option to copy the `.ico` file into the folder as a hidden file so the icon stays when moved across drives or USB.
   - 1-click reset to restore the default Windows folder icon.

3. **File Types & Extensions (`.pak`, `.bat`, `.cmd`, `.sys`, etc.)**
   - Configures `HKCU\Software\Classes\<extension>\DefaultIcon` in the registry.
   - Safe user-level modification without requiring administrator elevation.
   - Instant shell icon cache invalidation (`SHChangeNotify`).
   - 1-click reset to restore default system icons.

4. **Dedicated Shortcut Generator (`.lnk`)**
   - Target any individual `.bat`, `.cmd`, or `.pak` file to produce a custom desktop/folder shortcut with your chosen icon.

5. **User Experience**
   - **Drag and Drop**: Simply drag and drop any file, folder, or `.ico` directly into the window.
   - **Activity Console**: Real-time logging of operations and error reporting.

---

## 🛠️ How to Build

### Requirements
- MinGW-w64 (`g++`) or MSVC.

### One-Click Build
Run [build.bat](build.bat) or execute the following command:

```cmd
g++ -O2 -municode -mwindows main.cpp -o IconChanger.exe -lcomctl32 -lcomdlg32 -lole32 -luuid -lshlwapi -ladvapi32
```
