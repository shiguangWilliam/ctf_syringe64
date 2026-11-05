// launcher_main.cpp —— syringe64 启动壳: 把 tether.dll 送进目标。
//   launcher64.exe --attach <pid> <tether.dll>
//   launcher64.exe --create <game.exe> [args..] -- <tether.dll>   (suspended create + 注入 + resume)
#include <windows.h>
#include <cstdio>
#include <cstring>
#include <string>

static int InjectDll(HANDLE proc, const std::wstring& dll) {
  SIZE_T bytes = (dll.size() + 1) * sizeof(wchar_t);
  void* remote = VirtualAllocEx(proc, nullptr, bytes, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
  if (!remote) { fprintf(stderr, "VirtualAllocEx failed gle=%lu\n", GetLastError()); return 1; }
  if (!WriteProcessMemory(proc, remote, dll.c_str(), bytes, nullptr)) {
    fprintf(stderr, "WriteProcessMemory failed gle=%lu\n", GetLastError());
    return 1;
  }
  auto load = (LPTHREAD_START_ROUTINE)(uintptr_t)GetProcAddress(
      GetModuleHandleW(L"kernel32.dll"), "LoadLibraryW");
  if (!load) { fprintf(stderr, "LoadLibraryW not found\n"); return 1; }
  HANDLE t = CreateRemoteThread(proc, nullptr, 0, load, remote, 0, nullptr);
  if (!t) { fprintf(stderr, "CreateRemoteThread failed gle=%lu\n", GetLastError()); return 1; }
  WaitForSingleObject(t, 10000);
  DWORD code = 0;
  GetExitCodeThread(t, &code);
  CloseHandle(t);
  VirtualFreeEx(proc, remote, 0, MEM_RELEASE);
  if (!code) { fprintf(stderr, "remote LoadLibraryW returned NULL\n"); return 1; }
  printf("inject OK (remote hmodule=%p)\n", (void*)(uintptr_t)code);
  return 0;
}

static std::wstring ToWide(const char* s) {
  wchar_t w[1024];
  MultiByteToWideChar(CP_UTF8, 0, s, -1, w, 1024);
  return w;
}

int main(int argc, char** argv) {
  if (argc < 4) {
    fprintf(stderr,
            "usage:\n  %s --attach <pid> <tether.dll>\n"
            "  %s --create <exe> [args..] -- <tether.dll>\n",
            argv[0], argv[0]);
    return 2;
  }
  if (!strcmp(argv[1], "--attach")) {
    DWORD pid = (DWORD)strtoul(argv[2], nullptr, 0);
    HANDLE proc = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
    if (!proc) { fprintf(stderr, "OpenProcess(%lu) failed gle=%lu\n", pid, GetLastError()); return 1; }
    int r = InjectDll(proc, ToWide(argv[3]));
    CloseHandle(proc);
    return r;
  }
  if (!strcmp(argv[1], "--create")) {
    std::wstring exe = ToWide(argv[2]);
    std::wstring cmd = L"\"" + exe + L"\"";
    std::wstring dll;
    for (int i = 3; i < argc; i++) {
      if (!strcmp(argv[i], "--")) { dll = ToWide(argv[i + 1]); break; }
      cmd += L" ";
      cmd += ToWide(argv[i]);
    }
    if (dll.empty()) { fprintf(stderr, "missing '-- <tether.dll>'\n"); return 2; }
    STARTUPINFOW si{sizeof(si)};
    PROCESS_INFORMATION pi{};
    std::wstring cmdline = cmd;
    if (!CreateProcessW(exe.c_str(), cmdline.data(), nullptr, nullptr, FALSE,
                        CREATE_SUSPENDED, nullptr, nullptr, &si, &pi)) {
      fprintf(stderr, "CreateProcessW failed gle=%lu\n", GetLastError());
      return 1;
    }
    int r = InjectDll(pi.hProcess, dll);
    ResumeThread(pi.hThread);
    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);
    if (r != 0) TerminateProcess(pi.hProcess, 1);
    return r;
  }
  fprintf(stderr, "unknown mode %s\n", argv[1]);
  return 2;
}
