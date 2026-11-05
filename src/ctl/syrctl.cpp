// syrctl.cpp —— 控制面客户端: 连 \\.\pipe\syringe64-<pid>, 逐条发命令、回显应答。
//   syrctl.exe <pid> <命令...>        例: syrctl 1234 load D:\x\payload.dll
//   syrctl.exe <pid> -                交互模式(逐行从 stdin 转发)
#include <windows.h>
#include <cstdio>
#include <cstring>
#include <string>

int main(int argc, char** argv) {
  if (argc < 3) { fprintf(stderr, "usage: syrctl <pid> <command...|->\n"); return 2; }
  char aname[64];
  _snprintf_s(aname, _TRUNCATE, "\\\\.\\pipe\\syringe64-%s", argv[1]);
  wchar_t name[64];
  MultiByteToWideChar(CP_UTF8, 0, aname, -1, name, 64);

  HANDLE pipe = CreateFileW(name, GENERIC_READ | GENERIC_WRITE, 0, nullptr,
                            OPEN_EXISTING, 0, nullptr);
  if (pipe == INVALID_HANDLE_VALUE) {
    fprintf(stderr, "open pipe failed gle=%lu (tether 注入了吗?)\n", GetLastError());
    return 1;
  }
  DWORD mode = PIPE_READMODE_BYTE;
  SetNamedPipeHandleState(pipe, &mode, nullptr, nullptr);

  int rc = 0;
  if (!strcmp(argv[2], "-")) {
    char line[2048];
    while (fgets(line, sizeof(line), stdin)) {
      DWORD w = 0;
      if (!WriteFile(pipe, line, (DWORD)strlen(line), &w, nullptr)) break;
      char c;
      std::string acc;
      while (ReadFile(pipe, &c, 1, &w, nullptr) && w) {
        acc += c;
        if (acc.size() >= 2 && acc[acc.size() - 2] == '\n' && acc.back() == '.') break;
      }
      fputs(acc.c_str(), stdout);
      fflush(stdout);
      if (!strncmp(line, "quit", 4)) break;
    }
  } else {
    std::string cmd;
    for (int i = 2; i < argc; i++) { cmd += argv[i]; cmd += " "; }
    cmd += "\n";
    DWORD w = 0;
    WriteFile(pipe, cmd.data(), (DWORD)cmd.size(), &w, nullptr);
    char c;
    std::string acc;
    while (ReadFile(pipe, &c, 1, &w, nullptr) && w) {
      acc += c;
      if (acc.size() >= 2 && acc[acc.size() - 2] == '\n' && acc.back() == '.') break;
    }
    fputs(acc.c_str(), stdout);
    if (acc.rfind("ERR", 0) == 0) rc = 1;
  }
  CloseHandle(pipe);
  return rc;
}
