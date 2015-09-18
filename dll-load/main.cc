#define WIN32_LEAN_AND_MEAN
#include <Windows.h>

#include <cstdio>

int main (int argc, const char** argv)
{
    if (argc != 2)
    {
        fprintf(stderr, "Usage: dll-load <dll>\n");
        return 0;
    }
    const char* dll_path = argv[1];

    HMODULE dll = LoadLibraryA(dll_path);
    if (dll == NULL)
    {
        fprintf(stderr, "Failed loading library %s (%d)\n",
                dll_path, GetLastError());
        return -1;
    }

    FreeLibrary(dll);

    return 0;
}
