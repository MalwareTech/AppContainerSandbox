#include <windows.h>
#include <stdio.h>
#include "ContainerCreate.h"
#include "ContainerTest.h"

int main(int argc, char *argv[])
{
    if(!IsInAppContainer())
    {
        RunExecutableInContainer(argv[0]);
    }else{
        RunContainerTests();
    }
    getchar();

    return 0;
}