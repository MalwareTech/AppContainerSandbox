#include <windows.h>
#include <stdio.h>
#include "ContainerCreate.h"
#include "ContainerTest.h"

void main(int argc, char *argv[])
{
    if(!IsInAppContainer())
    {
        RunExecutableInContainer(argv[0]);
    }else{
        RunContainerTests();
    }
    getchar();
}