#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>

int magic;
char buff[4096];

void hardfmt()
{
    int *guard = alloca(4);
    *guard = magic;

    for(int i = 0; i < 5; i++) {
        read(0, buff, sizeof(buff));
        printf(buff);
    }
    if(*guard != magic) {
        puts("**Stack smashed**");
        exit(1);
    }
    exit(0);
}

int main(int argc, char *argv[], char *envp[])
{
    setbuf(stdout, NULL);
    long long int rnd;
    int fd = open("/dev/urandom", 0);
    if(fd < 0) {
        puts("urandom error");
        exit(1);