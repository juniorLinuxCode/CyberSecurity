#include <stdio.h>

void checkPass(int x)
{
    if(x == 7857)
    {
        printf("Access Granted\n");
    }
    else
    {
        printf("Access Denied\n");
    }
}

int main(int argc, char *argv[])
{
    int x = 0;
    printf("Enter the password: ");
    scanf("%d", &x);
    checkPass(x);
    return 0;
}

#passsword 7857