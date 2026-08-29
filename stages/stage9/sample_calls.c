#include <stdint.h>
__attribute__((noinline)) void sceAgcInit(void) {}
void test_caller(void) {
    uintptr_t p = 0x1234;
    __asm__ volatile("mov %0, %%rdx" : : "r"(p) : "rdx");
    (void)p;
    sceAgcInit();
}
int main(void){test_caller(); return 0;}
