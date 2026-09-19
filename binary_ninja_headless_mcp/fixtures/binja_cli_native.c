#include <stdint.h>
#include <stdio.h>

struct cli_pair { int left; int right; };
volatile uint32_t cli_global = 0x12345678;
char cli_message[] = "BINJA_CLI_NATIVE_SENTINEL";
const char *cli_message_ptr = cli_message;
struct cli_pair cli_pair_value = { 11, 29 };

__attribute__((noinline)) int cli_add(int value) { return value + 7; }
__attribute__((noinline)) int cli_branch(int value) {
    if (value > 10) return cli_add(value) + (int)cli_global;
    return cli_add(value) - 3;
}
int main(int argc, char **argv) {
    (void)argv;
    puts(cli_message_ptr);
    return cli_branch(argc) & 0xff;
}
