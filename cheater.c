#include <stdio.h>
#include <stdlib.h>

#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include <sys/ptrace.h>
#include <sys/personality.h>
#include <sys/wait.h>
#include <sys/user.h>

#define ELF_MAGIC_NUMBER "\x7F\x45\x4C\x46"

#define BOMB_CLICK_ADDRESS 0x55555555BABF
#define FLAG_CLICK_ONE 0x55555555E496
#define FLAG_CLICK_TWO 0x55555555C141

#define REG_RIP 1 // 64 bit instruction pointer
#define REG_ECX 2 // 32 bit RCX
#define REG_RAX 3 // 64 bit RAX
#define REG_EAX 4 // 32 bit RAX



void fatal(const char * msg) {
    fprintf(stderr, "ERROR: %s\n", msg);
    exit(-1);
}


u_int64_t get_register(pid_t pid, int reg) {

    u_int64_t value;
    struct user_regs_struct regs;

    ptrace(PTRACE_GETREGS, pid, NULL, &regs);

    switch (reg) {

        case REG_RIP:
            value = regs.rip;
            break;

        case REG_RAX:
            value = regs.rax;
            break;

        default:
            value = 0;
            break;

    }

    return value;
}


u_int64_t set_register(pid_t pid, int reg, u_int64_t new_value) {

    u_int64_t former_value;
    struct user_regs_struct regs;

    ptrace(PTRACE_GETREGS, pid, NULL, &regs);

    switch (reg) {

        case REG_RIP:
            former_value = regs.rip;
            regs.rip = new_value;
            break;

        case REG_RAX:
            former_value = regs.rax;
            regs.rax = new_value;
            break;

        default:
            former_value = 0;
            break;

    }

    ptrace(PTRACE_SETREGS, pid, NULL, &regs);
    return former_value;
}


u_int32_t get_register32(pid_t pid, int reg) {

    u_int32_t value;
    struct user_regs_struct regs;

    ptrace(PTRACE_GETREGS, pid, NULL, &regs);

    switch (reg) {

        case REG_ECX: // note: rcx is the 64 bit register whereas ecx is the lower 32 bits of rcx
            value = (u_int32_t) regs.rcx & 0x00000000FFFFFFFF;
            break;

        case REG_EAX:
            value = (u_int32_t) regs.rax & 0x00000000FFFFFFFF;
            break;

        default:
            value = 0;
            break;

    }

    return value;
}


u_int32_t set_register32(pid_t pid, int reg, u_int32_t new_value) {

    struct user_regs_struct regs;
    u_int32_t former_value;

    ptrace(PTRACE_GETREGS, pid, NULL, &regs);

    switch (reg) {

        case REG_ECX: // note: rcx is the 64 bit register whereas ecx is the lower 32 bits of rcx
            former_value = (u_int32_t) regs.rcx & 0x00000000FFFFFFFF;
            regs.rcx = (regs.rcx & 0xFFFFFFFF00000000) | new_value;
            break;

        case REG_EAX:
            former_value = (u_int32_t) regs.rax & 0x00000000FFFFFFFF;
            regs.rax = (regs.rax & 0xFFFFFFFF00000000) | new_value;
            break;

        default:
            former_value = 0;
            break;

    }

    ptrace(PTRACE_SETREGS, pid, NULL, &regs);
    return former_value;
}


u_int64_t poke_int3(pid_t pid, u_int64_t location) {

    u_int64_t data, save, int3, data_with_int3;

    // save instruction byte that we are about to clobber
    data = ptrace(PTRACE_PEEKDATA, pid, location, NULL);
    save = data & 0xfful;

    // overwrite one instruction byte with "interrupt 3" which causes a SIGTRAP when encountered by processor
    int3 = 0xcc;
    data_with_int3 = ((data & ~0xfful) | int3);

    if (ptrace(PTRACE_POKEDATA, pid, location, data_with_int3) == -1) {
        fatal("Poking int3 failed");
    }

    return save;

}


int unpoke_int3(pid_t pid, u_int64_t location, u_int64_t replaced_data) {

    u_int64_t data;
    int status;

    data = ptrace(PTRACE_PEEKDATA, pid, location, NULL);
    data = ((data & ~0xfful) | replaced_data);
    status = (int)ptrace(PTRACE_POKEDATA, pid, location, data);

    return status;
}


void alarm_signal_set(pid_t pid, int on) {
    sigset_t sig_mask_set;

    sigemptyset(&sig_mask_set);

    // Manpage says sizeof(siget_t) but it needs size 8 to work?!
    ptrace(PTRACE_GETSIGMASK, pid, sizeof(int64_t), &sig_mask_set);

    if (on) {
        sigdelset(&sig_mask_set, SIGALRM);
    } else {
        sigaddset(&sig_mask_set, SIGALRM);
    }

    ptrace(PTRACE_SETSIGMASK, pid, sizeof(int64_t), &sig_mask_set);
}


void single_step(pid_t pid) {
    int status;

    alarm_signal_set(pid, 0);
    ptrace(PTRACE_SINGLESTEP, pid, NULL, 0);

    if (waitpid(pid, &status, 0) == -1) {
        fatal("Inferior changed state in an unpredictable way.\n");
    }

    alarm_signal_set(pid, 1);

}


void wait_for_inferior(pid_t pid) {
    int time_elapsed = 0;
    int status;
    int first_stop = 1;
    u_int64_t bomb_save = 0, flag_save_1 = 0, flag_save_2 = 0, ip;
    u_int64_t flag_reg_1;
    u_int32_t bomb_reg, flag_reg_2;

    while(1) {
        waitpid(pid, &status, 0);

        if (status == -1) {
            fatal("Couldn't wait for inferior.");
        }

        if (WIFEXITED(status)) {
            printf("\nxdemineur exited.");
            printf("\nTime Elapsed: %d minute(s) %d second(s)", time_elapsed / 60, time_elapsed % 60);
            return;
        } else if (WIFSTOPPED(status)) {

            if (WSTOPSIG(status) == SIGALRM) {
                time_elapsed++;
                ptrace(PTRACE_CONT, pid, NULL, SIGALRM);
                continue;
            } else if (WSTOPSIG(status) == SIGSEGV) {
                fatal("Segfault in xdemineur.");
            } else if (WSTOPSIG(status) == SIGTRAP) {

                ip = get_register(pid, REG_RIP);
                //printf("It's a trap! Execution stopped at instruction address: %p\n", (void *) ip - 1);

                if (first_stop) {
                    first_stop = 0;
                    bomb_save = poke_int3(pid, BOMB_CLICK_ADDRESS);
                    flag_save_1 = poke_int3(pid, FLAG_CLICK_ONE);
                    flag_save_2 = poke_int3(pid, FLAG_CLICK_TWO);
                } else {
                    if (ip - 1 == BOMB_CLICK_ADDRESS) {
                        unpoke_int3(pid, BOMB_CLICK_ADDRESS, bomb_save);   // remove 0xCC byte
                        set_register(pid, REG_RIP, BOMB_CLICK_ADDRESS);

                        bomb_reg = get_register32(pid, REG_ECX);
                        if (bomb_reg != 0) {
                            set_register32(pid, REG_ECX, 0x0);
                        }

                        single_step(pid);

                        bomb_save = poke_int3(pid, BOMB_CLICK_ADDRESS);

                    } else if (ip - 1 == FLAG_CLICK_ONE) {
                        unpoke_int3(pid, FLAG_CLICK_ONE, flag_save_1);   // remove 0xCC
                        set_register(pid, REG_RIP, FLAG_CLICK_ONE);

                        flag_reg_1 = get_register(pid, REG_RAX);
                        set_register(pid, REG_RAX, flag_reg_1+0x4);

                        single_step(pid);

                        set_register(pid, REG_RAX, flag_reg_1);    // put back register value
                        flag_save_1 = poke_int3(pid, FLAG_CLICK_ONE);

                    } else if (ip - 1 == FLAG_CLICK_TWO) {
                        unpoke_int3(pid, FLAG_CLICK_TWO, flag_save_2);
                        set_register(pid, REG_RIP, FLAG_CLICK_TWO);

                        flag_reg_2 = get_register32(pid, REG_EAX);
                        if (flag_reg_2 != 0 && flag_reg_2 != 2) {
                            set_register32(pid, REG_EAX, 0x0);
                        }

                        single_step(pid);

                        flag_save_2 = poke_int3(pid, FLAG_CLICK_TWO);
                    }
                }

            } else {
                printf("Warning: unhandled stop signal.\n");
            }
        }

        ptrace(PTRACE_CONT, pid, NULL, 0);
    }
}


void validate_exe_path(const char * path) {

    int fd;
    char magic_number[4];
    fd = open(path, O_RDONLY);
    if (fd == -1) fatal("Invalid path.");

    read(fd, magic_number, 4);
    if (memcmp(magic_number, ELF_MAGIC_NUMBER, 4) != 0) {
        fatal("Not an ELF file.");
    }

}


void attach_exe(char * path, char ** argv) {
    pid_t pid;

    validate_exe_path(path);

    pid = fork();
    switch (pid) {

        case 0:     // inferior

            ptrace(PTRACE_TRACEME, 0, NULL, 0);
            personality(ADDR_NO_RANDOMIZE);

            if (execv(path, argv) == -1) {
                fatal("execv failed.");
            }

            break;

        case -1:    // error
            break;

        default:    // tracer
            wait_for_inferior(pid);
            break;
    }
}


int main(int argc, char *argv[]) {

    if (argc < 2) {
        fatal("Requires xdemineur path with optional arguments.");
    }

    attach_exe(argv[1], argv+1);

    return 0;
}
