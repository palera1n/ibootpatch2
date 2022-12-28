/*
 * patch.c
 *
 * copyright (C) 2022/12/04 dora2ios
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 */

#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <assert.h>
#include <inttypes.h>

#include "offsetfinder.h"
#include "payload.h"

#define LOG(x, ...) \
do { \
printf("[LOG] "x"\n", ##__VA_ARGS__); \
} while(0)

#define ERR(x, ...) \
do { \
printf("[ERR] "x"\n", ##__VA_ARGS__); \
} while(0)


#ifdef DEVBUILD
#define DEVLOG(x, ...) \
do { \
printf("[DEV] "x"\n", ##__VA_ARGS__); \
} while(0)
#else
#define DEVLOG(x, ...)
#endif

#define INSN_MOV_X0_0           0xd2800000
#define INSN_MOV_X0_1           0xd2800020
#define INSN_RET                0xd65f03c0
#define INSN_NOP                0xd503201f

int open_file(char *file, size_t *sz, unsigned char **buf)
{
    FILE *fd = fopen(file, "r");
    if (!fd) {
        ERR("error opening %s", file);
        return -1;
    }
    
    fseek(fd, 0, SEEK_END);
    *sz = ftell(fd);
    fseek(fd, 0, SEEK_SET);
    
    *buf = malloc(*sz);
    if (!*buf) {
        ERR("error allocating file buffer");
        fclose(fd);
        return -1;
    }
    
    fread(*buf, *sz, 1, fd);
    fclose(fd);
    
    return 0;
}

#define SUB (0x000100000)

void usage(const char *path)
{
    printf("%s [--t8015/--t8010] <in> <out>\n", path);
    printf("Version: " VERSION "\n");
}

int main(int argc, char **argv)
{
    if(argc != 4) {
        usage(argv[0]);
        return 0;
    }
    
    char *chip = argv[1];
    char *infile = argv[2];
    char *outfile = argv[3];
    uint16_t cpid;
    uint64_t sdram_page1 = 0;
    uint64_t load_address = 0;
    if(!strcmp(chip, "--t8015")) {
        cpid = 0x8015;
        sdram_page1     = 0x180002000;
        load_address    = 0x801000000;
    }
    
    if(!strcmp(chip, "--t8010")) {
        cpid = 0x8010;
        sdram_page1     = 0x180082000;
        load_address    = 0x800800000;
    }
    
    if(!cpid) {
        usage(argv[0]);
        return -1;
    }
    
    unsigned char* idata;
    size_t isize;
    if(open_file(infile, &isize, &idata))
        return -1;
    assert(isize && idata);
    
    
    {
        uint64_t iboot_base = *(uint64_t*)(idata + 0x300);
        if(!iboot_base)
            goto end;
        LOG("%016" PRIx64 "[%016" PRIx64 "]: iboot_base", iboot_base, (uint64_t)0x300);
        
#ifdef DEVBUILD
        {
            /*---- test part ----*/
            uint64_t test_printf = find_printf(iboot_base, idata, isize);
            if(test_printf)
                DEVLOG("%016" PRIx64 "[%016" PRIx64 "]: test_printf", test_printf + iboot_base, test_printf);
            else
                DEVLOG("Failed to find _printf");
            
            uint64_t test_mount_and_boot_system = find_mount_and_boot_system(iboot_base, idata, isize);
            if(test_mount_and_boot_system)
                DEVLOG("%016" PRIx64 "[%016" PRIx64 "]: test_mount_and_boot_system", test_mount_and_boot_system + iboot_base, test_mount_and_boot_system);
            else
                DEVLOG("Failed to find _mount_and_boot_system");
            
            uint64_t test_jumpto_func = find_jumpto_func(iboot_base, idata, isize);
            if(test_jumpto_func)
                DEVLOG("%016" PRIx64 "[%016" PRIx64 "]: test_jumpto_func", test_jumpto_func + iboot_base, test_jumpto_func);
            else
                DEVLOG("Failed to find jumpto_func");
            
            uint64_t test_panic = find_panic(iboot_base, idata, isize);
            if(test_panic)
                DEVLOG("%016" PRIx64 "[%016" PRIx64 "]: test_panic", test_panic + iboot_base, test_panic);
            else
                DEVLOG("Failed to find _panic");
            
        }
#endif
        
        uint64_t check_bootmode = find_check_bootmode(iboot_base, idata, isize);
        if(!check_bootmode) {
            ERR("Failed to find check_bootmode");
            goto end;
        }
        LOG("%016" PRIx64 "[%016" PRIx64 "]: check_bootmode", check_bootmode + iboot_base, check_bootmode);
        
        uint64_t bootx_str = find_bootx_str(iboot_base, idata, isize);
        if(!bootx_str) {
            ERR("Failed to find bootx string");
            goto end;
        }
        LOG("%016" PRIx64 "[%016" PRIx64 "]: bootx_str", bootx_str + iboot_base, bootx_str);
        
        uint64_t bootx_cmd_handler = find_bootx_cmd_handler(iboot_base, idata, isize);
        if(!bootx_cmd_handler) {
            ERR("Failed to find bootx command handler");
            goto end;
        }
        LOG("%016" PRIx64 "[%016" PRIx64 "]: bootx_cmd_handler", bootx_cmd_handler + iboot_base, bootx_cmd_handler);
        
        uint64_t go_cmd_handler = find_go_cmd_handler(iboot_base, idata, isize);
        if(!go_cmd_handler) {
            ERR("Failed to find go command handler");
            goto end;
        }
        LOG("%016" PRIx64 "[%016" PRIx64 "]: go_cmd_handler", go_cmd_handler + iboot_base, go_cmd_handler);
        
        uint64_t zeroBuf = find_zero(iboot_base, idata, isize);
        if(!zeroBuf) {
            ERR("Failed to find zeroBuf");
            goto end;
        }
        LOG("%016" PRIx64 "[%016" PRIx64 "]: zeroBuf", zeroBuf + iboot_base, zeroBuf);
        
        uint64_t jumpto_bl = find_jumpto_bl(iboot_base, idata, isize);
        if(!jumpto_bl) {
            ERR("Failed to find jumpto_bl");
            goto end;
        }
        LOG("%016" PRIx64 "[%016" PRIx64 "]: jumpto_bl", jumpto_bl + iboot_base, jumpto_bl);
        
        uint64_t kc_str = find_kc(iboot_base, idata, isize);
        if(!kc_str) {
            ERR("Failed to find kernelcache string");
            goto end;
        }
        LOG("%016" PRIx64 "[%016" PRIx64 "]: kc_str", kc_str + iboot_base, kc_str);
        
        /*---- patch part ----*/
        {
            uint32_t* patch_check_bootmode = (uint32_t*)(idata + check_bootmode);
            uint32_t opcode = INSN_MOV_X0_1;  // 0: LOCAL_BOOT, 1: REMOTE_BOOT
            if((opcode & 0xffffffdf) != 0xd2800000)
            {
                ERR("Detected weird opcode");
                goto end;
            }
            uint32_t bootmode = (opcode & 0xf0) >> 5;
            patch_check_bootmode[0] = opcode;
            patch_check_bootmode[1] = INSN_RET;
            LOG("set bootmode=%d (%s)", bootmode, bootmode == 0 ? "LOCAL_BOOT" : "REMOTE_BOOT");
        }
        
        {
            uint32_t* patch_bootx_str = (uint32_t*)(idata + bootx_str);
            patch_bootx_str[0] = 0x77726F64; // 'bootx' -> 'dorwx'
            LOG("bootx -> dorwx");
        }
        
        {
            uint64_t* patch_bootx_cmd_handler = (uint64_t*)(idata + bootx_cmd_handler);
            uint64_t* patch_go_cmd_handler = (uint64_t*)(idata + go_cmd_handler);
            
            patch_bootx_cmd_handler[0] = iboot_base + zeroBuf;
            LOG("change dorwx_cmd_handler -> %016" PRIx64, iboot_base + zeroBuf);
            patch_go_cmd_handler[0] = iboot_base + zeroBuf + a10_a11rxw_bin_len;
            LOG("change go_cmd_handler -> %016" PRIx64, iboot_base + zeroBuf + a10_a11rxw_bin_len);
            
            LOG("writing sdram_page1");
            uint64_t* ptr = (uint64_t*)(a10_a11rxw_bin + (a10_a11rxw_bin_len-8));
            ptr[0] = sdram_page1;
            LOG("writing load_address");
            ptr = (uint64_t*)(go_cmd_hook_bin + (go_cmd_hook_bin_len-0x10));
            ptr[0] = load_address-SUB;
            ptr[1] = load_address;
            
            ptr = (uint64_t*)(tram_bin + (tram_bin_len-8));
            ptr[0] = load_address-SUB+4;
            
            LOG("copying payload...");
            memcpy((void*)(idata + zeroBuf), a10_a11rxw_bin, a10_a11rxw_bin_len);
            memcpy((void*)(idata + zeroBuf + a10_a11rxw_bin_len), go_cmd_hook_bin, go_cmd_hook_bin_len);
            memcpy((void*)(idata + zeroBuf + a10_a11rxw_bin_len + go_cmd_hook_bin_len), tram_bin, tram_bin_len);
            LOG("done");
            
            uint64_t jumpto_hook_addr = zeroBuf + a10_a11rxw_bin_len + go_cmd_hook_bin_len;
            uint32_t opcode = make_branch(jumpto_bl, jumpto_hook_addr);
            LOG("jumpto_bl_opcode: %08x", opcode);
            uint32_t* patch_jumpto_bl = (uint32_t*)(idata + jumpto_bl);
            patch_jumpto_bl[0] = opcode;
        }
        
        {
            uint8_t* patch_kc_str = (uint8_t*)(idata + kc_str);
            patch_kc_str[0] = 'd';
            LOG("kernelcache -> kernelcachd");
        }
    }
    
    
    
    FILE *out = fopen(outfile, "w");
    if (!out) {
        ERR("error opening %s", outfile);
        return -1;
    }
    
    LOG("writing %s...", outfile);
    fwrite(idata, isize, 1, out);
    fflush(out);
    fclose(out);
    
    
end:
    if(idata)
        free(idata);
    
    return 0;
}
