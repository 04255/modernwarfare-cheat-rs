#include "encryption.h"
#include <iostream>
#include <intrin.h>

#pragma intrinsic(_umul128)

extern void interop_read_bytes(uint64_t address, uint64_t size, size_t buf);

template<typename T>
auto read(uint64_t address) -> T {
    T result;
    interop_read_bytes(address, sizeof(T), (size_t) &result);
    return result;
}

auto decrypt_client_info(uint64_t encrypted_address, uint64_t game_base_address, uint64_t _last_key,
                         uint64_t peb) -> uint64_t {
    const auto Peb = peb;
    const auto baseModuleAddr = game_base_address;
    uint64_t rax, rbx, rcx, rdx, r8, rdi, rsi, r9, r10, r11, r12, r13, r14 = 0;

//    rdx = baseModuleAddr; //new
    rbx = encrypted_address;

    r8 = Peb;
    rax = rbx;
    rax >>= 0x9;
    rbx ^= rax;
    rax = rbx;
    rax >>= 0x12;
    rbx ^= rax;
    rax = (baseModuleAddr + 0x773);
//    rdx -= rax;
    rcx = rbx;
//    rdx &= 0xffffffffc0000000;
    rcx >>= 0x24;
    rcx ^= rbx;
//    rdx <<= 0x10;
    rdx = 0;
    rdx ^= read<QWORD>(baseModuleAddr + 0x5D53127);
    rax = (baseModuleAddr + 0x18E4);
    rax = (~rax);
    rax ^= r8;
    rcx -= rax;
    rax = 0xFDCD016155DFE5D9;
    rcx += r8;
    rdx = _byteswap_uint64(rdx);
    rbx = read<QWORD>(rdx + 0x11);
    rbx *= rcx;
    rbx *= rax;
    rax = 0x59DC5FB6344F14D9;
    rbx -= rax;
    return rbx;
}

typedef uint64_t UINT64;

auto decrypt_client_base(uint64_t encrypted_address, uint64_t game_base_address, uint64_t last_key,
                         uint64_t peb) -> uint64_t {
    // Default decl
    uint64_t rax, rbx, rcx, rdx, r8, rdi, rsi, r9, r10, r11, r12, r13, r14, r15 = 0;

    rax = encrypted_address;

    const auto clientBaseSwitch = _byteswap_uint64(~peb << 0x2A) & 0xf;

    rdi = ~peb;

    // To fix encryption from mole's dumper: remove read<QWORD>(rbp + x) and lines modifying it after and set it to zero

    switch (clientBaseSwitch) {
        case 0: {
            rax = rbx;
            rax >>= 0x9;
            rbx ^= rax;
            rax = rbx;
            rax >>= 0x12;
            rbx ^= rax;
            rax = (game_base_address + 0x773);
            rcx = rbx;
            rcx >>= 0x24;
            rcx ^= rbx;
            rax = (game_base_address + 0x18E4);
            rax = (~rax);
            rax ^= r8;
            rcx -= rax;
            rax = 0xFDCD016155DFE5D9;
            rcx += r8;
            rdx = _byteswap_uint64(rdx);
            rbx = read<QWORD>(rdx + 0x11);
            rbx *= rcx;
            rbx *= rax;
            rax = 0x59DC5FB6344F14D9;
            rbx -= rax;
            rbx = game_base_address;
            rsi = (game_base_address + 0xADF);
            r8 = 0x5B66AA5AA7F6DD97;
            r9 = read<QWORD>(game_base_address + 0x5D53159);
            rcx = 0x1E78819176826C52;
            r8 ^= rcx;
            rcx = rax;
            rcx >>= 0x1E;
            rax ^= rcx;
            rcx = rax;
            rcx >>= 0x3C;
            rax ^= rcx;
            rcx = 0x54A398D54B091215;
            rax += rcx;
            rcx = 0x5CE36782FB392177;
            r8 ^= rcx;
            rcx = 0x34A5C9D1443FA317;
            rax -= rcx;
            rcx = 0xEC5A88CC7AC204A5;
            r8 ^= rcx;
            rcx = rbx;
            rcx -= rdi;
            rax += rcx;
            rcx = 0x267A02604B2346A7;
            r8 ^= rcx;
            rcx = 0x9E360116C961CA29;
            r8 ^= rcx;
            rcx = 0x540766CAE9F8E8B9;
            r8 ^= rcx;
            rcx = 0x7EB594D9A1E50AED;
            rax *= rcx;
            rax -= rbx;
            rcx = 0x2625713BAACE72E3;
            rax += 0xFFFFFFFF9B3100EA;
            r8 ^= rcx;
            rax += rdi;
//            rcx = read<QWORD>(rbp + 0xd8);
//            rcx -= rsi;
//            rcx &= 0xffffffffc0000000;
            rcx = 0;
            rcx <<= 0x10;
            rcx ^= r9;
            rcx = (~rcx);
            rax *= read<QWORD>(rcx + 0xd);
            return rax;
            break;
        }

        case 1: {
            rbx = game_base_address;
            rsi = (game_base_address + 0xADF);
            r9 = read<QWORD>(game_base_address + 0x5D53159);
//            rcx = read<QWORD>(rbp + 0xd8);
//            rcx -= rsi;
//            rcx &= 0xffffffffc0000000;
            rcx = 0;
            rcx <<= 0x10;
            rcx ^= r9;
            rcx = (~rcx);
            rax *= read<QWORD>(rcx + 0xd);
            rcx = rax;
            rcx >>= 0xC;
            rax ^= rcx;
            rcx = rax;
            rcx >>= 0x18;
            rax ^= rcx;
            rcx = rax;
            rcx >>= 0x30;
            rax ^= rcx;
            rax -= rdi;
            rax -= rbx;
            rax -= 0x82E3;
            rax ^= rbx;
            rcx = 0xF7C147EB647B3EB8;
            rax ^= rcx;
            rcx = 0x1E041F691B473E87;
            rax *= rcx;
            rcx = 0x2AA7F16B4E5E8B35;
            rax ^= rcx;
            rax -= rdi;
            return rax;
            break;
        }

        case 2: {
            r10 = read<QWORD>(game_base_address + 0x5D53159);
            rsi = (game_base_address + 0xADF);
            r15 = (game_base_address + 0xCB3C);
            rcx = 0xDAF2B099F6421E2B;
            rax *= rcx;
            rcx = rax;
            rcx >>= 0x1B;
            rax ^= rcx;
            rcx = rax;
            rcx >>= 0x36;
            rax ^= rcx;
            rcx = 0xC173D5117D91F9FE;
            rax ^= rcx;
            rcx = rdi;
            rcx *= r15;
            rax += rcx;
//            rdx = read<QWORD>(rbp + 0xd8);
//            rdx -= rsi;
            rcx = rax;
//            rdx &= 0xffffffffc0000000;
            rdx = 0;
            rcx -= rdi;
            rdx <<= 0x10;
            rdx ^= r10;
            rdx = (~rdx);
            rax = read<QWORD>(rdx + 0xd);
            rax *= rcx;
            rcx = 0xE6D68530E12586BF;
            rax *= rcx;
            rax += rdi;
            return rax;
            break;
        }

        case 3: {
            r10 = read<QWORD>(game_base_address + 0x5D53159);
            rsi = (game_base_address + 0xADF);
//            rdx = read<QWORD>(rbp + 0xd8);
//            rdx -= rsi;
//            rdx &= 0xffffffffc0000000;
            rdx = 0;
            rdx <<= 0x10;
            rcx = rax;
            rdx ^= r10;
            rcx -= rdi;
            rdx = (~rdx);
            rax = read<QWORD>(rdx + 0xd);
            rax *= rcx;
            rdx = (game_base_address + 0x78659C2C);
            rdx = (~rdx);
            rcx = rdi;
            rcx = (~rcx);
            rcx += rdi;
            rdx += rcx;
            rcx = (game_base_address + 0x1C58);
            rax += rcx;
            rax += rdx;
            rcx = rax;
            rcx >>= 0xC;
            rax ^= rcx;
            rcx = rax;
            rcx >>= 0x18;
            rax ^= rcx;
            rcx = rax;
            rcx >>= 0x30;
            rax ^= rcx;
            rcx = 0x7CAA129FE480BCA9;
            rax *= rcx;
            rcx = 0x14731C734A59CBCE;
            rax += rcx;
            rcx = 0xE8AA5AC3983629B3;
            rax *= rcx;
            return rax;
            break;
        }

        case 4: {
            r10 = read<QWORD>(game_base_address + 0x5D53159);
            rbx = game_base_address;
            rsi = (game_base_address + 0xADF);
            rcx = rax;
            rcx >>= 0xD;
            rax ^= rcx;
            rcx = rax;
            rcx >>= 0x1A;
            rax ^= rcx;
            rdx = rdi;
            rdx = (~rdx);
            rdx -= rbx;
            rdx -= 0x7C7D8FDF;
            rcx = rax;
            rcx >>= 0x34;
            rdx ^= rcx;
            rax ^= rdx;
            rcx = 0x63846E25322C56AC;
            rax += rcx;
            rdx = rdi;
            rdx = (~rdx);
            rcx = (game_base_address + 0xC78B);
            rax += rcx;
            rax += rdx;
            rax ^= rdi;
            rcx = 0x59C27CB41F0B3CC3;
            rax *= rcx;
//            rcx = read<QWORD>(rbp + 0xd8);
//            rcx -= rsi;
//            rcx &= 0xffffffffc0000000;
            rcx = 0;
            rcx <<= 0x10;
            rcx ^= r10;
            rcx = (~rcx);
            rcx = read<QWORD>(rcx + 0xd);
            rax *= rcx;
            rcx = 0x2C92DEA84ED665D6;
            rax -= rcx;
            return rax;
            break;
        }

        case 5: {
            r11 = read<QWORD>(game_base_address + 0x5D53159);
            rbx = game_base_address;
            rsi = (game_base_address + 0xADF);
            rax += rdi;
            rcx = 0xFFFFFFFFCC00379F;
            rcx -= rdi;
            rcx -= rbx;
            rax += rcx;
//            rdx = read<QWORD>(rbp + 0xd8);
            rcx = rax;
//            rdx -= rsi;
            rcx >>= 0x23;
            rcx ^= rax;
//            rdx &= 0xffffffffc0000000;
            rdx = 0;
            rdx <<= 0x10;
            rax = 0x49B35D88BDDB3CC0;
            rdx ^= r11;
            rdx = (~rdx);
            r8 = read<QWORD>(rdx + 0xd);
            rdx = rdi;
            rdx = (~rdx);
            r8 *= rcx;
            rax = 0xD9629355CC65726E;
            rcx = (game_base_address + 0x5EF6);
            rax = 0xF48DFD27B3499198;
            rax = rdi;
            rax ^= rcx;
            rcx = (game_base_address + 0x65866166);
            rax += rdi;
            rax += r8;
            r8 = (game_base_address + 0xF9D5);
            rax += rcx;
            rcx = r8;
            rcx = (~rcx);
            rdx *= rcx;
            rax ^= rdx;
            rcx = 0xB821344F9B9F347;
            rax *= rcx;
            return rax;
            break;
        }

        case 6: {
            rbx = game_base_address;
            rsi = (game_base_address + 0xADF);
            r9 = read<QWORD>(game_base_address + 0x5D53159);
            rcx = rax;
            rcx >>= 0x18;
            rax ^= rcx;
            rcx = rax;
            rcx >>= 0x30;
            rax ^= rcx;
            rcx = 0x3AD2C64DAAE9DE27;
            rax *= rcx;
            rcx = 0x9546576F9C7A5E70;
            rax ^= rcx;
            rcx = rax;
            rcx >>= 0xD;
            rax ^= rcx;
            rcx = rax;
            rcx >>= 0x1A;
            rax ^= rcx;
            rcx = rax;
            rcx >>= 0x34;
            rax ^= rcx;
//            rcx = read<QWORD>(rbp + 0xd8);
//            rcx -= rsi;
//            rcx &= 0xffffffffc0000000;
            rcx = 0;
            rcx <<= 0x10;
            rcx ^= r9;
            rcx = (~rcx);
            rax *= read<QWORD>(rcx + 0xd);
            rcx = rbx + 0xf052;
            rcx += rdi;
            rax += rcx;
            rax ^= rbx;
            rcx = 0x77F12CF68D3430B5;
            rax *= rcx;
            return rax;
            break;
        }

        case 7: {
            rbx = game_base_address;
            rsi = (game_base_address + 0xADF);
            r10 = read<QWORD>(game_base_address + 0x5D53159);
            rcx = 0x8ED4F11D1CE608E1;
            rax *= rcx;
            rcx = rax;
            rcx >>= 0xE;
            rax ^= rcx;
            rcx = rax;
            rcx >>= 0x1C;
            rax ^= rcx;
            rcx = rax;
            rcx >>= 0x38;
            rcx ^= rax;
            rax = 0xCB4A66557421845;
            rcx -= rdi;
            rax += rcx;
            rax += rbx;
//            rcx = read<QWORD>(rbp + 0xd8);
//            rcx -= rsi;
//            rcx &= 0xffffffffc0000000;
            rcx = 0;
            rcx <<= 0x10;
            rcx ^= r10;
            rcx = (~rcx);
            rcx = read<QWORD>(rcx + 0xd);
            rax *= rcx;
            rcx = (game_base_address + 0xFE66);
            rax += rdi;
            rax += rcx;
            rax -= rdi;
            return rax;
            break;
        }

        case 8: {
            r10 = read<QWORD>(game_base_address + 0x5D53159);
            rbx = game_base_address;
            rsi = (game_base_address + 0xADF);
            rcx = 0x22BA4D1DF67C6F4D;
            rax ^= rcx;
            rax -= rbx;
            rcx = rax;
            rcx >>= 0x1C;
            rax ^= rcx;
            rcx = rax;
            rcx >>= 0x38;
            rax ^= rcx;
//            rdx = read<QWORD>(rbp + 0xd8);
//            rdx -= rsi;
            rcx = rdi;
            rcx *= 0x7FF6958DA09B;
//            rdx &= 0xffffffffc0000000;
            rdx = 0;
            rcx += rax;
            rdx <<= 0x10;
            rdx ^= r10;
            rdx = (~rdx);
            rax = read<QWORD>(rdx + 0xd);
            rax *= rcx;
            rcx = rax;
            rcx >>= 0xE;
            rax ^= rcx;
            rcx = rax;
            rcx >>= 0x1C;
            rax ^= rcx;
            rcx = rax;
            rcx >>= 0x38;
            rax ^= rcx;
            rcx = 0x1C467A321224D71D;
            rax *= rcx;
            rcx = 0x5D812F5A69CC6B09;
            rax ^= rcx;
            return rax;
            break;
        }

        case 9: {
            rbx = game_base_address;
            rsi = (game_base_address + 0xADF);
            r11 = (game_base_address + 0xC8AB);
            r9 = read<QWORD>(game_base_address + 0x5D53159);
            rcx = 0xDB8D2AA510B3D017;
            rax *= rcx;
            rcx = 0x7F494617E8C33EDB;
            rax ^= rcx;
            rcx = 0xEF051302D7C5D443;
            rax *= rcx;
            rcx = rax;
            rcx >>= 0xE;
            rax ^= rcx;
            rcx = rax;
            rcx >>= 0x1C;
            rax ^= rcx;
            rcx = rax;
            rcx >>= 0x38;
            rax ^= rcx;
//            rcx = read<QWORD>(rbp + 0xd8);
//            rcx -= rsi;
//            rcx &= 0xffffffffc0000000;
            rcx = 0;
            rcx <<= 0x10;
            rcx ^= r9;
            rcx = (~rcx);
            rcx = read<QWORD>(rcx + 0xd);
            rcx *= rax;
            rax = r11;
            rax = (~rax);
            rax *= rdi;
            rcx += rax;
            rax = rcx + rbx * 2;
            return rax;
            break;
        }

        case 10: {
            r10 = read<QWORD>(game_base_address + 0x5D53159);
            rbx = game_base_address;
            rsi = (game_base_address + 0xADF);
            rcx = 0x5746AFB1E1155233;
            rax *= rcx;
            rax ^= rbx;
            rcx = rax;
            rcx >>= 0x6;
            rax ^= rcx;
            rcx = rax;
            rcx >>= 0xC;
            rax ^= rcx;
//            rdx = read<QWORD>(rbp + 0xd8);
//            rdx -= rsi;
            rcx = rax;
//            rdx &= 0xffffffffc0000000;
            rdx = 0;
            rcx >>= 0x18;
            rax ^= rcx;
            rdx <<= 0x10;
            rdx ^= r10;
            rdx = (~rdx);
            rcx = rax;
            rcx >>= 0x30;
            rcx ^= rax;
            rax = read<QWORD>(rdx + 0xd);
            rax *= rcx;
            rcx = 0x56DD85FA49785361;
            rax ^= rcx;
            rcx = (game_base_address + 0x7E6BCF0D);
            rax += rdi;
            rax += rcx;
            rcx = rax;
            rcx >>= 0xF;
            rax ^= rcx;
            rcx = rax;
            rcx >>= 0x1E;
            rax ^= rcx;
            rcx = rax;
            rcx >>= 0x3C;
            rax ^= rcx;
            return rax;
            break;
        }

        case 11: {
            r10 = read<QWORD>(game_base_address + 0x5D53159);
            rsi = (game_base_address + 0xADF);
            rbx = (game_base_address + 0x72DE3288);
//            rcx = read<QWORD>(rbp + 0xd8);
//            rcx -= rsi;
//            rcx &= 0xffffffffc0000000;
            rcx = 0;
            rcx <<= 0x10;
            rcx ^= r10;
            rcx = (~rcx);
            rax *= read<QWORD>(rcx + 0xd);
            rcx = 0x72B8A71E74CF6D66;
            rax ^= rcx;
            rax += rdi;
            rax += rdi;
            rcx = rdi;
            rcx = (~rcx);
            rcx += rbx;
            rax ^= rcx;
            rcx = 0x89E82B4C8580417B;
            rax ^= rcx;
            rcx = rax;
            rcx >>= 0x19;
            rax ^= rcx;
            rcx = rax;
            rcx >>= 0x32;
            rax ^= rcx;
            rcx = 0x2E2DD232D0329849;
            rax *= rcx;
            return rax;
            break;
        }

        case 12: {
            r10 = read<QWORD>(game_base_address + 0x5D53159);
            rbx = game_base_address;
            rsi = (game_base_address + 0xADF);
            rdx = rdi;
            rdx = (~rdx);
            rcx = (game_base_address + 0x345F);
            rcx = (~rcx);
            rdx *= rcx;
            rcx = 0x12B7E9DB12BF99DF;
            rax ^= rdx;
            rax ^= rcx;
            rcx = 0xAC1DAD327A257BEF;
            rax *= rcx;
            rcx = rax;
            rcx >>= 0x16;
            rax ^= rcx;
            rcx = rax;
            rcx >>= 0x2C;
            rax ^= rcx;
//            rcx = read<QWORD>(rbp + 0xd8);
//            rcx -= rsi;
//            rcx &= 0xffffffffc0000000;
            rcx = 0;
            rcx <<= 0x10;
            rcx ^= r10;
            rcx = (~rcx);
            rcx = read<QWORD>(rcx + 0xd);
            rax *= rcx;
            rax += rbx;
            rcx = rax;
            rcx >>= 0x23;
            rax ^= rcx;
            rcx = 0x4BF88342719B3DA2;
            rax -= rcx;
            return rax;
            break;
        }

        case 13: {
            r10 = read<QWORD>(game_base_address + 0x5D53159);
            rsi = (game_base_address + 0xADF);
            rbx = (game_base_address + 0xDB9A);
            rcx = 0x7DCBC5B71BD27FDD;
            rax *= rcx;
            rcx = rax;
            rcx >>= 0x16;
            rax ^= rcx;
            rcx = rax;
            rcx >>= 0x2C;
            rax ^= rcx;
//            rcx = read<QWORD>(rbp + 0xd8);
//            rcx -= rsi;
//            rcx &= 0xffffffffc0000000;
            rcx = 0;
            rcx <<= 0x10;
            rcx ^= r10;
            rcx = (~rcx);
            rax *= read<QWORD>(rcx + 0xd);
            rcx = rax;
            rcx >>= 0xD;
            rax ^= rcx;
            rcx = rax;
            rcx >>= 0x1A;
            rax ^= rcx;
            rcx = rax;
            rcx >>= 0x34;
            rax ^= rcx;
            rcx = rax;
            rcx >>= 0x19;
            rax ^= rcx;
            rcx = rax;
            rcx >>= 0x32;
            rax ^= rcx;
            rcx = 0xB4083BDB91FE0928;
            rax ^= rcx;
            rcx = rbx;
            rcx = (~rcx);
            rcx ^= rdi;
            rax -= rcx;
            rdx = rdi;
            rdx = (~rdx);
            rcx = (game_base_address + 0x19D72071);
            rcx = (~rcx);
            rdx *= rcx;
            rax += rdx;
            return rax;
            break;
        }

        case 14: {
            rsi = (game_base_address + 0xADF);
            rbx = (game_base_address + 0x620F4771);
            r10 = read<QWORD>(game_base_address + 0x5D53159);
//            rcx = read<QWORD>(rbp + 0xd8);
//            rcx -= rsi;
//            rcx &= 0xffffffffc0000000;
            rcx = 0;
            rcx <<= 0x10;
            rcx ^= r10;
            rcx = (~rcx);
            rcx = read<QWORD>(rcx + 0xd);
            rax *= rcx;
            rax += rdi;
            rcx = rax;
            rcx >>= 0x1F;
            rax ^= rcx;
            rcx = rax;
            rcx >>= 0x3E;
            rax ^= rcx;
            rcx = rdi;
            rcx = (~rcx);
            rcx += rbx;
            rax ^= rcx;
            rcx = 0xB76BA6C7B44160C7;
            rax *= rcx;
            rcx = 0xA70458DA692F0CFF;
            rax ^= rcx;
            rax ^= rdi;
            return rax;
            break;
        }

        case 15: {
            r10 = read<QWORD>(game_base_address + 0x5D53159);
            rbx = game_base_address;
            rsi = (game_base_address + 0xADF);
            r15 = (game_base_address + 0x4C194B5C);
            rax += rbx;
            rcx = rax;
            rcx >>= 0x1F;
            rax ^= rcx;
            rcx = rax;
            rcx >>= 0x3E;
            rax ^= rcx;
            rcx = rax;
            rcx >>= 0x20;
            rax ^= rcx;
            rcx = 0x70FA1695B4DFBE91;
            rax *= rcx;
            rdx = rdi;
            rdx = (~rdx);
            rdx ^= r15;
            rcx = rax;
            rax = 0x2A47881FB6E8A891;
            rax *= rcx;
            rax += rdx;
//            rcx = read<QWORD>(rbp + 0xd8);
//            rcx -= rsi;
//            rcx &= 0xffffffffc0000000;
            rcx = 0;
            rcx <<= 0x10;
            rcx ^= r10;
            rcx = (~rcx);
            rax *= read<QWORD>(rcx + 0xd);
            rcx = 0x2E438145BCC0937F;
            rax -= rcx;
            return rax;
            break;
        }
    }
    return 0;
}

auto
decrypt_bone_base(uint64_t encrypted_address, uint64_t game_base_address, uint64_t last_key, uint64_t peb) -> uint64_t {
    uint64_t rax, rbx, rcx, rdx, r8, rdi, rsi, r9, r10, r11, r12, r13, r14 = 0;

    const auto Peb = peb;
    const auto baseModuleAddr = game_base_address;

//    rax = peb;
//    rax <<= 0x24;
//    rax = _byteswap_uint64(rax);

    const auto enc_case = _byteswap_uint64(peb << 0x24) & 0xf;

    r8 = encrypted_address;

    rbx = peb;

    switch (enc_case) {
        case 0: {
            rdi = (baseModuleAddr + 0x17F);
            r10 = read<QWORD>(baseModuleAddr + 0x5D53227);
            rax = r8;
            rax >>= 0xE;
            r8 ^= rax;
            rax = r8;
            rax >>= 0x1C;
            r8 ^= rax;
            rax = r8;
            rax >>= 0x38;
            r8 ^= rax;
            rax = 0xDB6DC51F6FF98E5F;
            r8 ^= rax;
            rax = r8;
            rax >>= 0x24;
            r8 ^= rax;
            rax = 0x69631C05889FD3D3;
            r8 *= rax;
            rax = (baseModuleAddr + 0xA819);
            r8 += rbx;
            r8 += rax;
//            rax = read<QWORD>(rbp + 0xa8);
//            rax -= rdi;
//            rax &= 0xffffffffc0000000;
            rax = 0;
            rax <<= 0x10;
            rax ^= r10;
            rax = (~rax);
            r8 *= read<QWORD>(rax + 0x15);
            rax = 0x9C90F3A61F77E23F;
            r8 ^= rax;
            rax = (baseModuleAddr + 0x65E3C668);
            rax -= rbx;
            r8 += rax;
            return r8;
            break;
        }

        case 1: {
            rdi = (baseModuleAddr + 0x17F);
            r11 = (baseModuleAddr + 0x9A07);
            r9 = read<QWORD>(baseModuleAddr + 0x5D53227);
//            rax = read<QWORD>(rbp + 0xa8);
//            rax -= rdi;
//            rax &= 0xffffffffc0000000;
            rax = 0;
            rax <<= 0x10;
            rax ^= r9;
            rax = (~rax);
            rax = read<QWORD>(rax + 0x15);
            r8 *= rax;
            rax = baseModuleAddr;
            rax += 0x703B;
            r8 += rbx;
            rax += rbx;
            r8 ^= rax;
            rax = rbx;
            rax *= r11;
            r8 += rax;
            rax = r8;
            rax >>= 0x26;
            r8 ^= rax;
            rax = 0xB14714BB8CD3EB15;
            r8 ^= rax;
            rax = 0xCE3EB69CFF2A3703;
            r8 *= rax;
            rax = 0x47CA62ED16EF42C9;
            r8 *= rax;
            return r8;
            break;
        }

        case 2: {
            r10 = read<QWORD>(baseModuleAddr + 0x5D53227);
            rdi = (baseModuleAddr + 0x17F);
            rax = r8;
            rax >>= 0x1D;
            r8 ^= rax;
            rax = r8;
            rax >>= 0x3A;
            r8 ^= rax;
            rax = r8;
            rax >>= 0x1C;
            r8 ^= rax;
            rax = r8;
            rax >>= 0x38;
            r8 ^= rax;
            rax = baseModuleAddr;
            r8 += rax;
            rax = baseModuleAddr;
//            rcx = read<QWORD>(rbp + 0xa8);
            r8 -= rax;
//            rcx -= rdi;
            rax = 0xA69DD414A75785FB;
            rax *= r8;
//            rcx &= 0xffffffffc0000000;
            rcx = 0;
            r8 = 0x5089EAB950027EB;
            rax -= r8;
            rcx <<= 0x10;
            rcx ^= r10;
            rcx = (~rcx);
            r8 = read<QWORD>(rcx + 0x15);
            r8 *= rax;
            rax = 0x6EFD702FD391D695;
            r8 ^= rax;
            return r8;
            break;
        }

        case 3: {
            r10 = read<QWORD>(baseModuleAddr + 0x5D53227);
            rdi = (baseModuleAddr + 0x17F);
            rax = (baseModuleAddr + 0xDDBA);
            rax -= rbx;
            r8 += rax;
            rax = baseModuleAddr;
            r8 += rax;
            rax = (baseModuleAddr + 0xE8A1);
            rax = (~rax);
            r8 ^= rax;
            r8 ^= rbx;
            rax = 0x7C0A8AA44112229B;
            r8 ^= rax;
//            rax = read<QWORD>(rbp + 0xa8);
//            rax -= rdi;
//            rax &= 0xffffffffc0000000;
            rax = 0;
            rax <<= 0x10;
            rax ^= r10;
            rax = (~rax);
            rax = read<QWORD>(rax + 0x15);
            r8 *= rax;
            rax = 0x7B9111E7A64BA71C;
            r8 += rax;
            rax = r8;
            rax >>= 0xE;
            r8 ^= rax;
            rax = r8;
            rax >>= 0x1C;
            r8 ^= rax;
            rax = r8;
            rax >>= 0x38;
            r8 ^= rax;
            rax = 0x5E1F02952B35CA9;
            r8 *= rax;
            return r8;
            break;
        }

        case 4: {
            r9 = read<QWORD>(baseModuleAddr + 0x5D53227);
            rdi = (baseModuleAddr + 0x17F);
            rax = r8;
            rax >>= 0x1B;
            r8 ^= rax;
            rax = r8;
            rax >>= 0x36;
            r8 ^= rax;
            rax = (baseModuleAddr + 0x607E2476);
            r8 += rbx;
            r8 += rax;
//            rax = read<QWORD>(rbp + 0xa8);
//            rax -= rdi;
//            rax &= 0xffffffffc0000000;
            rax = 0;
            rax <<= 0x10;
            rax ^= r9;
            rax = (~rax);
            r8 *= read<QWORD>(rax + 0x15);
            rax = r8;
            rax >>= 0x24;
            r8 ^= rax;
            rax = 0xE8BB39DE215ED178;
            r8 ^= rax;
            rax = 0xF8A4BF09543973F3;
            r8 ^= rax;
            return r8;
            break;
        }

        case 5: {
            rdi = (baseModuleAddr + 0x17F);
            r9 = read<QWORD>(baseModuleAddr + 0x5D53227);
            rax = 0x5F99F14E0A3362CB;
            r8 -= rax;
//            rax = read<QWORD>(rbp + 0xa8);
//            rax -= rdi;
//            rax &= 0xffffffffc0000000;
            rax = 0;
            rax <<= 0x10;
            rax ^= r9;
            rax = (~rax);
            r8 *= read<QWORD>(rax + 0x15);
            rax = r8;
            rax >>= 0xA;
            r8 ^= rax;
            rax = r8;
            rax >>= 0x14;
            r8 ^= rax;
            rax = r8;
            rax >>= 0x28;
            r8 ^= rax;
            rax = r8;
            rax >>= 0x3;
            r8 ^= rax;
            rax = r8;
            rax >>= 0x6;
            r8 ^= rax;
            rax = r8;
            rax >>= 0xC;
            r8 ^= rax;
            rax = r8;
            rax >>= 0x18;
            r8 ^= rax;
            rax = r8;
            rax >>= 0x30;
            r8 ^= rax;
            rax = 0xB2F087E6E9D9B5C5;
            r8 *= rax;
            r8 ^= rbx;
            rax = (baseModuleAddr + 0x3BCFF4A8);
            r8 ^= rax;
            rax = 0x2ED872D7D48F35FC;
            r8 ^= rax;
            r8 -= rbx;
            return r8;
            break;
        }

        case 6: {
            rdi = (baseModuleAddr + 0x17F);
            r10 = read<QWORD>(baseModuleAddr + 0x5D53227);
            r8 -= rbx;
//            rax = read<QWORD>(rbp + 0xa8);
//            rax -= rdi;
//            rax &= 0xffffffffc0000000;
            rax = 0;
            rax <<= 0x10;
            rax ^= r10;
            rax = (~rax);
            r8 *= read<QWORD>(rax + 0x15);
            rax = 0xEC6A957A16FB4691;
            r8 *= rax;
            rax = (baseModuleAddr + 0x41CE59F5);
            rax = (~rax);
            r8 -= rbx;
            r8 += rax;
            rax = 0xEA98D92147B2410;
            r8 ^= rax;
            rcx = rbx;
            rax = (baseModuleAddr + 0x9C0A);
            rcx *= rax;
            rax = 0x54B0C3018D872D6A;
            rax += r8;
            r8 = rcx;
            r8 ^= rax;
            rax = r8;
            rax >>= 0x14;
            r8 ^= rax;
            rax = r8;
            rax >>= 0x28;
            r8 ^= rax;
            return r8;
            break;
        }

        case 7: {
            rdi = (baseModuleAddr + 0x17F);
            r9 = read<QWORD>(baseModuleAddr + 0x5D53227);
            rax = baseModuleAddr;
            r8 -= rax;
            rax = 0xF7813480A8847E2;
            r8 += rax;
            r8 += rbx;
            rax = baseModuleAddr;
            r8 -= rax;
            rax = 0xEE03F1DCC34AA95D;
            r8 *= rax;
            rax = r8;
            rax >>= 0xD;
            r8 ^= rax;
            rax = r8;
            rax >>= 0x1A;
            r8 ^= rax;
            rax = r8;
            rax >>= 0x34;
            r8 ^= rax;
            rax = rbx;
            rax *= 0x7FF6F3217F04;
            r8 += rax;
//            rax = read<QWORD>(rbp + 0xa8);
//            rax -= rdi;
//            rax &= 0xffffffffc0000000;
            rax = 0;
            rax <<= 0x10;
            rax ^= r9;
            rax = (~rax);
            r8 *= read<QWORD>(rax + 0x15);
            rax = 0xEE2FB976331745B3;
            r8 *= rax;
            return r8;
            break;
        }

        case 8: {
            rdi = (baseModuleAddr + 0x17F);
            r10 = read<QWORD>(baseModuleAddr + 0x5D53227);
            rax = r8;
            rax >>= 0x1F;
            r8 ^= rax;
            rax = r8;
            rax >>= 0x3E;
            r8 ^= rax;
//            rax = read<QWORD>(rbp + 0xa8);
//            rax -= rdi;
//            rax &= 0xffffffffc0000000;
            rax = 0;
            rax <<= 0x10;
            rax ^= r10;
            rax = (~rax);
            r8 *= read<QWORD>(rax + 0x15);
            r8 ^= rbx;
            rax = (baseModuleAddr + 0x58BAB0D9);
            r8 ^= rax;
            rax = 0x4EDC74E4B3B219AD;
            r8 -= rax;
            rax = r8;
            rax >>= 0x1C;
            r8 ^= rax;
            rax = r8;
            rax >>= 0x38;
            r8 ^= rax;
            rax = 0x99FF61775E98445B;
            r8 *= rax;
            r8 -= rbx;
            rax = 0x79419A9873DBF25;
            r8 -= rax;
            return r8;
            break;
        }

        case 9: {
            rdi = (baseModuleAddr + 0x17F);
            r10 = read<QWORD>(baseModuleAddr + 0x5D53227);
            rax = 0x94784A058C8BFF8C;
            r8 ^= rax;
            rax = (baseModuleAddr + 0x3680);
            rax -= rbx;
            r8 += rax;
//            rax = read<QWORD>(rbp + 0xa8);
//            rax -= rdi;
//            rax &= 0xffffffffc0000000;
            rax = 0;
            rax <<= 0x10;
            rax ^= r10;
            rax = (~rax);
            rax = read<QWORD>(rax + 0x15);
            rax *= 0x6C46997512C07CA1;
            r8 *= rax;
            rax = r8;
            rax >>= 0x11;
            r8 ^= rax;
            rax = r8;
            rax >>= 0x22;
            r8 ^= rax;
            rax = r8;
            rax >>= 0x6;
            r8 ^= rax;
            rax = r8;
            rax >>= 0xC;
            r8 ^= rax;
            rax = r8;
            rax >>= 0x18;
            r8 ^= rax;
            rax = r8;
            rax >>= 0x30;
            r8 ^= rax;
            rcx = r8;
            rcx >>= 0x24;
            rax = (baseModuleAddr + 0x3195EF0B);
            rax = (~rax);
            rcx ^= rax;
            rcx ^= rbx;
            r8 ^= rcx;
            return r8;
            break;
        }

        case 10: {
            r10 = read<QWORD>(baseModuleAddr + 0x5D53227);
            rdi = (baseModuleAddr + 0x17F);
            r8 ^= rbx;
            r8 += rbx;
            r8 ^= rbx;
            rax = r8;
            rax >>= 0x24;
            r8 ^= rax;
            rax = 0x2AA1E893F393A86B;
            r8 -= rax;
            rax = 0xF2FF86F8E4113D49;
            r8 *= rax;
//            rax = read<QWORD>(rbp + 0xa8);
//            rax -= rdi;
//            rax &= 0xffffffffc0000000;
            rax = 0;
            rax <<= 0x10;
            rax ^= r10;
            rax = (~rax);
            r8 *= read<QWORD>(rax + 0x15);
            rax = 0xD9CEE9206B4C9F61;
            r8 ^= rax;
            return r8;
            break;
        }

        case 11: {
            rdi = (baseModuleAddr + 0x17F);
            r10 = read<QWORD>(baseModuleAddr + 0x5D53227);
//            rcx = read<QWORD>(rbp + 0xa8);
//            rcx -= rdi;
//            rcx &= 0xffffffffc0000000;
            rcx = 0;
            rcx <<= 0x10;
            rax = r8;
            rcx ^= r10;
            rax >>= 0x25;
            rcx = (~rcx);
            rax ^= r8;
            r8 = read<QWORD>(rcx + 0x15);
            r8 *= rax;
            rcx = (baseModuleAddr + 0x3F35A35D);
            rax = rbx;
            rax = (~rax);
            rax *= rcx;
            rcx = (baseModuleAddr + 0x2AE2);
            r8 += rax;
            rcx = (~rcx);
            rax = baseModuleAddr;
            r8 += rax;
            rcx += rbx;
            r8 ^= rcx;
            rax = 0x6FFB66453BE204E4;
            r8 ^= rax;
            rax = 0x1485B285DFFDE8D5;
            r8 *= rax;
            return r8;
            break;
        }

        case 12: {
            rdi = (baseModuleAddr + 0x17F);
            r9 = read<QWORD>(baseModuleAddr + 0x5D53227);
            rax = r8;
            rax >>= 0x3;
            r8 ^= rax;
            rax = r8;
            rax >>= 0x6;
            r8 ^= rax;
            rax = r8;
            rax >>= 0xC;
            r8 ^= rax;
            rax = r8;
            rax >>= 0x18;
            r8 ^= rax;
            rax = r8;
            rax >>= 0x30;
            r8 ^= rax;
            rax = (baseModuleAddr + 0x67DB);
            rax = (~rax);
            rax *= rbx;
            r8 += rax;
            rax = r8;
            rax >>= 0x24;
            r8 ^= rax;
            rax = r8;
            rax >>= 0x21;
            r8 ^= rax;
            //rax = read<QWORD>(rbp + 0xa8);
            //rax -= rdi;
            //rax &= 0xffffffffc0000000;
            rax = 0;
            rax <<= 0x10;
            rax ^= r9;
            rax = (~rax);
            rax = read<QWORD>(rax + 0x15);
            r8 *= rax;
            rax = baseModuleAddr;
            r8 -= rax;
            rax = 0x77B19ED057AC8014;
            r8 += rax;
            rax = 0x98BF87B2095D2CBB;
            r8 *= rax;
            return r8;
            break;
        }

        case 13: {
            r10 = read<QWORD>(baseModuleAddr + 0x5D53227);
            rdi = (baseModuleAddr + 0x17F);
            r11 = baseModuleAddr;
            rax = rbx;
            rax = (~rax);
            rax -= r11;
            r11 = 0x78AC2BEAE5BEA70;
            rax += r11;
            r8 += rax;
            rax = r8;
            rax >>= 0x6;
            r8 ^= rax;
            rax = r8;
            rax >>= 0xC;
            r8 ^= rax;
            rax = r8;
            rax >>= 0x18;
            r8 ^= rax;
            rcx = rbx;
            rcx = (~rcx);
            rax = (baseModuleAddr + 0x5131AE7D);
            rcx += rax;
            rax = r8;
            rax >>= 0x30;
            rcx ^= rax;
            r8 ^= rcx;
            rax = baseModuleAddr;
            r8 -= rax;
            rax = 0xF04E92A851804D7;
            r8 *= rax;
            rax = r8;
            rax >>= 0x9;
            r8 ^= rax;
            rax = r8;
            rax >>= 0x12;
            r8 ^= rax;
            rax = r8;
            rax >>= 0x24;
            r8 ^= rax;
//            rax = read<QWORD>(rbp + 0xa8);
//            rax -= rdi;
//            rax &= 0xffffffffc0000000;
            rax = 0;
            rax <<= 0x10;
            rax ^= r10;
            rax = (~rax);
            r8 *= read<QWORD>(rax + 0x15);
            return r8;
            break;
        }

        case 14: {
            rdi = (baseModuleAddr + 0x17F);
            r11 = read<QWORD>(baseModuleAddr + 0x5D53227);
            rax = r8;
            rax >>= 0xC;
            r8 ^= rax;
            rax = r8;
            rax >>= 0x18;
            r8 ^= rax;
            rcx = r8;
//            rdx = read<QWORD>(rbp + 0xa8);
//            rdx -= rdi;
            rcx >>= 0x30;
            rcx ^= r8;
//            rdx &= 0xffffffffc0000000;
            rdx = 0;
            rdx <<= 0x10;
            r8 = (baseModuleAddr + 0x44179748);
            rdx ^= r11;
            rax = 0xF777B93C4B0F545F;
            rcx *= rax;
            rdx = (~rdx);
            rax = rbx;
            rax = (~rax);
            rax *= r8;
            r8 = read<QWORD>(rdx + 0x15);
            rcx ^= rax;
            rax = 0xFDB595C779EB2F4A;
            r8 *= rcx;
            r8 ^= rax;
            rax = r8;
            rax >>= 0x1C;
            r8 ^= rax;
            rax = r8;
            rax >>= 0x38;
            r8 ^= rax;
            rax = baseModuleAddr;
            r8 += rax;
            rax = 0x65DFC1DD6F4EECAF;
            r8 *= rax;
            return r8;
            break;
        }

        case 15: {
            rdi = (baseModuleAddr + 0x17F);
            r10 = read<QWORD>(baseModuleAddr + 0x5D53227);
            rax = r8;
            rax >>= 0x11;
            r8 ^= rax;
            rax = r8;
            rax >>= 0x22;
            r8 ^= rax;
            rcx = rbx;
            rcx = (~rcx);
            rax = (baseModuleAddr + 0x944);
            rax = (~rax);
            rcx += rax;
            rax = baseModuleAddr;
            rcx -= rax;
            r8 += rcx;
            rax = 0xDC39EE1A2113255;
            r8 ^= rax;
            rax = 0x629AF63F4098E66C;
            r8 -= rax;
//            rax = read<QWORD>(rbp + 0xa8);
//            rax -= rdi;
//            rax &= 0xffffffffc0000000;
            rax = 0;
            rax <<= 0x10;
            rax ^= r10;
            rax = (~rax);
            r8 *= read<QWORD>(rax + 0x15);
            rax = r8;
            rax >>= 0x10;
            r8 ^= rax;
            rax = r8;
            rax >>= 0x20;
            r8 ^= rax;
            rax = 0x7AD7FEB69994060B;
            r8 *= rax;
            return r8;
            break;
        }
    }
    return 0;
}

auto get_bone_index(uint64_t index, uint64_t game_base_address) -> uint64_t {
    uint64_t rax = 0, rbx = 0, rcx = 0, rdx = 0, r8 = 0, rdi = 0, r9 = 0, r10 = 0, r11 = 0, r12 = 0, r13 = 0, r14 = 0, rsi = 0, rsp = 0, rbp = 0, r15 = 0;
    const auto baseModuleAddr = game_base_address;
    rbx = index;

    rcx = rbx * 0x13C8;
    rax = 0xE16108FF1793EEB9;
    r11 = baseModuleAddr;
    rax = _umul128(rax, rcx, (QWORD *) &rdx);
    r10 = 0x8A63AB88AA8DD5E7;
    rdx >>= 0xD;
    rax = rdx * 0x2459;
    rcx -= rax;
    rax = 0xBB4776D52876E0DD;
    r8 = rcx * 0x2459;
    rax = _umul128(rax, r8, (QWORD *) &rdx);
    rdx >>= 0xD;
    rax = rdx * 0x2BBE;
    r8 -= rax;
    rax = 0x889ABF4CB4E4EB53;
    rax = _umul128(rax, r8, (QWORD *) &rdx);
    rax = 0xCCCCCCCCCCCCCCCD;
    rdx >>= 0xA;
    rcx = rdx * 0x77F;
    rax = _umul128(rax, r8, (QWORD *) &rdx);
    rdx >>= 0x3;
    rcx += rdx;
    rax = rcx + rcx * 4;
    rax <<= 0x2;
    rcx = r8 * 0x16;
    rcx -= rax;
    rax = read<uint16_t>(rcx + r11 * 1 + 0x5D58BD0);
    r8 = rax * 0x13C8;
    rax = r10;
    rax = _umul128(rax, r8, (QWORD *) &rdx);
    rax = r10;
    rdx >>= 0xC;
    rcx = rdx * 0x1D99;
    r8 -= rcx;
    r9 = r8 * 0x2B81;
    rax = _umul128(rax, r9, (QWORD *) &rdx);
    rdx >>= 0xC;
    rax = rdx * 0x1D99;
    r9 -= rax;
    rax = 0xBFA02FE80BFA02FF;
    rax = _umul128(rax, r9, (QWORD *) &rdx);
    rax = 0xFC0FC0FC0FC0FC1;
    rdx >>= 0x7;
    rcx = rdx * 0xAB;
    rax = _umul128(rax, r9, (QWORD *) &rdx);
    rdx >>= 0x2;
    rcx += rdx;
    rax = rcx * 0x82;
    rcx = r9 * 0x84;
    rcx -= rax;
    r15 = read<uint16_t>(rcx + r11 * 1 + 0x5D621C0);
    return r15;
}

auto get_visible_base(int32_t index, uint64_t game_base_address, uint64_t func_distribute,
                      uint64_t vis_function) -> uint64_t {
    for (int j = 4000; j >= 0; --j) {
        QWORD nIndex = (j + (j << 2)) << 0x6;
        QWORD BaseAddress = game_base_address + func_distribute + nIndex;
        QWORD cmpFunctionHeader = read<QWORD>(BaseAddress + 0x90);

        if (!cmpFunctionHeader) {
            continue;
        }

        auto h = cmpFunctionHeader - game_base_address;
        if (cmpFunctionHeader == game_base_address + vis_function) {
            QWORD ValidVisibleListBaseAddress = read<QWORD>(BaseAddress + 0x108); // Visible_ListHead
            if (!ValidVisibleListBaseAddress)
                continue;

            QWORD rdx = ValidVisibleListBaseAddress + (index * 9 + 0x14e) * 8;
            if (!rdx)
                continue;

            DWORD VisibleFlags = (rdx + 0x10) ^read<QWORD>(rdx + 0x14);
            if (!VisibleFlags)
                continue;

            DWORD v511 = VisibleFlags * (VisibleFlags + 2);
            if (!v511)
                continue;

            BYTE VisibleFlags1 = read<QWORD>(rdx + 0x10) ^v511 ^BYTE1(v511);

            if (VisibleFlags1 == 3) {
                return BaseAddress;
            }
        }
    }

    return 0;
}

// 0: not visible, 1: visible: 2: error
auto is_visible(int32_t index, uint64_t last_visible_offset) -> uint32_t {
    QWORD VisibleList = read<QWORD>(last_visible_offset + 0x108);
    if (!VisibleList)
        return 2;

    QWORD rdx = VisibleList + (index * 9 + 0x14E) * 8;
    if (!rdx)
        return 2;

    DWORD VisibleFlags = (rdx + 0x10) ^read<DWORD>(rdx + 0x14);
    if (!VisibleFlags)
        return 2;

    DWORD v511 = VisibleFlags * (VisibleFlags + 2);
    if (!v511)
        return 2;

    BYTE VisibleFlags1 = read<DWORD>(rdx + 0x10) ^v511 ^BYTE1(v511);
    if (VisibleFlags1 == 3) {
        return 1;
    }
    return 0;
}
