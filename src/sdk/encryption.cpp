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

// Defs for mole dumper
#define Read read
#define baseModuleAddr game_base_address
#define Peb peb
typedef uint64_t UINT64;

auto decrypt_client_info(uint64_t encrypted_address, uint64_t game_base_address, uint64_t _last_key,
                         uint64_t peb) -> uint64_t {
    uint64_t rax, rbx, rcx, rdx, r8, rdi, rsi, r9, r10, r11, r12, r13, r14 = 0;

    rbx = encrypted_address;

    rdx = ~peb;

    r8 = peb;
    rax = (game_base_address + 0x777B);
    r8 *= rax;
    rax = 0x1F8F946E8C369BB;
    rbx *= rax;
    r8 ^= rbx;
    rax = r8;
    rax >>= 0x28;
    r8 ^= rax;
    rax = r8;
    rax >>= 0xE;
    r8 ^= rax;
    rax = r8;
    rax >>= 0x1C;
    r8 ^= rax;
    rax = r8;
    rax >>= 0x38;
    r8 ^= rax;
    rax = (game_base_address + 0xFC0);
//    rcx -= rax;
    rax = r8;
//    rcx &= 0xffffffffc0000000;
    rax >>= 0x25;
//    rcx <<= 0x10;
    rcx = 0;
    rax ^= r8;
    rcx ^= read<QWORD>(game_base_address + 0x66FA0FC);
    rcx = (~rcx);
    rbx = read<QWORD>(rcx + 0x9);
    rbx *= rax;
    return rbx;
}


auto decrypt_client_base(uint64_t encrypted_address, uint64_t game_base_address, uint64_t last_key,
                         uint64_t peb) -> uint64_t {
    // Default decl
    uint64_t rax = 0, rbx = 0, rcx = 0, rdx = 0, r8 = 0, rdi = 0, rsi = 0, r9 = 0, r10 = 0, r11 = 0, r12 = 0, r13 = 0, r14 = 0, r15 = 0;

    rax = encrypted_address;

    auto decrypt_case = _rotl64(~peb, 0x25) & 0xF;

    rbx = ~peb;
    rdx = game_base_address;

    switch (decrypt_case) {
        case 0: {
            rax = (game_base_address + 0x777B);
            r8 *= rax;
            rax = 0x1F8F946E8C369BB;
            rbx *= rax;
            r8 ^= rbx;
            rax = r8;
            rax >>= 0x28;
            r8 ^= rax;
            rax = r8;
            rax >>= 0xE;
            r8 ^= rax;
            rax = r8;
            rax >>= 0x1C;
            r8 ^= rax;
            rax = r8;
            rax >>= 0x38;
            r8 ^= rax;
            rax = (game_base_address + 0xFC0);
            rcx -= rax;
            rax = r8;
            rcx &= 0xffffffffc0000000;
            rax >>= 0x25;
            rcx <<= 0x10;
            rax ^= r8;
            rcx ^= read<QWORD>(game_base_address + 0x66FA0FC);
            rcx = (~rcx);
            rbx = read<QWORD>(rcx + 0x9);
            rbx *= rax;
            rdi = (game_base_address + 0x1D4);
            r14 = (game_base_address + 0x3FF6);
            r8 = 0x2926E5D05E846783;
            r9 = read<QWORD>(game_base_address + 0x66FA12A);
            rcx = 0x7CD23AFF41271AD5;
            r8 ^= rcx;
            rcx = r14;
            rcx -= rbx;
            rax += rcx;
            rcx = 0xECDC0D68AF8122B5;
            r8 ^= rcx;
            rcx = rax;
            rcx >>= 0x1A;
            rax ^= rcx;
            rcx = rax;
            rcx >>= 0x34;
            rax ^= rcx;
            rcx = rax;
            rcx >>= 0x6;
            rax ^= rcx;
            rcx = 0x9088151123BFBEA4;
            r8 ^= rcx;
            rcx = rax;
            rcx >>= 0xC;
            rax ^= rcx;
            rcx = rax;
            rcx >>= 0x18;
            rax ^= rcx;
            rcx = rax;
            rcx >>= 0x30;
            rax ^= rcx;
            rcx = 0x92EE7B189DBAAB80;
            r8 ^= rcx;
            rcx = 0x890F42B7FCD615;
            rax *= rcx;
            rcx = 0x747F5AD7733203AB;
            r8 ^= rcx;
            rcx = rax;
            rcx >>= 0x20;
            rax ^= rcx;
//            rcx = read<QWORD>(rbp + 0x108);
//            rcx -= rdi;
//            rcx &= 0xffffffffc0000000;
            rcx = 0;
            rcx <<= 0x10;
            rcx ^= r9;
            rcx = (~rcx);
            rcx = read<QWORD>(rcx + 0x17);
            rax *= rcx;
            rcx = 0x71294A8B070B9839;
            rax -= rcx;
            rcx = 0xDDBC4EFBAA9F5E5B;
            r8 ^= rcx;
            rcx = 0xBF1E74D2D72983AB;
            rax *= rcx;
            return rax;
            break;
        }

        case 1: {
            r11 = read<QWORD>(game_base_address + 0x66FA12A);
            rdi = (game_base_address + 0x1D4);
            rdx = (game_base_address + 0x28554F16);
            rcx = rbx;
            rcx ^= rdx;
            rax -= rcx;
            rcx = rax;
            rcx >>= 0xE;
            rax ^= rcx;
            rcx = rax;
            rcx >>= 0x1C;
            rax ^= rcx;
            rcx = rax;
            rcx >>= 0x38;
            rax ^= rcx;
            rcx = rax;
            rcx >>= 0xA;
            rax ^= rcx;
            rcx = rax;
            rcx >>= 0x14;
            rax ^= rcx;
            rcx = rax;
            rcx >>= 0x28;
            rax ^= rcx;
            rcx = 0xE1FD3C86DB19EBF9;
            rax *= rcx;
//            r8 = read<QWORD>(rbp + 0x108);
            rdx = (game_base_address + 0x5D7E5CC0);
//            r8 -= rdi;
//            r8 &= 0xffffffffc0000000;
            r8 = 0;
            r8 <<= 0x10;
            r8 ^= r11;
            rcx = rbx;
            r8 = (~r8);
            rcx = (~rcx);
            rdx = (~rdx);
            rcx += rax;
            rdx += rcx;
            rcx = 0x18DB6BC94B2CBA7C;
            rax = read<QWORD>(r8 + 0x17);
            rax *= rdx;
            rax ^= rcx;
            rcx = 0x68C819A3C9078EC0;
            rax ^= rcx;
            return rax;
            break;
        }

        case 2: {
            r10 = read<QWORD>(game_base_address + 0x66FA12A);
            rdi = (game_base_address + 0x1D4);
            r15 = (game_base_address + 0xD51F);
            r11 = game_base_address;
            rcx = rax;
            rcx >>= 0x11;
            rax ^= rcx;
            rcx = rax;
            rcx >>= 0x22;
            rax ^= rcx;
//            rdx = read<QWORD>(rbp + 0x108);
//            rdx -= rdi;
//            rdx &= 0xffffffffc0000000;
            rdx = 0;
            rcx = rax + r11 * 1;
            rdx <<= 0x10;
            rdx ^= r10;
            rdx = (~rdx);
            rax = read<QWORD>(rdx + 0x17);
            rax *= rcx;
            rcx = 0x4DE64FAFA04AFCC3;
            rax *= rcx;
            rcx = r15;
            rcx = (~rcx);
            rcx += rbx;
            rax ^= rcx;
            rax -= rbx;
            rcx = 0x9EF4528D17D101CD;
            rax ^= rcx;
            return rax;
            break;
        }

        case 3: {
            rdi = (game_base_address + 0x1D4);
            r11 = game_base_address;
            r9 = read<QWORD>(game_base_address + 0x66FA12A);
            rcx = 0x51DF0317C63BA0B0;
            rax -= rcx;
            rcx = rax;
            rcx >>= 0x4;
            rax ^= rcx;
            rcx = rax;
            rcx >>= 0x8;
            rax ^= rcx;
            rcx = rax;
            rcx >>= 0x10;
            rax ^= rcx;
            rcx = rax;
            rcx >>= 0x20;
            rax ^= rcx;
            rcx = rax;
            rcx >>= 0xC;
            rax ^= rcx;
            rcx = rax;
            rcx >>= 0x18;
            rax ^= rcx;
            rcx = rax;
            rcx >>= 0x30;
            rax ^= rcx;
            rcx = 0x7B440B4A6B0A8EF5;
            rax *= rcx;
//            rcx = read<QWORD>(rbp + 0x108);
//            rcx -= rdi;
//            rcx &= 0xffffffffc0000000;
            rcx = 0;
            rcx <<= 0x10;
            rcx ^= r9;
            rcx = (~rcx);
            rcx = read<QWORD>(rcx + 0x17);
            rax *= rcx;
            rax -= rbx;
            rax ^= r11;
            rcx = 0x3762E5D919DF6CF0;
            rax -= rcx;
            return rax;
            break;
        }

        case 4: {
            rdi = (game_base_address + 0x1D4);
            r11 = game_base_address;
            r15 = (game_base_address + 0x455B9C25);
            r9 = read<QWORD>(game_base_address + 0x66FA12A);
            rcx = rbx;
            rcx ^= read<QWORD>(game_base_address + 0x1C3DD8A);
            rax += rcx;
//            rcx = read<QWORD>(rbp + 0x108);
//            rcx -= rdi;
//            rcx &= 0xffffffffc0000000;
            rcx = 0;
            rcx <<= 0x10;
            rcx ^= r9;
            rcx = (~rcx);
            rcx = read<QWORD>(rcx + 0x17);
            rcx *= 0xDC393A1CB26C59A9;
            rax *= rcx;
            rax -= rbx;
            rcx = rbx;
            rcx ^= r15;
            rax -= rcx;
            rcx = rax;
            rcx >>= 0x11;
            rax ^= rcx;
            rcx = rax;
            rcx >>= 0x22;
            rax ^= rcx;
            rax -= r11;
            rax += r11;
            return rax;
            break;
        }

        case 5: {
            rdi = (game_base_address + 0x1D4);
            r11 = (game_base_address + 0x739C6080);
            r9 = read<QWORD>(game_base_address + 0x66FA12A);
            rcx = 0xE56F47E25078E80C;
            rax ^= rcx;
            rcx = 0x36BCDD71AC89676F;
            rax *= rcx;
            rcx = rax;
            rcx >>= 0xD;
            rax ^= rcx;
            rcx = rax;
            rcx >>= 0x1A;
            rax ^= rcx;
            rcx = rax;
            rcx >>= 0x34;
            rax ^= rcx;
            rcx = r11;
            rcx = (~rcx);
            rcx ^= rbx;
            rax ^= rcx;
            rax += rbx;
            rcx = 0xC824B36FD4F56BF3;
            rax *= rcx;
//            rcx = read<QWORD>(rbp + 0x108);
//            rcx -= rdi;
//            rcx &= 0xffffffffc0000000;
            rcx = 0;
            rcx <<= 0x10;
            rcx ^= r9;
            rcx = (~rcx);
            rax *= read<QWORD>(rcx + 0x17);
            rcx = rax;
            rcx >>= 0xA;
            rax ^= rcx;
            rcx = rax;
            rcx >>= 0x14;
            rax ^= rcx;
            rcx = rax;
            rcx >>= 0x28;
            rax ^= rcx;
            return rax;
            break;
        }

        case 6: {
            r10 = read<QWORD>(game_base_address + 0x66FA12A);
            rdi = (game_base_address + 0x1D4);
            r11 = game_base_address;
            rcx = 0x2EBB8A785E1A856A;
            rax += rcx;
            rax ^= r11;
            rcx = 0xC5EE09076CC9FE1C;
            rax ^= rcx;
            rax -= rbx;
            rcx = rax;
            rcx >>= 0x1B;
            rax ^= rcx;
            rcx = rax;
            rcx >>= 0x36;
            rax ^= rcx;
            rcx = 0x1AEFC88777814F31;
            rax *= rcx;
//            rcx = read<QWORD>(rbp + 0x108);
//            rcx -= rdi;
//            rcx &= 0xffffffffc0000000;
            rcx = 0;
            rcx <<= 0x10;
            rcx ^= r10;
            rcx = (~rcx);
            rax *= read<QWORD>(rcx + 0x17);
            rax -= rbx;
            return rax;
            break;
        }

        case 7: {
            r10 = read<QWORD>(game_base_address + 0x66FA12A);
            rdi = (game_base_address + 0x1D4);
            r15 = (game_base_address + 0x39BD428F);
            rcx = 0x4A8E836720C9B049;
            rax += rcx;
            rax ^= rbx;
            rax ^= r15;
            rcx = 0x47ADAA0C40AA79CE;
            rax += rcx;
            rax += rbx;
            rcx = rax;
            rcx >>= 0x13;
            rax ^= rcx;
            rcx = rax;
            rcx >>= 0x26;
            rax ^= rcx;
            rcx = rax;
            rcx >>= 0x18;
            rax ^= rcx;
            rcx = rax;
            rcx >>= 0x30;
            rax ^= rcx;
            rcx = 0x7404B5F5DE776B17;
            rax *= rcx;
//            rcx = read<QWORD>(rbp + 0x108);
//            rcx -= rdi;
//            rcx &= 0xffffffffc0000000;
            rcx = 0;
            rcx <<= 0x10;
            rcx ^= r10;
            rcx = (~rcx);
            rax *= read<QWORD>(rcx + 0x17);
            return rax;
            break;
        }

        case 8: {
            rdi = (game_base_address + 0x1D4);
            r11 = game_base_address;
            r10 = read<QWORD>(game_base_address + 0x66FA12A);
            rdx = rbx;
            rcx = (game_base_address + 0x1818822A);
            rdx *= rcx;
            rcx = r11;
            rcx -= rdx;
            rax += rcx;
            rcx = 0xF3DCF6EBF3A3997;
            rax += rcx;
            rcx = 0x4C42D15E4A2708E5;
            rax *= rcx;
//            rcx = read<QWORD>(rbp + 0x108);
//            rcx -= rdi;
//            rcx &= 0xffffffffc0000000;
            rcx = 0;
            rcx <<= 0x10;
            rcx ^= r10;
            rcx = (~rcx);
            rax *= read<QWORD>(rcx + 0x17);
            rcx = 0x83DBAD3327E0A500;
            rax ^= rcx;
            rax -= rbx;
            rcx = rax;
            rcx >>= 0x12;
            rax ^= rcx;
            rcx = rax;
            rcx >>= 0x24;
            rax ^= rcx;
            return rax;
            break;
        }

        case 9: {
            rdi = (game_base_address + 0x1D4);
            r11 = game_base_address;
            r10 = read<QWORD>(game_base_address + 0x66FA12A);
            rcx = r11 + 0xf50;
            rcx += rbx;
            rax += rcx;
            rax ^= rbx;
//            rdx = read<QWORD>(rbp + 0x108);
//            rdx -= rdi;
//            rdx &= 0xffffffffc0000000;
            rdx = 0;
            rcx = 0x9475C968613A0C67;
            rdx <<= 0x10;
            rcx += rax;
            rdx ^= r10;
            rdx = (~rdx);
            rax = read<QWORD>(rdx + 0x17);
            rax *= rcx;
            rcx = (game_base_address + 0x6E91D3AB);
            rcx = (~rcx);
            rcx *= rbx;
            rax ^= rcx;
            rcx = 0x1A81BB2AD0B4F3AC;
            rax -= rcx;
            rcx = 0xBBB2C4BB8CE6593;
            rax *= rcx;
            rcx = rax;
            rcx >>= 0x19;
            rax ^= rcx;
            rcx = rax;
            rcx >>= 0x32;
            rax ^= rcx;
            return rax;
            break;
        }

        case 10: {
            r9 = read<QWORD>(game_base_address + 0x66FA12A);
            rdi = (game_base_address + 0x1D4);
            r11 = game_base_address;
            r15 = (game_base_address + 0x6EA15250);
            rax += rbx;
            rax *= 0x9BD059290DCB43D3;
            rcx = rbx;
            rcx = (~rcx);
            rcx ^= r15;
            rax -= rcx;
            rax ^= rbx;
            rax -= r11;
//            rcx = read<QWORD>(rbp + 0x108);
//            rcx -= rdi;
//            rcx &= 0xffffffffc0000000;
            rcx = 0;
            rcx <<= 0x10;
            rcx ^= r9;
            rcx = (~rcx);
            rax *= read<QWORD>(rcx + 0x17);
            rcx = rax;
            rcx >>= 0x8;
            rax ^= rcx;
            rcx = rax;
            rcx >>= 0x10;
            rax ^= rcx;
            rcx = rax;
            rcx >>= 0x20;
            rax ^= rcx;
            rax -= rbx;
            return rax;
            break;
        }

        case 11: {
            rdi = (game_base_address + 0x1D4);
            r11 = game_base_address;
            r10 = read<QWORD>(game_base_address + 0x66FA12A);
            rcx = rax;
            rcx >>= 0x14;
            rax ^= rcx;
            rcx = rax;
            rcx >>= 0x28;
            rax ^= rcx;
            rcx = 0x60FC131021EA9670;
            rax ^= rcx;
            rcx = r11 + 0x8054;
            rcx += rbx;
            rax += rcx;
            rax ^= r11;
//            rdx = read<QWORD>(rbp + 0x108);
//            rdx -= rdi;
//            rdx &= 0xffffffffc0000000;
            rdx = 0;
            rcx = rax;
            rdx <<= 0x10;
            rcx ^= r11;
            rdx ^= r10;
            rdx = (~rdx);
            rax = read<QWORD>(rdx + 0x17);
            rax *= rcx;
            rcx = 0x989F1826B9D2513F;
            rax *= rcx;
            return rax;
            break;
        }

        case 12: {
            r10 = read<QWORD>(game_base_address + 0x66FA12A);
            rdi = (game_base_address + 0x1D4);
            r11 = game_base_address;
            rcx = (game_base_address + 0x56E1284B);
            rcx = (~rcx);
            rcx -= rbx;
            rax ^= rcx;
            rcx = (game_base_address + 0xD4EC);
            rcx = (~rcx);
            rcx -= rbx;
            rax += rcx;
            rcx = 0xBBA27374E8361FEB;
            rax *= rcx;
            rcx = rax;
            rcx >>= 0x1C;
            rax ^= rcx;
            rcx = rax;
            rcx >>= 0x38;
            rax ^= rcx;
            rcx = r11 + 0x42c2;
            rcx += rbx;
            rax ^= rcx;
//            rcx = read<QWORD>(rbp + 0x108);
//            rcx -= rdi;
//            rcx &= 0xffffffffc0000000;
            rcx = 0;
            rcx <<= 0x10;
            rcx ^= r10;
            rcx = (~rcx);
            rax *= read<QWORD>(rcx + 0x17);
            rcx = (game_base_address + 0x4FE2BA2B);
            rdx = rbx;
            rax += rcx;
            rdx = (~rdx);
            rax += rdx;
            rcx = 0x1EE121203251119E;
            rax += rcx;
            return rax;
            break;
        }

        case 13: {
            rdi = (game_base_address + 0x1D4);
            r11 = game_base_address;
            r10 = read<QWORD>(game_base_address + 0x66FA12A);
//            rcx = read<QWORD>(rbp + 0x108);
//            rcx -= rdi;
//            rcx &= 0xffffffffc0000000;
            rcx = 0;
            rcx <<= 0x10;
            rcx ^= r10;
            rcx = (~rcx);
            rax *= read<QWORD>(rcx + 0x17);
            rax += rbx;
            rax -= r11;
            rcx = 0xF2C3607F255C85D7;
            rax *= rcx;
            rcx = 0xA0E2B3FEB404B52;
            rax ^= rcx;
            rcx = rbx;
            rcx *= 0x7FF7BA153B74;
            rax += rcx;
            rcx = rax;
            rcx >>= 0x4;
            rax ^= rcx;
            rcx = rax;
            rcx >>= 0x8;
            rax ^= rcx;
            rcx = rax;
            rcx >>= 0x10;
            rax ^= rcx;
            rcx = rax;
            rcx >>= 0x20;
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

        case 14: {
            rdi = (game_base_address + 0x1D4);
            r11 = game_base_address;
            r9 = read<QWORD>(game_base_address + 0x66FA12A);
            rax -= rbx;
            rax -= r11;
            rax -= 0x8DEB;
            rax ^= rbx;
//            rcx = read<QWORD>(rbp + 0x108);
//            rcx -= rdi;
//            rcx &= 0xffffffffc0000000;
            rcx = 0;
            rcx <<= 0x10;
            rcx ^= r9;
            rcx = (~rcx);
            rcx = read<QWORD>(rcx + 0x17);
            rcx *= 0x87F2757EC1B54FAB;
            rax *= rcx;
            rcx = rax;
            rcx >>= 0xD;
            rax ^= rcx;
            rcx = rax;
            rcx >>= 0x1A;
            rax ^= rcx;
            rcx = rax;
            rcx >>= 0x34;
            rax ^= rcx;
            rcx = (game_base_address + 0x7E28C7A5);
            rcx -= rbx;
            rax += rcx;
            rax -= r11;
            return rax;
            break;
        }

        case 15: {
            r10 = read<QWORD>(game_base_address + 0x66FA12A);
            rdi = (game_base_address + 0x1D4);
            rcx = 0x73482614CEAA9160;
            rax ^= rcx;
            rax += rbx;
            rcx = rax;
            rcx >>= 0xB;
            rax ^= rcx;
            rcx = rax;
            rcx >>= 0x16;
            rax ^= rcx;
            rcx = rax;
            rcx >>= 0x2C;
            rax ^= rcx;
            rcx = rax;
            rcx >>= 0x12;
            rax ^= rcx;
            rcx = rax;
            rcx >>= 0x24;
            rax ^= rcx;
//            rcx = read<QWORD>(rbp + 0x108);
//            rcx -= rdi;
//            rcx &= 0xffffffffc0000000;
            rcx = 0;
            rcx <<= 0x10;
            rcx ^= r10;
            rcx = (~rcx);
            rax *= read<QWORD>(rcx + 0x17);
            rcx = 0xFD678AA3934E2FC7;
            rax *= rcx;
            rcx = (game_base_address + 0x80E2);
            rax += rcx;
            return rax;
            break;
        }
    }
}

auto
decrypt_bone_base(uint64_t encrypted_address, uint64_t game_base_address, uint64_t last_key,
                  uint64_t peb) -> uint64_t {
    uint64_t rax, rbx, rcx, rdx, r8, rdi, rsi, r9, r10, r11, r12, r13, r14, r15;

    r11 = peb;
    rax = r11;
    rax <<= 0x2C;
    rax = _byteswap_uint64(rax);
    const auto enc_case = rax & 0xF;

//    r8 = encrypted_address;
    rdx = encrypted_address;

    switch (enc_case) {
        case 0: {
            r9 = read<QWORD>(game_base_address + 0x66FA1D2);
            r10 = game_base_address;
            rbx = (game_base_address + 0xE37);
            r15 = (game_base_address + 0x6FD0);
            r12 = (game_base_address + 0x4928);
            rax = r11;
            rax = (~rax);
            rdx ^= rax;
            rdx ^= r12;
            rax = rdx;
            rax >>= 0x1B;
            rdx ^= rax;
            rax = rdx;
            rax >>= 0x36;
            rdx ^= rax;
            rdx += r10;
            r13 = 0x6B51AAEB49186B7D;
            rax = r11;
            rax ^= r15;
            rax += r13;
            rdx += rax;
            rax = rdx;
            rax >>= 0x17;
            rdx ^= rax;
            rax = rdx;
            rax >>= 0x2E;
            rdx ^= rax;
//            rax = read<QWORD>(rbp + 0x4d8);
//            rax -= rbx;
//            rax &= 0xffffffffc0000000;
            rax = 0;
            rax <<= 0x10;
            rax ^= r9;
            rax = (~rax);
            rdx *= read<QWORD>(rax + 0x13);
            rax = 0xF4976C6B0405633;
            rdx *= rax;
//            r13 = read<QWORD>(game_base_address + 0x1540CC64);
//            rdx = r13;
            return rdx;
            break;
        }

        case 1: {
            rdx = 0x1CEB66A29554AA69;
            rdx = 0x4F6DCE9D;
            r9 = read<QWORD>(game_base_address + 0x66FA1D2);
            r10 = game_base_address;
            rbx = (game_base_address + 0xE37);
            r12 = (game_base_address + 0xB4F3);
            r13 = (game_base_address + 0x50E0C5AE);
//            rax = read<QWORD>(rbp + 0x4d8);
//            rax -= rbx;
//            rax &= 0xffffffffc0000000;
            rax = 0;
            rax <<= 0x10;
            rax ^= r9;
            rax = (~rax);
            rax = read<QWORD>(rax + 0x13);
            rax *= 0xB020852A8A1A69A1;
            rdx *= rax;
            rax = r11;
            rax *= r12;
            rdx += rax;
            rax = 0x655F0049DD0E44EE;
            rdx ^= rax;
            rdx -= r11;
            rdx += r13;
            rdx += r10;
            rax = rdx;
            rax >>= 0x11;
            rdx ^= rax;
            rax = rdx;
            rax >>= 0x22;
            rdx ^= rax;
            rax = rdx;
            rax >>= 0x2;
            rdx ^= rax;
            rax = rdx;
            rax >>= 0x4;
            rdx ^= rax;
            rax = rdx;
            rax >>= 0x8;
            rdx ^= rax;
            rax = rdx;
            rax >>= 0x10;
            rdx ^= rax;
            rax = rdx;
            rax >>= 0x20;
            rdx ^= rax;
            return rdx;
            break;
        }

        case 2: {
            r10 = game_base_address;
            rbx = (game_base_address + 0xE37);
            r12 = (game_base_address + 0x5E817FB4);
            r9 = read<QWORD>(game_base_address + 0x66FA1D2);
            rdx -= r10;
            rdx += 0xFFFFFFFFB881A882;
            rdx += r11;
            rax = rdx;
            rax >>= 0x15;
            rdx ^= rax;
            rax = rdx;
            rax >>= 0x2A;
            rdx ^= rax;
            rax = 0xCC223CDD20BE0F5E;
            rdx ^= rax;
            rax = 0x95AC10BE99AC11B;
            rdx += rax;
            rax = rdx;
            rax >>= 0x1E;
            rdx ^= rax;
            rax = rdx;
            rax >>= 0x3C;
            rdx ^= rax;
            rax = 0x7F766F0B82220F1D;
            rdx *= rax;
//            rax = read<QWORD>(rbp + 0x4d8);
//            rax -= rbx;
//            rax &= 0xffffffffc0000000;
            rax = 0;
            rax <<= 0x10;
            rax ^= r9;
            rax = (~rax);
            rdx *= read<QWORD>(rax + 0x13);
            rax = r11;
            rax ^= r12;
            rdx -= rax;
//            r13 = read<QWORD>(game_base_address + 0x1540CC64);
//            rdx = r13;
            return rdx;
            break;
        }

        case 3: {
            rdx += 0x3C10BC93;
            r9 = read<QWORD>(game_base_address + 0x66FA1D2);
            rbx = (game_base_address + 0xE37);
            r10 = (game_base_address + 0x113E);
            rcx = r10;
            rcx = (~rcx);
            rax = r11;
            rax = (~rax);
            rdx += rax;
            rdx += rcx;
            rax = rdx;
            rax >>= 0x9;
            rdx ^= rax;
            rax = rdx;
            rax >>= 0x12;
            rdx ^= rax;
            rax = rdx;
            rax >>= 0x24;
            rdx ^= rax;
//            rax = read<QWORD>(rbp + 0x4d8);
//            rax -= rbx;
//            rax &= 0xffffffffc0000000;
            rax = 0;
            rax <<= 0x10;
            rax ^= r9;
            rax = (~rax);
            rdx *= read<QWORD>(rax + 0x13);
            rdx -= r11;
            rax = rdx;
            rax >>= 0x11;
            rdx ^= rax;
            rax = rdx;
            rax >>= 0x22;
            rdx ^= rax;
            rax = 0x205CB87F06748E5E;
            rdx ^= rax;
            rax = 0x6645E2E5FC2CD35E;
            rdx ^= rax;
            rax = 0x9A0DF5A6C6252B3B;
            rdx *= rax;
//            r13 = read<QWORD>(game_base_address + 0x1540CC64);
//            rdx = r13;
            return rdx;
            break;
        }

        case 4: {
            r9 = read<QWORD>(game_base_address + 0x66FA1D2);
            rbx = (game_base_address + 0xE37);
            rax = rdx;
            rax >>= 0xF;
            rdx ^= rax;
            rax = rdx;
            rax >>= 0x1E;
            rdx ^= rax;
            rax = rdx;
            rax >>= 0x3C;
            rdx ^= rax;
            rax = rdx;
            rax >>= 0x11;
            rdx ^= rax;
            rax = rdx;
            rax >>= 0x22;
            rdx ^= rax;
            rax = 0xD9FFAE14578652B3;
            rdx *= rax;
            rax = rdx;
            rax >>= 0x12;
            rdx ^= rax;
            rax = rdx;
            rax >>= 0x24;
            rdx ^= rax;
            rax = 0x7874A7A272206886;
            rdx += rax;
            rax = 0x2F130B9105D79F06;
            rdx ^= rax;
//            rcx = read<QWORD>(rbp + 0x4d8);
            rax = (game_base_address + 0x40F67476);
//            rcx -= rbx;
            rax += r11;
            rax += rdx;
//            rcx &= 0xffffffffc0000000;
            rcx = 0;
            rcx <<= 0x10;
            rcx ^= r9;
            rcx = (~rcx);
            rdx = read<QWORD>(rcx + 0x13);
            rdx *= rax;
//            r13 = read<QWORD>(game_base_address + 0x1540CC64);
//            rdx = r13;
            return rdx;
            break;
        }

        case 5: {
            rdx = 0x6189FF649A0321EB;
//            rdx ^= none; FIXME
            r10 = game_base_address;
            rbx = (game_base_address + 0xE37);
            r12 = (game_base_address + 0x6BDC3032);
            r9 = read<QWORD>(game_base_address + 0x66FA1D2);
//            rcx = read<QWORD>(rbp + 0x4d8);
//            rcx -= rbx;
//            rcx &= 0xffffffffc0000000;
            rcx = 0;
            rcx <<= 0x10;
            rcx ^= r9;
            rax = r11;
            rax = (~rax);
            rcx = (~rcx);
            rax ^= r12;
            rax ^= rdx;
            rdx = read<QWORD>(rcx + 0x13);
            rdx *= rax;
            rax = 0x6BD28F77518D812B;
            rdx ^= rax;
            rax = 0x64D9B2D43E2B145F;
            rdx *= rax;
            rdx -= r10;
            rax = rdx;
            rax >>= 0xE;
            rdx ^= rax;
            rax = rdx;
            rax >>= 0x1C;
            rdx ^= rax;
            rax = rdx;
            rax >>= 0x38;
            rdx ^= rax;
            rax = 0x3FE7C020674E44DF;
            rdx -= r10;
            rdx ^= rax;
//            r13 = read<QWORD>(game_base_address + 0x1540CC64);
//            rdx = r13;
            return rdx;
            break;
        }

        case 6: {
            rbx = (game_base_address + 0xE37);
            r15 = (game_base_address + 0x249C1A05);
            r9 = read<QWORD>(game_base_address + 0x66FA1D2);
            rax = rdx;
            rax >>= 0x1F;
            rdx ^= rax;
            rax = rdx;
            rax >>= 0x3E;
            rdx ^= rax;
            rax = rdx;
            rax >>= 0x19;
            rdx ^= rax;
            rcx = r15;
            rcx = (~rcx);
            rax = rdx;
            rcx ^= r11;
            rax >>= 0x32;
            rdx ^= rax;
            rax = 0xF73C61F80EB487BF;
            rdx -= rcx;
            rdx *= rax;
            rax = 0x6B9122DD815955D6;
            rdx -= rax;
            rax = rdx;
            rax >>= 0xA;
            rdx ^= rax;
            rax = rdx;
            rax >>= 0x14;
            rdx ^= rax;
            rax = rdx;
            rax >>= 0x28;
            rdx ^= rax;
//            rax = read<QWORD>(rbp + 0x4d8);
//            rax -= rbx;
//            rax &= 0xffffffffc0000000;
            rax = 0;
            rax <<= 0x10;
            rax ^= r9;
            rax = (~rax);
            rdx *= read<QWORD>(rax + 0x13);
            rax = 0xC5D1C85CE995DE0;
            rdx ^= rax;
//            r13 = read<QWORD>(game_base_address + 0x1540CC64);
//            rdx = r13;
            return rdx;
            break;
        }

        case 7: {
            r10 = game_base_address;
            rbx = (game_base_address + 0xE37);
            r15 = (game_base_address + 0x584B373E);
            r8 = read<QWORD>(game_base_address + 0x66FA1D2);
            rax = rdx;
            rax >>= 0x13;
            rdx ^= rax;
            rax = rdx;
            rax >>= 0x26;
            rdx ^= rax;
            rax = 0x850FF6DC768ACC1F;
            rdx *= rax;
            rax = r15;
            rax = (~rax);
            rax *= r11;
            rdx ^= rax;
//            rax = read<QWORD>(rbp + 0x4d8);
//            rax -= rbx;
//            rax &= 0xffffffffc0000000;
            rax = 0;
            rax <<= 0x10;
            rax ^= r8;
            rax = (~rax);
            rdx *= read<QWORD>(rax + 0x13);
            rax = r11;
            rax -= r10;
            rdx += rax;
            rax = 0x2DAEAE791ED8A741;
            rdx *= rax;
            rax = 0x1AA6C69C36A0A32;
            rdx += rax;
//            r13 = read<QWORD>(game_base_address + 0x1540CC64);
//            rdx = r13;
            return rdx;
            break;
        }

        case 8: {
            rdx -= 0x4421EBFC;
            rdx = 0x2B97F057;
            r10 = game_base_address;
            rbx = (game_base_address + 0xE37);
            r8 = read<QWORD>(game_base_address + 0x66FA1D2);
            rax = 0xFD3D6E0DA1363B69;
            rdx *= rax;
            rax = rdx;
            rax >>= 0x27;
            rdx ^= rax;
//            rax = read<QWORD>(rbp + 0x4d8);
//            rax -= rbx;
//            rax &= 0xffffffffc0000000;
            rax = 0;
            rax <<= 0x10;
            rax ^= r8;
            rax = (~rax);
            rax = read<QWORD>(rax + 0x13);
            rax *= 0x38EB3F1ADD18D26B;
            rdx *= rax;
            rax = 0x36CD3D5317C7F877;
            rdx *= rax;
            rdx += r11;
            rdx = rdx + r10 * 2;
//            r13 = read<QWORD>(game_base_address + 0x1540CC64);
//            rdx = r13;
            return rdx;
            break;
        }

        case 9: {
            rbx = (game_base_address + 0xE37);
            r14 = (game_base_address + 0x68DD);
            r8 = read<QWORD>(game_base_address + 0x66FA1D2);
            rax = rdx;
            rax >>= 0x28;
            rdx ^= rax;
//            rax = read<QWORD>(rbp + 0x4d8);
//            rax -= rbx;
//            rax &= 0xffffffffc0000000;
            rax = 0;
            rax <<= 0x10;
            rax ^= r8;
            rax = (~rax);
            rdx *= read<QWORD>(rax + 0x13);
            rax = rdx;
            rax >>= 0x9;
            rdx ^= rax;
            rax = rdx;
            rax >>= 0x12;
            rdx ^= rax;
            rax = rdx;
            rax >>= 0x24;
            rdx ^= rax;
            rax = (game_base_address + 0xF187);
            rax += r11;
            rdx += rax;
            rax = 0x70210FD2BF4B98F5;
            rdx *= rax;
            rax = r14;
            rax ^= r11;
            rdx -= rax;
            rax = 0x8FB17DC73B500031;
            rdx ^= rax;
            rax = 0x7B742CBEF0A8CEB4;
            rdx -= rax;
//            r13 = read<QWORD>(game_base_address + 0x1540CC64);
//            rdx = r13;
            return rdx;
            break;
        }

        case 10: {
            rbx = (game_base_address + 0xE37);
            r15 = (game_base_address + 0xC863);
            r9 = read<QWORD>(game_base_address + 0x66FA1D2);
            rax = rdx;
            rax >>= 0x8;
            rdx ^= rax;
            rax = rdx;
//            rcx = read<QWORD>(rbp + 0x4d8);
            rax >>= 0x10;
//            rcx -= rbx;
            rdx ^= rax;
//            rcx &= 0xffffffffc0000000;
            rcx = 0;
            rcx <<= 0x10;
            rcx ^= r9;
            rcx = (~rcx);
            rax = rdx;
            rax >>= 0x20;
            rax ^= r15;
            rax ^= r11;
            rax ^= rdx;
            rdx = read<QWORD>(rcx + 0x13);
            rdx *= rax;
            rax = rdx;
            rax >>= 0x17;
            rdx ^= rax;
            rax = rdx;
            rax >>= 0x2E;
            rdx ^= rax;
            r14 = 0xA9BF7C6364F562C0;
            rax = (game_base_address + 0x124C);
            rax = (~rax);
            rax += r11;
            rax += r14;
            rdx += rax;
            rax = 0xE34BB6FB19203563;
            rdx *= rax;
//            r13 = read<QWORD>(game_base_address + 0x1540CC64);
//            rdx = r13;
            return rdx;
            break;
        }

        case 11: {
            r9 = read<QWORD>(game_base_address + 0x66FA1D2);
            r10 = game_base_address;
            rbx = (game_base_address + 0xE37);
            rax = rdx;
            rax >>= 0xB;
            rdx ^= rax;
            rax = rdx;
            rax >>= 0x16;
            rdx ^= rax;
            rax = rdx;
            rax >>= 0x2C;
            rdx ^= rax;
            rax = rdx;
            rax >>= 0x13;
            rdx ^= rax;
            rax = rdx;
            rax >>= 0x26;
            rdx ^= rax;
//            rcx = read<QWORD>(rbp + 0x4d8);
//            rcx -= rbx;
//            rcx &= 0xffffffffc0000000;
            rcx = 0;
            rcx <<= 0x10;
            rcx ^= r9;
            rax = 0xF533424C8FA58DCB;
            rax += rdx;
            rcx = (~rcx);
            rdx = read<QWORD>(rcx + 0x13);
            rdx *= rax;
            rdx ^= r10;
            rax = 0x65151ECEC4572FE8;
            rdx -= rax;
            rax = 0xBA211560381C467F;
            rdx *= rax;
            rax = (game_base_address + 0xD94E);
            rax += r11;
            rdx ^= rax;
//            r13 = read<QWORD>(game_base_address + 0x1540CC64);
//            rdx = r13;
            return rdx;
            break;
        }

        case 12: {
            r9 = read<QWORD>(game_base_address + 0x66FA1D2);
            rbx = (game_base_address + 0xE37);
            r15 = (game_base_address + 0x5E9477BA);
//            rax = read<QWORD>(rbp + 0x4d8);
//            rax -= rbx;
//            rax &= 0xffffffffc0000000;
            rax = 0;
            rax <<= 0x10;
            rax ^= r9;
            rax = (~rax);
            rdx *= read<QWORD>(rax + 0x13);
            rax = rdx;
            rax >>= 0x27;
            rax ^= r11;
            rdx ^= rax;
            rax = rdx;
            rax >>= 0x1B;
            rdx ^= rax;
            rcx = rdx;
            rcx >>= 0x36;
            rdx ^= rcx;
            rax = r15;
            rax ^= r11;
            rdx -= rax;
            rax = 0x1A1143322C21280A;
            rdx -= rax;
            rax = 0xCAC628C59F15CD77;
            rdx ^= rax;
            rax = 0x9A24D948F64444F1;
            rdx *= rax;
//            r13 = read<QWORD>(game_base_address + 0x1540CC64);
//            rdx = r13;
            return rdx;
            break;
        }

        case 13: {
            r9 = read<QWORD>(game_base_address + 0x66FA1D2);
            r10 = game_base_address;
            rbx = (game_base_address + 0xE37);
            r13 = (game_base_address + 0x57CB);
            rax = (game_base_address + 0x4AF85AAF);
            rax += r11;
            rdx += rax;
            rax = rdx;
            rax >>= 0x8;
            rdx ^= rax;
            rax = rdx;
            rax >>= 0x10;
            rdx ^= rax;
            rax = rdx;
            rax >>= 0x20;
            rdx ^= rax;
//            rcx = read<QWORD>(rbp + 0x4d8);
//            rcx -= rbx;
//            rcx &= 0xffffffffc0000000;
            rcx = 0;
            rcx <<= 0x10;
            rcx ^= r9;
            rax = 0x225C533B97C362B5;
            rax += rdx;
            rcx = (~rcx);
            rdx = r13;
            rdx = (~rdx);
            rcx = read<QWORD>(rcx + 0x13);
            rax *= rcx;
            rax += r11;
            rdx += rax;
            rax = 0x6BB168604226F6C9;
            rdx *= rax;
            rcx = r11;
            rax = 0x8E1445FED9842DD5;
            rax += rdx;
            rcx = (~rcx);
            rcx -= r10;
            rdx = rcx + 0xffffffff92dbb574;
            rdx ^= rax;
//            r13 = read<QWORD>(game_base_address + 0x1540CC64);
//            rdx = r13;
            return rdx;
            break;
        }

        case 14: {
            r9 = read<QWORD>(game_base_address + 0x66FA1D2);
            r10 = game_base_address;
            rbx = (game_base_address + 0xE37);
            rax = rdx;
            rax >>= 0x22;
            rdx ^= rax;
//            rax = read<QWORD>(rbp + 0x4d8);
//            rax -= rbx;
//            rax &= 0xffffffffc0000000;
            rax = 0;
            rax <<= 0x10;
            rax ^= r9;
            rax = (~rax);
            rax = read<QWORD>(rax + 0x13);
            rdx *= rax;
            rdx -= r10;
            rdx += 0xFFFFFFFFFFFFEC4E;
            rdx += r11;
            rax = rdx;
            rax >>= 0x23;
            rdx ^= rax;
            rax = 0x31E15FA946FBB9CB;
            rdx += rax;
            rdx ^= r10;
            rax = 0x7794B1B9DEBB6519;
            rdx *= rax;
            rax = 0x412CCE90753E64FD;
            rdx += rax;
//            r13 = read<QWORD>(game_base_address + 0x1540CC64);
//            rdx = r13;
            return rdx;
            break;
        }

        case 15: {
            rbx = (game_base_address + 0xE37);
            r9 = read<QWORD>(game_base_address + 0x66FA1D2);
//            rax = read<QWORD>(rbp + 0x4d8);
//            rax -= rbx;
//            rax &= 0xffffffffc0000000;
            rax = 0;
            rax <<= 0x10;
            rax ^= r9;
            rax = (~rax);
            rax = read<QWORD>(rax + 0x13);
            rdx *= rax;
            rax = (game_base_address + 0x5DAB);
            rdx -= r11;
            rdx += rax;
            rax = (game_base_address + 0x83C2);
            rax += r11;
            rdx += rax;
//            r13 = read<QWORD>(game_base_address + 0x1540CC64);
//            rdx = r13;
            return rdx;
            break;
        }
    }
    return 0;
}

auto get_bone_index(uint64_t index, uint64_t game_base_address) -> uint64_t {
    uint64_t rax = 0, rbx = 0, rcx = 0, rdx = 0, r8 = 0, rdi = 0, r9 = 0, r10 = 0, r11 = 0, r12 = 0, r13 = 0, r14 = 0, rsi = 0, rsp = 0, rbp = 0, r15 = 0;
    rbx = index;

    rcx = rbx * 0x13C8;
    rax = 0x1B6FEDBB492D6DC9;
    r11 = game_base_address;
    rax = _umul128(rax, rcx, (QWORD *) &rdx);
    rax = rcx;
    r10 = 0x9140938595D3AC2B;
    rax -= rdx;
    rax >>= 0x1;
    rax += rdx;
    rax >>= 0xC;
    rax = rax * 0x1CE7;
    rcx -= rax;
    rax = 0xE454A9CCAE878231;
    r8 = rcx * 0x1CE7;
    rax = _umul128(rax, r8, (QWORD *) &rdx);
    rax = r8;
    rax -= rdx;
    rax >>= 0x1;
    rax += rdx;
    rax >>= 0xD;
    rax = rax * 0x21D4;
    r8 -= rax;
    rax = 0xC7CE0C7CE0C7CE0D;
    rax = _umul128(rax, r8, (QWORD *) &rdx);
    rax = 0x70FE3C070FE3C071;
    rdx >>= 0x6;
    rcx = rdx * 0x52;
    rax = _umul128(rax, r8, (QWORD *) &rdx);
    rdx >>= 0x6;
    rcx += rdx;
    rax = rcx * 0x122;
    rcx = r8 * 0x124;
    rcx -= rax;
    rax = Read<uint16_t>(rcx + r11 * 1 + 0x6703B60);
    r8 = rax * 0x13C8;
    rax = r10;
    rax = _umul128(rax, r8, (QWORD *) &rdx);
    rax = r10;
    rdx >>= 0xC;
    rcx = rdx * 0x1C33;
    r8 -= rcx;
    r9 = r8 * 0x327E;
    rax = _umul128(rax, r9, (QWORD *) &rdx);
    rdx >>= 0xC;
    rax = rdx * 0x1C33;
    r9 -= rax;
    rax = 0xF4898D5F85BB3951;
    rax = _umul128(rax, r9, (QWORD *) &rdx);
    rax = 0x3159721ED7E75347;
    rdx >>= 0x7;
    rcx = rdx * 0x86;
    rax = _umul128(rax, r9, (QWORD *) &rdx);
    rdx >>= 0x4;
    rcx += rdx;
    rax = rcx * 0xA6;
    rcx = r9 * 0xA8;
    rcx -= rax;
    return rcx;
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
