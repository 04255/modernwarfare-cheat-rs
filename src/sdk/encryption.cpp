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
    uint64_t rax, rbx, rcx, rdx, r8, rdi, rsi, r9, r10, r11, r12, r13, r14 = 0;

    rbx = encrypted_address;

    rcx = peb; //?
    rax = 0x0AE288A0E01D68767;
    rbx *= rax;
    rax = (game_base_address + 0x2E2CF25D);
    rax = (~rax);
    rbx ^= rax;
    rbx ^= rcx;
//    rcx = read<QWORD>(rbp + 0xe8);
    rax = rbx;
    rax >>= 0x19;
    rbx ^= rax;
    rax = (game_base_address + 0x9C3);
//    rcx -= rax;
    rax = rbx;
//    rcx &= 0xffffffffc0000000;
    rcx = 0; //
    rax >>= 0x32;
    rax ^= rbx;
    rcx <<= 0x10;
    rcx ^= read<QWORD>(game_base_address + 0x5C420F4);
    rcx = _byteswap_uint64(rcx);
    rcx = read<QWORD>(rcx + 0x5);
    rcx *= rax;
    rax = rcx;
    rax >>= 0x1E;
    rcx ^= rax;
    rax = 0x1911773BD4DC7C85;
    rbx = rcx;
    rbx >>= 0x3C;
    rbx ^= rcx;
    rbx ^= rax;
    return rbx;
}

typedef uint64_t UINT64;

auto decrypt_client_base(uint64_t encrypted_address, uint64_t game_base_address, uint64_t last_key,
                         uint64_t peb) -> uint64_t {
    // Default decl
    uint64_t rax, rbx, rcx, rdx, r8, rdi, rsi, r9, r10, r11, r12, r13, r14, r15 = 0;

    rax = encrypted_address;

    const auto clientBaseSwitch = _rotl64(peb, 0x2E) & 0xF;

    rbx = peb;

    // To fix encryption from mole's dumper: remove read<QWORD>(rbp + x) and lines modifying it after and set it to zero

//    std::cout << std::hex << clientBaseSwitch << std::endl;

    switch (clientBaseSwitch) {
        case 0: {
            rbx *= rax;
            rax = (game_base_address + 0x2E2CF25D);
            rax = (~rax);
            rbx ^= rax;
            rbx ^= rcx;
            rax = rbx;
            rax >>= 0x19;
            rbx ^= rax;
            rax = (game_base_address + 0x9C3);
            rax = rbx;
            rax >>= 0x32;
            rax ^= rbx;
            rcx = _byteswap_uint64(rcx);
            rcx = read<QWORD>(rcx + 0x5);
            rcx *= rax;
            rax = rcx;
            rax >>= 0x1E;
            rcx ^= rax;
            rax = 0x1911773BD4DC7C85;
            rbx = rcx;
            rbx >>= 0x3C;
            rbx ^= rcx;
            rbx ^= rax;
            rdi = (game_base_address + 0x25A);
            rdx = (game_base_address + 0x414EC2BE);
            r15 = (game_base_address + 0xC94A);
            r11 = read<QWORD>(game_base_address + 0x5C42128);
            rcx = rax;
            rcx >>= 0x19;
            rax ^= rcx;
            rcx = rax;
            rcx >>= 0x32;
            rax ^= rcx;
            rcx = rax;
            rcx >>= 0x11;
            rax ^= rcx;
            rcx = rax;
            rcx >>= 0x22;
            rax ^= rcx;
//            r8 = read<QWORD>(rbp + 0xe8);
//            r8 -= rdi;
//            r8 &= 0xffffffffc0000000;
            r8 = 0;
            r8 <<= 0x10;
            rcx = rdx;
            r8 ^= r11;
            r8 = (~r8);
            rcx = (~rcx);
            rcx ^= rbx;
            rdx = rbx;
            rdx -= rcx;
            rdx += rax;
            rax = read<QWORD>(r8 + 0x5);
            rdx ^= rbx;
            rdx ^= r15;
            rax *= rdx;
            rcx = 0x5DC887A2CA47F36;
            rax ^= rcx;
            rcx = 0x3C998147D6BF8147;
            rax *= rcx;
            return rax;
            break;
        }

        case 1: {
            rdi = (game_base_address + 0x25A);
            r15 = (game_base_address + 0x4E73);
            r11 = game_base_address;
            r9 = read<QWORD>(game_base_address + 0x5C42128);
            rcx = rbx;
            rcx ^= r15;
            rax += rcx;
            rcx = 0x80D5EEFBD7E10302;
            rax ^= rcx;
            rax += r11;
            rcx = rax;
            rcx >>= 0x7;
            rax ^= rcx;
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
            rcx >>= 0x1A;
            rax ^= rcx;
            rcx = rax;
            rcx >>= 0x34;
            rax ^= rcx;
            rcx = 0x9C4755BF7712BB6D;
            rax *= rcx;
//            rcx = read<QWORD>(rbp + 0xe8);
//            rcx -= rdi;
//            rcx &= 0xffffffffc0000000;
            rcx = 0;
            rcx <<= 0x10;
            rcx ^= r9;
            rcx = (~rcx);
            rax *= read<QWORD>(rcx + 0x5);
            rcx = 0xB0F91D8509F948F1;
            rax *= rcx;
            return rax;
            break;
        }

        case 2: {
            rdi = (game_base_address + 0x25A);
            r14 = (game_base_address + 0xC230);
            r15 = (game_base_address + 0x66C8);
            r10 = read<QWORD>(game_base_address + 0x5C42128);
//            rcx = read<QWORD>(rbp + 0xe8);
//            rcx -= rdi;
//            rcx &= 0xffffffffc0000000;
            rcx = 0;
            rcx <<= 0x10;
            rcx ^= r10;
            rcx = (~rcx);
            rax *= read<QWORD>(rcx + 0x5);
            rcx = 0xDDA4EE06B3F06EBA;
            rax ^= rcx;
            rcx = 0x3075D9D9B6C3F993;
            rax *= rcx;
            rcx = rax;
            rcx >>= 0x1C;
            rax ^= rcx;
            rcx = rax;
            rcx >>= 0x38;
            rax ^= rcx;
            rdx = rbx + 0x1;
            rcx = rbx;
            rcx *= r14;
            rdx *= r15;
            rdx -= rcx;
            rax += rdx;
            rcx = rax;
            rcx >>= 0xA;
            rax ^= rcx;
            rcx = rax;
            rcx >>= 0x14;
            rax ^= rcx;
            rcx = rax;
            rcx >>= 0x28;
            rax ^= rcx;
            rcx = 0x22291931FE48DFB4;
            rax ^= rcx;
            return rax;
            break;
        }

        case 3: {
            r10 = read<QWORD>(game_base_address + 0x5C42128);
            rdi = (game_base_address + 0x25A);
            rcx = 0xB94D546247AEF6C9;
            rax += rcx;
            rax += rbx;
            rcx = rax;
            rcx >>= 0x1C;
            rax ^= rcx;
            rcx = rax;
            rcx >>= 0x38;
            rax ^= rcx;
            rax -= rbx;
            rcx = 0xA56308CA267E73E1;
            rax ^= rbx;
            rax ^= rcx;
            rcx = 0x5FF27F5827B39F23;
            rax *= rcx;
//            rcx = read<QWORD>(rbp + 0xe8);
//            rcx -= rdi;
//            rcx &= 0xffffffffc0000000;
            rcx = 0;
            rcx <<= 0x10;
            rcx ^= r10;
            rcx = (~rcx);
            rax *= read<QWORD>(rcx + 0x5);
            return rax;
            break;
        }

        case 4: {
            r10 = read<QWORD>(game_base_address + 0x5C42128);
            rdi = (game_base_address + 0x25A);
            r11 = game_base_address;
            rcx = rax;
            rcx >>= 0x1D;
            rax ^= rcx;
            rcx = rax;
            rcx >>= 0x3A;
            rax ^= rcx;
            rcx = r11 + 0xd9f4;
            rcx += rbx;
            rax += rcx;
            rcx = rax;
            rcx >>= 0x24;
            rax ^= rcx;
//            rcx = read<QWORD>(rbp + 0xe8);
//            rcx -= rdi;
//            rcx &= 0xffffffffc0000000;
            rcx = 0;
            rcx <<= 0x10;
            rcx ^= r10;
            rcx = (~rcx);
            rcx = read<QWORD>(rcx + 0x5);
            rcx *= 0x11DC9FC0F33D5DEF;
            rax *= rcx;
            rax ^= r11;
            rdx = rbx;
            rdx = (~rdx);
            rcx = (game_base_address + 0x16ABC166);
            rcx = (~rcx);
            rdx += rcx;
            rcx = rax;
            rax = 0x85DAD31527A4047;
            rcx *= rax;
            rax = rdx;
            rax ^= rcx;
            return rax;
            break;
        }

        case 5: {
            rdi = (game_base_address + 0x25A);
            r11 = game_base_address;
            r10 = read<QWORD>(game_base_address + 0x5C42128);
            rax -= rbx;
            rcx = rax;
//            rdx = read<QWORD>(rbp + 0xe8);
            rcx ^= r11;
//            rdx -= rdi;
//            rdx &= 0xffffffffc0000000;
            rdx = 0;
            rdx <<= 0x10;
            rdx ^= r10;
            rdx = (~rdx);
            rax = read<QWORD>(rdx + 0x5);
            rax *= rcx;
            rax ^= r11;
            rcx = 0xE7230CFA47EB0F93;
            rax ^= rcx;
            rcx = 0x1653FC9A8E6D677D;
            rax *= rcx;
            rax ^= rbx;
            rcx = rax;
            rcx >>= 0x22;
            rax ^= rcx;
            return rax;
            break;
        }

        case 6: {
            rdi = (game_base_address + 0x25A);
            rdx = (game_base_address + 0x38F85CDE);
            r15 = (game_base_address + 0x12E2C0C7);
            r10 = read<QWORD>(game_base_address + 0x5C42128);
            rcx = rax;
            rcx >>= 0x13;
            rax ^= rcx;
            rcx = rax;
            rcx >>= 0x26;
            rax ^= rcx;
            rcx = 0x6171171014F5B4F9;
            rax *= rcx;
            rcx = rax;
            rcx >>= 0x1B;
            rax ^= rcx;
            rcx = rax;
            rcx >>= 0x36;
            rax ^= rcx;
            rcx = 0x3CFE143743C16E69;
            rax += rcx;
            rax ^= rbx;
            rax ^= rdx;
            rcx = 0x4A10419C8DFBA3E5;
            rax ^= rcx;
            rcx = rbx;
            rcx *= r15;
            rax -= rcx;
//            rcx = read<QWORD>(rbp + 0xe8);
//            rcx -= rdi;
//            rcx &= 0xffffffffc0000000;
            rcx = 0;
            rcx <<= 0x10;
            rcx ^= r10;
            rcx = (~rcx);
            rax *= read<QWORD>(rcx + 0x5);
            return rax;
            break;
        }

        case 7: {
            rdi = (game_base_address + 0x25A);
            r11 = game_base_address;
            r15 = (game_base_address + 0xDC31);
            r10 = read<QWORD>(game_base_address + 0x5C42128);
            rcx = rax;
            rcx >>= 0x1A;
            rax ^= rcx;
            rcx = rax;
            rcx >>= 0x34;
            rax ^= rcx;
//            rcx = read<QWORD>(rbp + 0xe8);
//            rcx -= rdi;
//            rcx &= 0xffffffffc0000000;
            rcx = 0;
            rcx <<= 0x10;
            rcx ^= r10;
            rcx = (~rcx);
            rax *= read<QWORD>(rcx + 0x5);
            rcx = (game_base_address + 0x38C30F41);
            rcx = (~rcx);
            rcx += rbx;
            rax += rcx;
            rcx = 0x34C5DBB740630199;
            rax *= rcx;
            rcx = 0x342F700E7A51A47;
            rax += rcx;
            rcx = rax;
            rcx >>= 0x21;
            rax ^= rcx;
            rcx = rbx;
            rcx -= r11;
            rcx -= 0x2D02;
            rax ^= rcx;
            rcx = rbx;
            rcx *= r15;
            rax ^= rcx;
            return rax;
            break;
        }

        case 8: {
            r10 = read<QWORD>(game_base_address + 0x5C42128);
            rdi = (game_base_address + 0x25A);
            r11 = game_base_address;
            rcx = rax;
            rcx >>= 0x11;
            rax ^= rcx;
            rcx = rax;
            rcx >>= 0x22;
            rax ^= rcx;
            rcx = rax;
            rcx >>= 0x24;
            rax ^= rcx;
            rcx = 0x8231D60C3E9A0CBE;
            rax ^= rcx;
            rax ^= r11;
            rcx = 0xCD7FBAC43F132D5;
            rax *= rcx;
            rcx = 0xFA8B0D8820433C90;
            rax ^= rcx;
//            rdx = read<QWORD>(rbp + 0xe8);
            rcx = rax;
//            rdx -= rdi;
            rcx -= rbx;
//            rdx &= 0xffffffffc0000000;
            rdx = 0;
            rdx <<= 0x10;
            rdx ^= r10;
            rdx = (~rdx);
            rax = read<QWORD>(rdx + 0x5);
            rax *= rcx;
            return rax;
            break;
        }

        case 9: {
            rdi = (game_base_address + 0x25A);
            r11 = game_base_address;
            r15 = (game_base_address + 0x15EFD7AA);
            r10 = read<QWORD>(game_base_address + 0x5C42128);
            rcx = 0x15FA09C07ED75B2E;
            rax ^= rcx;
            rcx = rax;
            rcx >>= 0x1B;
            rax ^= rcx;
            rcx = rax;
            rcx >>= 0x36;
            rax ^= rcx;
            rcx = 0x212F8C599FA94B79;
            rax *= rcx;
            rdx = rbx;
            rdx = (~rdx);
            rcx = (game_base_address + 0x311672ED);
            rdx += rcx;
            rcx = rax;
            rax = 0x7CC18E9A499DBBFD;
            rcx *= rax;
            rax = rdx;
            rax ^= rcx;
            rcx = r15;
            rcx = (~rcx);
            rcx ^= rbx;
            rax -= rcx;
            rax -= r11;
//            rcx = read<QWORD>(rbp + 0xe8);
//            rcx -= rdi;
//            rcx &= 0xffffffffc0000000;
            rcx = 0;
            rcx <<= 0x10;
            rcx ^= r10;
            rcx = (~rcx);
            rax *= read<QWORD>(rcx + 0x5);
            return rax;
            break;
        }

        case 10: {
            rdi = (game_base_address + 0x25A);
            r11 = game_base_address;
            r9 = read<QWORD>(game_base_address + 0x5C42128);
            rcx = rax;
            rcx >>= 0x15;
            rax ^= rcx;
            rcx = rax;
            rcx >>= 0x2A;
            rax ^= rcx;
            rcx = (game_base_address + 0x39985427);
            rax += rbx;
            rax += rcx;
            rcx = 0xC1D46843B5A675A7;
            rax *= rcx;
            rax += r11;
            rax += rbx;
//            rcx = read<QWORD>(rbp + 0xe8);
//            rcx -= rdi;
//            rcx &= 0xffffffffc0000000;
            rcx = 0;
            rcx <<= 0x10;
            rcx ^= r9;
            rcx = (~rcx);
            rax *= read<QWORD>(rcx + 0x5);
            rcx = 0x19E44D25A759B984;
            rax -= rcx;
            rcx = r11 + 0x1d8a;
            rcx += rbx;
            rax ^= rcx;
            return rax;
            break;
        }

        case 11: {
            rdi = (game_base_address + 0x25A);
            r11 = game_base_address;
            r15 = (game_base_address + 0xE846);
            r10 = read<QWORD>(game_base_address + 0x5C42128);
            rax -= r11;
            rcx = rax;
            rcx >>= 0x26;
            rax ^= rcx;
            rcx = 0xC0A3127215C28EDA;
            rax ^= rcx;
//            rcx = read<QWORD>(rbp + 0xe8);
//            rcx -= rdi;
//            rcx &= 0xffffffffc0000000;
            rcx = 0;
            rcx <<= 0x10;
            rcx ^= r10;
            rcx = (~rcx);
            rax *= read<QWORD>(rcx + 0x5);
            rcx = rax;
            rcx >>= 0xE;
            rax ^= rcx;
            rcx = rax;
            rcx >>= 0x1C;
            rax ^= rcx;
            rcx = rax;
            rcx >>= 0x38;
            rax ^= rcx;
            rax *= 0x4E88C19E0C0E994B;
            rdx = 0xB3569BB624216F54;
            rcx = rbx;
            rcx ^= r15;
            rcx += rdx;
            rax += rcx;
            return rax;
            break;
        }

        case 12: {
            rdi = (game_base_address + 0x25A);
            r11 = game_base_address;
            r10 = read<QWORD>(game_base_address + 0x5C42128);
            rcx = rax;
            rcx >>= 0xA;
            rax ^= rcx;
            rcx = rax;
            rcx >>= 0x14;
            rax ^= rcx;
            rcx = rax;
            rcx >>= 0x28;
            rax ^= rcx;
            rcx = 0xC5DBD8495A0183A7;
//            rdx = read<QWORD>(rbp + 0xe8);
            rcx ^= rax;
            rcx -= r11;
//            rdx -= rdi;
//            rdx &= 0xffffffffc0000000;
            rdx = 0;
            rdx <<= 0x10;
            rdx ^= r10;
            rdx = (~rdx);
            rax = read<QWORD>(rdx + 0x5);
            rax *= rcx;
            rcx = rax;
            rcx >>= 0x7;
            rax ^= rcx;
            rcx = rax;
            rcx >>= 0xE;
            rax ^= rcx;
            rcx = rax;
            rcx >>= 0x1C;
            rax ^= rcx;
            rcx = rax;
            rcx >>= 0x38;
            rax ^= rcx;
            rcx = 0x45EADF11D3DA8F8A;
            rax ^= rcx;
            rcx = 0xF719B9B7386E6BA9;
            rax *= rcx;
            rcx = rax;
            rcx >>= 0x28;
            rax ^= rcx;
            return rax;
            break;
        }

        case 13: {
            rdi = (game_base_address + 0x25A);
            r11 = game_base_address;
            r10 = read<QWORD>(game_base_address + 0x5C42128);
            rcx = 0x4D72818B548CA9C8;
            rax -= rcx;
            rcx = rax;
            rcx >>= 0x17;
            rax ^= rcx;
            rcx = rax;
            rcx >>= 0x2E;
            rax ^= rcx;
//            rcx = read<QWORD>(rbp + 0xe8);
//            rcx -= rdi;
//            rcx &= 0xffffffffc0000000;
            rcx = 0;
            rcx <<= 0x10;
            rcx ^= r10;
            rcx = (~rcx);
            rcx = read<QWORD>(rcx + 0x5);
            rax *= rcx;
            rcx = 0xA395C9E379885E07;
            rax *= rcx;
            rcx = r11 + 0xa061;
            rcx += rbx;
            rax ^= rcx;
            rcx = 0x2D9B53A0F260313E;
            rax ^= rcx;
            rcx = rax;
            rcx >>= 0x1C;
            rax ^= rcx;
            rdx = rax;
            rdx >>= 0x38;
            rdx ^= rax;
            rax = (game_base_address + 0x3F9C97DF);
            rax ^= rbx;
            rax += rdx;
            return rax;
            break;
        }

        case 14: {
            rdi = (game_base_address + 0x25A);
            r11 = game_base_address;
            r9 = read<QWORD>(game_base_address + 0x5C42128);
            rcx = rax;
            rcx >>= 0x22;
            rax ^= rcx;
            rcx = 0x73F2D1E3898142CD;
            rax -= rcx;
//            rcx = read<QWORD>(rbp + 0xe8);
//            rcx -= rdi;
//            rcx &= 0xffffffffc0000000;
            rcx = 0;
            rcx <<= 0x10;
            rcx ^= r9;
            rcx = (~rcx);
            rax *= read<QWORD>(rcx + 0x5);
            rax ^= rbx;
            rax ^= r11;
            rcx = 0xF66185C0BAE043DF;
            rax *= rcx;
            rcx = rax;
            rcx >>= 0x15;
            rax ^= rcx;
            rcx = rax;
            rcx >>= 0x2A;
            rax ^= rcx;
            rcx = 0x20014237A30E740C;
            rax += rcx;
            return rax;
            break;
        }

        case 15: {
            r10 = read<QWORD>(game_base_address + 0x5C42128);
            rdi = (game_base_address + 0x25A);
            r15 = (game_base_address + 0x52C26DC4);
//            rcx = read<QWORD>(rbp + 0xe8);
//            rcx -= rdi;
//            rcx &= 0xffffffffc0000000;
            rcx = 0;
            rcx <<= 0x10;
            rcx ^= r10;
            rcx = (~rcx);
            rcx = read<QWORD>(rcx + 0x5);
            rcx *= 0x9EEBA31569C381A1;
            rax *= rcx;
            rax += rbx;
            rcx = (game_base_address + 0x256D51FE);
            rax += rcx;
            rcx = 0xEFB67E105AA788F1;
            rax ^= rcx;
            rax += r15;
            rdx = rbx;
            rdx = (~rdx);
            rax += rdx;
            rax ^= rbx;
            rcx = rax;
            rcx >>= 0x27;
            rax ^= rcx;
            rax += rbx;
            return rax;
            break;
        }
    }
    return 0;
}

auto
decrypt_bone_base(uint64_t encrypted_address, uint64_t game_base_address, uint64_t last_key, uint64_t peb) -> uint64_t {
    uint64_t rax, rbx, rcx, rdx, r8, rdi, rsi, r9, r10, r11, r12, r13, r14, r15;

    const auto Peb = peb;

//    rax = peb;
//    rax <<= 0x24;
//    rax = _byteswap_uint64(rax);

    const auto enc_case = _rotl64(~peb, 0x28) & 0xF;

//    r8 = encrypted_address;
    rdx = encrypted_address;

    r10 = peb;

    switch (enc_case) {
        case 0: {
            r8 = 0xF43EA89AE66A5B5D;
            rbx = (game_base_address + 0xE10);
            r9 = read<QWORD>(game_base_address + 0x5C4220B);
            rax = rdx;
            rax >>= 0x24;
            rdx ^= rax;
            rax = 0x9D2C4CAE46F1EFE5;
            r8 ^= rax;
//            rcx = read<QWORD>(rbp + 0x358);
//            rcx -= rbx;
//            rcx &= 0xffffffffc0000000;
            rcx = 0;
            rax = 0x3F4C2F9B3B2309EB;
            rcx <<= 0x10;
            r8 ^= rax;
            rcx ^= r9;
            rax = r10;
            rcx = (~rcx);
            rax ^= rdx;
            rdx = read<QWORD>(rcx + 0x5);
            rdx *= rax;
            rax = rdx;
            rax >>= 0xA;
            rdx ^= rax;
            rax = rdx;
            rax >>= 0x14;
            rdx ^= rax;
            rax = 0x6052C120D629DE5E;
            r8 ^= rax;
            rax = rdx;
            rax >>= 0x28;
            rdx ^= rax;
            rax = 0x28A1E3E41520FFA0;
            r8 ^= rax;
            rdx ^= r10;
            rax = 0x801D944E49424BF6;
            rdx ^= rax;
            rax = 0x7989CA897141CEAE;
            r8 ^= rax;
            rax = 0x391D591AED20CD94;
            r8 ^= rax;
            rax = 0x9E4AD488F0E7DBEE;
            r8 ^= rax;
            rax = 0xD7FB854262277AE0;
            r8 ^= rax;
            rax = 0x3F685F1D34E440CB;
            rdx *= rax;
            rax = 0xD5AD32007E06E5B3;
            rdx *= rax;
            rax = 0x769F3ABD3FDD289A;
            r8 ^= rax;
            rbx ^= rbx;
            rax = rsi;
            r13 = rax * 0x150;
            r13 += rdx;
            r15 = read<QWORD>(r13 + 0xf0);
            rax = rbx;
            rdi = r15 + rax * 8;
            rax = read<QWORD>(rdi + 0x98);
            r8 = rbx;
            rax ^= rax;
            rax ^= rax;
            rbx += rax;
            r8 = rbx;
            rax ^= rax;
            rax ^= rax;
            rbx += rax;
            r8 = rbx;
            return r8;
            break;
        }

        case 1: {
            rbx = (game_base_address + 0xE10);
            r8 = read<QWORD>(game_base_address + 0x5C4220B);
            rbx ^= rbx;
            r8 = rbx;
            return r8;
            break;
        }

        case 2: {
            rbx = (game_base_address + 0xE10);
            r8 = read<QWORD>(game_base_address + 0x5C4220B);
            rbx ^= rbx;
            r8 = rbx;
            return r8;
            break;
        }

        case 3: {
            r8 = 0x7C495D54D1F1CE30;
            rbx = (game_base_address + 0xE10);
            rax = 0x83DED9454F389A98;
            r8 ^= rax;
            rax = 0xA40B0D3EB9D94BF5;
            r8 ^= rax;
            rax = 0x16AE24DDFE95676;
            r8 ^= rax;
            rax = 0x6D76B80A35BF81D2;
            r8 ^= rax;
            rax = 0x272162B07A2A8708;
            r8 ^= rax;
            rax = 0xB46CD2217524D1DD;
            r8 ^= rax;
            rax = 0xC667C093A0146895;
            r8 ^= rax;
            rax = 0x536F51B13B1D639;
            r8 ^= rax;
            rax = 0xA7166125C54C41D9;
            r8 ^= rax;
            rax = 0x7C032086974FFF1E;
            r8 ^= rax;
            rbx ^= rbx;
            r8 = rbx;
            return r8;
            break;
        }

        case 4: {
            r8 = 0xE77C63A2A61391A0;
            rbx = (game_base_address + 0xE10);
            rax = 0x9C9E90455ADA1DA3;
            r8 ^= rax;
            rax = 0x75BE68331A57677D;
            r8 ^= rax;
            rax = 0x7F8F1D2BFFDE7FFE;
            r8 ^= rax;
            rax = 0x94A93D11AD5F279;
            r8 ^= rax;
            rax = 0xA6351F02CA378D78;
            r8 ^= rax;
            rax = 0x9BC47FD11BB5E733;
            r8 ^= rax;
            rax = 0xB2A0EA5FE9695156;
            r8 ^= rax;
            rax = 0x7450459D682650DB;
            r8 ^= rax;
            rax = 0xEFF5A08D4A96E862;
            r8 ^= rax;
            rax = 0x884F3E56853120A1;
            r8 ^= rax;
            rax = 0xE078925F7424B4D;
            r8 ^= rax;
            rbx ^= rbx;
            r8 = rbx;
            return r8;
            break;
        }

        case 5: {
            r8 = 0x93D48714D80F9EC9;
            rbx = (game_base_address + 0xE10);
            rax = 0x38F517CC8C30FDCC;
            r8 ^= rax;
            rax = 0xC99F09096319B7FC;
            r8 ^= rax;
            rax = 0xE52DC193143A2151;
            r8 ^= rax;
            rax = 0x65083A76CAFB7ADF;
            r8 ^= rax;
            rax = 0xC29737B0FC328032;
            r8 ^= rax;
            rax = 0x657BD290FC0B61BB;
            r8 ^= rax;
            rax = 0x4999BC7EB0E4FB53;
            r8 ^= rax;
            rax = 0xB9F5D5B9598FF88A;
            r8 ^= rax;
            rax = 0xE98287A876E928BB;
            r8 ^= rax;
            rbx ^= rbx;
            r8 = rbx;
            return r8;
            break;
        }

        case 6: {
            r8 = read<QWORD>(game_base_address + 0x5C4220B);
            rbx = (game_base_address + 0xE10);
//            rax = read<QWORD>(rbp + 0x358);
//            rax -= rbx;
//            rax &= 0xffffffffc0000000;
            rax = 0;
            rax <<= 0x10;
            rax ^= r8;
            rax = (~rax);
            rdx *= read<QWORD>(rax + 0x5);
            rax = rdx;
            rax >>= 0x13;
            rdx ^= rax;
            rax = rdx;
            rax >>= 0x26;
            rdx ^= rax;
            rax = r10 + 0x1d5af795;
            rax += r11;
            rdx -= r10;
            rdx ^= rax;
            rax = rdx;
            rax >>= 0x12;
            rdx ^= rax;
            rax = rdx;
            rax >>= 0x24;
            rdx ^= rax;
            rax = 0xD86EDE1801E442AF;
            rdx ^= rax;
            rax = 0x428AF3C0B65ED17D;
            rdx *= rax;
            rax = 0x3D4E4DC78EB805F8;
            rdx -= rax;
            rbx ^= rbx;
            rax = rsi;
            r13 = rax * 0x150;
            r13 += rdx;
            r15 = read<QWORD>(r13 + 0xf0);
            rax = rbx;
            rdi = r15 + rax * 8;
            rax = read<QWORD>(rdi + 0x98);
            r8 = rbx;
            rax ^= rax;
            rax ^= rax;
            rbx += rax;
            r8 = rbx;
            return r8;
            break;
        }

        case 7: {
            rbx = (game_base_address + 0xE10);
            r8 = read<QWORD>(game_base_address + 0x5C4220B);
            rbx ^= rbx;
            r8 = rbx;
            return r8;
            break;
        }

        case 8: {
            rbx = (game_base_address + 0xE10);
            r13 = (game_base_address + 0x269BED2C);
            r8 = read<QWORD>(game_base_address + 0x5C4220B);
            rax = 0xBF6FD4AB79BB6F95;
            rdx ^= rax;
            rax = r10 + 0x1;
            rax *= 0x7FF847421526;
            rdx += rax;
            rax = 0x96B7D4CC4F02DF67;
            rdx *= rax;
            rdx ^= r11;
            rax = rdx;
            rax >>= 0x12;
            rdx ^= rax;
            rax = rdx;
            rax >>= 0x24;
            rdx ^= rax;
            rax = 0xD02E8C294DFABC43;
            rdx *= rax;
//            rax = read<QWORD>(rbp + 0x358);
//            rax -= rbx;
//            rax &= 0xffffffffc0000000;
            rax = 0;
            rax <<= 0x10;
            rax ^= r8;
            rax = (~rax);
            rdx *= read<QWORD>(rax + 0x5);
            rax = r10;
            rax *= r13;
            rdx -= rax;
            rbx ^= rbx;
            rax = rsi;
            r13 = rax * 0x150;
            r13 += rdx;
            r15 = read<QWORD>(r13 + 0xf0);
            rax = rbx;
            rdi = r15 + rax * 8;
            rax = read<QWORD>(rdi + 0x98);
            r8 = rbx;
            rax ^= rax;
            rax ^= rax;
            rbx += rax;
            r8 = rbx;
            return r8;
            break;
        }

        case 9: {
            r8 = 0x7B3CC317C98743EE;
            r9 = read<QWORD>(game_base_address + 0x5C4220B);
            rbx = (game_base_address + 0xE10);
            rax = 0x47E0A4B4C91FFD53;
            r8 ^= rax;
            rdx ^= r10;
            rdx += r10;
            rax = (game_base_address + 0xE3CF);
            rdx += rax;
            rax = 0xD88A466009A9290B;
            r8 ^= rax;
            rdx -= r11;
            rdx += 0xFFFFFFFFCF299512;
            rdx += r10;
            rax = 0x76BC6149EF3C443F;
            r8 ^= rax;
            rax = 0x2329A97238555793;
            rdx *= rax;
            rax = rdx;
            rax >>= 0x1D;
            rdx ^= rax;
            rax = 0xC4DD26DEC5AC662;
            r8 ^= rax;
            rax = rdx;
            rax >>= 0x3A;
            rdx ^= rax;
            rax = 0xDAEF696D480AAC3;
            r8 ^= rax;
            rax = 0x722C80A8266435E8;
            r8 ^= rax;
            rax = 0xAAC0518C37B39179;
            rdx *= rax;
            rdx += r11;
            rax = 0x5344269C4DB386D3;
            r8 ^= rax;
//            rax = read<QWORD>(rbp + 0x358);
//            rax -= rbx;
//            rax &= 0xffffffffc0000000;
            rax = 0;
            rax <<= 0x10;
            rax ^= r9;
            rax = (~rax);
            rdx *= read<QWORD>(rax + 0x5);
            rbx ^= rbx;
            rax = rsi;
            r13 = rax * 0x150;
            r13 += rdx;
            r15 = read<QWORD>(r13 + 0xf0);
            rax = rbx;
            rdi = r15 + rax * 8;
            rax = read<QWORD>(rdi + 0x98);
            r8 = rbx;
            rax ^= rax;
            rax ^= rax;
            rbx += rax;
            r8 = rbx;
            return r8;
            break;
        }

        case 10: {
            r8 = 0xA3042905438571F5;
            rdx = 0x228CD68499715CFB;
            rbx = (game_base_address + 0xE10);
            rcx = (game_base_address + 0x7E9AB4C4);
            r9 = read<QWORD>(game_base_address + 0x5C4220B);
            rax = rdx;
            rax >>= 0x1F;
            rdx ^= rax;
            rax = 0x7610FF6256D5B85A;
            r8 ^= rax;
            rax = 0xC026A1E0B6B8118A;
            r8 ^= rax;
            rax = rdx;
            rax >>= 0x3E;
            rdx ^= rax;
            rax = 0x5EA5CE48CC179563;
            rdx *= rax;
            rax = r10;
            rax *= rcx;
            rdx ^= rax;
            rax = 0xBAD809A45C010C88;
            rdx ^= rax;
            rax = 0xDE53EF4A7C90B4EF;
            r8 ^= rax;
            rax = 0xC65D07376E2F0FB1;
            rdx *= rax;
//            rax = read<QWORD>(rbp + 0x358);
//            rax -= rbx;
//            rax &= 0xffffffffc0000000;
            rax = 0;
            rax <<= 0x10;
            rax ^= r9;
            rax = (~rax);
            rdx *= read<QWORD>(rax + 0x5);
            rax = 0x3B3093D1D216755D;
            r8 ^= rax;
            rax = 0x32BF3A5DDF165A94;
            r8 ^= rax;
            rax = rdx;
            rax >>= 0x6;
            rdx ^= rax;
            rax = 0xEB9769DC5FCA1C70;
            r8 ^= rax;
            rax = rdx;
            rax >>= 0xC;
            rdx ^= rax;
            rax = rdx;
            rax >>= 0x18;
            rdx ^= rax;
            rax = rdx;
            rax >>= 0x30;
            rdx ^= rax;
            rax = (game_base_address + 0xE36F);
            rdx += r10;
            rdx += rax;
            rax = 0x3E0CA72D82EE3D0E;
            r8 ^= rax;
            rbx ^= rbx;
            rax = rsi;
            r13 = rax * 0x150;
            r13 += rdx;
            r15 = read<QWORD>(r13 + 0xf0);
            rax = rbx;
            rdi = r15 + rax * 8;
            rax = read<QWORD>(rdi + 0x98);
            r8 = rbx;
            rax ^= rax;
            rax ^= rax;
            rbx += rax;
            r8 = rbx;
            return r8;
            break;
        }

        case 11: {
            r8 = 0x7A4F418D108C8737;
            r9 = read<QWORD>(game_base_address + 0x5C4220B);
            rbx = (game_base_address + 0xE10);
            rax = 0xB90189A2C1955EB7;
            r8 ^= rax;
            rax = rdx;
            rax >>= 0x28;
            rdx ^= rax;
            rax = 0xAE5DD79A65B2480B;
            r8 ^= rax;
            rdx ^= r11;
//            rax = read<QWORD>(rbp + 0x358);
//            rax -= rbx;
//            rax &= 0xffffffffc0000000;
            rax = 0;
            rax <<= 0x10;
            rax ^= r9;
            rax = (~rax);
            rax = read<QWORD>(rax + 0x5);
            rdx *= rax;
            rax = 0x7FF87F9CC70D1A4F;
            rdx -= rax;
            rax = 0x485859ECB40D80BC;
            r8 ^= rax;
            rcx = (game_base_address + 0x78AF);
            rax = 0xE55B408E6AB53496;
            rcx = (~rcx);
            r8 ^= rax;
            rax = rdx;
            rdx = 0xC44A535EA4B68C19;
            rcx *= r10;
            rax *= rdx;
            rdx = rcx;
            rdx ^= rax;
            rax = 0x3D4208FBE2C8C1F2;
            r8 ^= rax;
            rax = (game_base_address + 0x6210B0EF);
            rax = (~rax);
            rax -= r10;
            rdx += rax;
            rax = 0xEE1572E2E513F633;
            rdx *= rax;
            rbx ^= rbx;
            rax = rsi;
            r13 = rax * 0x150;
            r13 += rdx;
            r15 = read<QWORD>(r13 + 0xf0);
            rax = rbx;
            rdi = r15 + rax * 8;
            rax = read<QWORD>(rdi + 0x98);
            r8 = rbx;
            rax ^= rax;
            rax ^= rax;
            rbx += rax;
            r8 = rbx;
            return r8;
            break;
        }

        case 12: {
            r8 = 0x81B26A0DF7CD4BE9;
            rdx = 0xA90E605D1FEB4B00;
//            rdx ^= none; //FIXME
            r9 = read<QWORD>(game_base_address + 0x5C4220B);
            rbx = (game_base_address + 0xE10);
            rax = 0x8CECE475C99C5C79;
            r8 ^= rax;
            rax = (game_base_address + 0x4DD3);
            rax = (~rax);
            rax -= r10;
            rdx += rax;
            rax = r10;
            rax *= 0x7FF7CBA69D82;
            rdx += rax;
            rax = 0x67EE2D0F619FF627;
            r8 ^= rax;
            rax = rdx;
            rax >>= 0x21;
            rdx ^= rax;
            rax = 0x29596296A4889A5E;
            r8 ^= rax;
            rax = 0x1D622A5FC296159B;
            rdx *= rax;
            rax = 0xDE549EF223592D3C;
            r8 ^= rax;
            rax = 0xC856E62CB36FC3A7;
            r8 ^= rax;
            rax = 0xD0BE6B4E3C2ACEEC;
            r8 ^= rax;
            rax = 0x8B6C63D7FD3AD684;
//            rcx = read<QWORD>(rbp + 0x358);
            rax += rdx;
//            rcx -= rbx;
            rdx = 0xD5C1259BCAE9D756;
//            rcx &= 0xffffffffc0000000;
            rcx = 0;
            rax ^= rdx;
            rcx <<= 0x10;
            rcx ^= r9;
            rcx = (~rcx);
            rdx = read<QWORD>(rcx + 0x5);
            rdx *= rax;
            rbx ^= rbx;
            rax = rsi;
            r13 = rax * 0x150;
            r13 += rdx;
            r15 = read<QWORD>(r13 + 0xf0);
            rax = rbx;
            rdi = r15 + rax * 8;
            rax = read<QWORD>(rdi + 0x98);
            r8 = rbx;
            rax ^= rax;
            rax ^= rax;
            rbx += rax;
            r8 = rbx;
            return r8;
            break;
        }

        case 13: {
            r8 = 0x3585DE8C9A760440;
            rbx = (game_base_address + 0xE10);
            rax = 0x21E07744933583F6;
            r8 ^= rax;
            rax = 0x6511004209607EB3;
            r8 ^= rax;
            rax = 0x8ACAA8C2463B1E10;
            r8 ^= rax;
            rax = 0xDE3836FB894F750B;
            r8 ^= rax;
            rax = 0x3F1398B4AF1FD149;
            r8 ^= rax;
            rax = 0xF66121DB40A16F81;
            r8 ^= rax;
            rax = 0x7EA8FA3D6A5E2E50;
            r8 ^= rax;
            rax = 0xF7812BFD21868221;
            r8 ^= rax;
            rax = 0x86084106E034C0AD;
            r8 ^= rax;
            rax = 0x3FC748D5ED2970A5;
            r8 ^= rax;
            rbx ^= rbx;
            r8 = rbx;
            return r8;
            break;
        }

        case 14: {
            rbx = (game_base_address + 0xE10);
            r8 = read<QWORD>(game_base_address + 0x5C4220B);
            rbx ^= rbx;
            r8 = rbx;
            return r8;
            break;
        }

        case 15: {
            r8 = 0x194639D435837155;
            rax = 0x12FD72D67AC081A0;
            r8 ^= rax;
            rax = 0xFC1C63CC03600E8B;
            r8 ^= rax;
            rax = 0x118668C27A3B5035;
            r8 ^= rax;
            rax = 0x930F1796D3283EF8;
            r8 ^= rax;
            r8 = peb;
            r8 = peb;
            r8 = peb;
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
