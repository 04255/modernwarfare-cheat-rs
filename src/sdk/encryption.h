#include <cstdint>
#include <stdlib.h>
#include <stdio.h>

typedef unsigned __int64 QWORD;
typedef uint32_t DWORD;
typedef unsigned char BYTE;

#define _BYTE  uint8_t
#define BYTEn(x, n)   (*((_BYTE*)&(x)+(n)))
#define BYTE1(x)   BYTEn(x,  1)         // byte 1 (counting from 0)
#define HIBYTE(x)   (*((_BYTE*)&(x)+1))

auto decrypt_client_info(uint64_t encrypted_address, uint64_t game_base_address, uint64_t last_key, uint64_t peb) -> uint64_t;
auto decrypt_client_base(uint64_t encrypted_address, uint64_t game_base_address, uint64_t last_key, uint64_t peb) -> uint64_t;
auto decrypt_bone_base(uint64_t encrypted_address, uint64_t game_base_address, uint64_t last_key, uint64_t peb) -> uint64_t;
auto get_bone_index(uint64_t index, uint64_t game_base_address) -> uint64_t;

auto get_visible_base(int32_t index, uint64_t game_base_address, uint64_t func_distribute, uint64_t vis_function) -> uint64_t;
// 0: not visible, 1: visible: 2: error
auto is_visible(int32_t index, uint64_t last_visible_offset) -> uint32_t;