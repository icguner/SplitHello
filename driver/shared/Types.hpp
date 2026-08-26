#pragma once

namespace splithello {

using U8 = unsigned char;
using U16 = unsigned short;
using U32 = unsigned int;
using I32 = int;
using U64 = unsigned __int64;
using Size = decltype(sizeof(0));

static_assert(sizeof(U8) == 1);
static_assert(sizeof(U16) == 2);
static_assert(sizeof(U32) == 4);
static_assert(sizeof(I32) == 4);
static_assert(sizeof(U64) == 8);

}  // namespace splithello
