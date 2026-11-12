#ifndef EMERALDSTRIKE_SALT_H
#define EMERALDSTRIKE_SALT_H

#ifndef OBF_SALT
#define OBF_SALT 0
#endif

#if OBF_SALT != 0
namespace salt {

constexpr unsigned SEED = (unsigned)OBF_SALT;
constexpr unsigned N    = 4096u + (SEED % 4097u);

struct Buf {
    unsigned char d[N];
    consteval Buf() {
        unsigned s = SEED * 2654435761u + 0x9E3779B9u;
        if (!s) s = 0xA5A5A5A5u;
        for (unsigned i = 0; i < N; i++) {
            s ^= s << 13;
            s ^= s >> 17;
            s ^= s << 5;
            d[i] = (unsigned char)(s ^ (i * 0x9Du + 0x33u));
        }
    }
};
inline constexpr Buf g_salt{};

__attribute__((noinline))
inline unsigned mix(unsigned x) {
    unsigned a = SEED;
    unsigned step = (SEED % 97u) + 1u;
    for (unsigned i = 0; i < 32u; i++)
        a = a * 16777619u ^ g_salt.d[(x + i * step) % N];
    return a;
}

} // namespace salt

// Anchor: call once from agent_init with any pointer. The volatile guard
// stops the optimizer folding the noinline chain away.
#define SALT_RETAIN(ptr_)                                       \
    do {                                                        \
        volatile unsigned _sv_ =                                \
            salt::mix((unsigned)(unsigned long long)(void*)(ptr_)); \
        (void)_sv_;                                             \
    } while (0)
#else
#define SALT_RETAIN(ptr_) do {} while (0)
#endif

#endif // EMERALDSTRIKE_SALT_H
