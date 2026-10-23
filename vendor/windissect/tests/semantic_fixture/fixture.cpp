using u32 = unsigned int;
using Callback = long(__cdecl *)(u32, void*);

enum class SemanticColor : int {
    Red = -1,
    Green = 2,
    Blue = 0x100,
};

struct PrimaryBase {
    virtual int primary() const;
    u32 primary_value;
};

struct SecondaryBase {
    virtual int secondary();
    void* secondary_pointer;
};

struct Interface {
    virtual long invoke(u32 value) = 0;
};

struct SemanticFixture final : PrimaryBase, SecondaryBase, Interface {
    union Payload {
        unsigned long long integer;
        double real;
        void* pointer;
    } payload;
    unsigned enabled : 1;
    unsigned mode : 3;
    unsigned reserved : 28;
    Callback callback;

    int primary() const override;
    int secondary() override;
    long invoke(u32 value) override;
};

int PrimaryBase::primary() const { return static_cast<int>(primary_value); }
int SecondaryBase::secondary() { return secondary_pointer != nullptr; }
int SemanticFixture::primary() const { return static_cast<int>(payload.integer); }
int SemanticFixture::secondary() { return enabled; }
long SemanticFixture::invoke(u32 value) { return callback ? callback(value, this) : -1; }

extern "C" __declspec(dllexport) unsigned long long semantic_fixture_size() {
    return sizeof(SemanticFixture);
}

extern "C" __declspec(dllexport) unsigned long long semantic_fixture_payload_offset() {
    return __builtin_offsetof(SemanticFixture, payload);
}

extern "C" __declspec(dllexport) int semantic_fixture_color_value(SemanticColor color) {
    return static_cast<int>(color);
}
