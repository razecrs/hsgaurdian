struct Base {
    virtual int value(int x) const { return x + 1; }
    int base_field = 7;
};

struct Child : Base {
    int field;
    Child(int x) : field(x) {}
    int value(int x) const override { int local = field + x; return local; }
    inline int inline_add(int x) const { return field + x; }
};

extern "C" __declspec(dllexport) int fixture_entry(int x) {
    Child c(x);
    return c.value(x) + c.inline_add(2);
}
