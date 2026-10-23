#include "../headers/dui70/dui70_c.h"
#include "../syms/dui70_syms.h"

static_assert(WINDISSECT_C20_PROFILE == 1);

int main() {
    const DUI70SymEntry* symbol = dui70_sym_lookup("inflateReset");
    return symbol == nullptr;
}
