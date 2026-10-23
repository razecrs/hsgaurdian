#include "../headers/dui70/windissect_calls.h"

static const void* reject_all(std::uint32_t) {
    return nullptr;
}

int main() {
    windissect_calls::set_resolver(reject_all);
    return windissect_calls::resolver == reject_all ? 0 : 1;
}
