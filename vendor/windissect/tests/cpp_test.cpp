// C++ compilation test harness for reconstructed DirectUI headers
#include <iostream>

// Standard Windows types stub for cross-compilation/Linux testing
typedef unsigned long DWORD;
typedef int HRESULT;
typedef void* HANDLE;
typedef unsigned short WCHAR;

// Forward declarations
namespace DirectUI {
    class Element;
    class Button;
    class HWNDElement;
    class Value;
    class PropertyInfo;
    class ClassInfoBase;
    struct Event;
    struct IElementListener;
    class DeferCycle;
    class UID;
}
struct IDuiBehavior;
struct IDCompositionVisual;
struct IRawElementProviderSimple;

#include "../headers/dui70/dui70.h"
#include "../headers/dui70/dui70_c.h"

static_assert(windissect_abi::vtable_count > 0);

int main() {
    std::cout << "DirectUI C++ headers compiled successfully!" << std::endl;
    return 0;
}
