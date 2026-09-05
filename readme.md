\# Changing the C++ standard library



See \[deps.hpp](src/deps.hpp), which contains the required features. Create a header that defines the required features in the ac:: namespace and `#define ARMCALL\_DEPS\_HDR <path/to/hdr.hpp>`. The library will use that header instead.

