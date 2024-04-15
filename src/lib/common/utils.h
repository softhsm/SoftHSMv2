#include <string>
#include <vector>

namespace utils
{
    void ltrim( std::string &s );
    void rtrim( std::string &s );
    void trim(  std::string &s );
    
    enum SplitFlags
    {
        SPLIT_TRIMMED  = 0x01
    ,   SPLIT_NO_EMPTY = 0x02
    };
    std::vector<std::string> split(
        const std::string &s, const char delimiter, const int flags=0 );
}