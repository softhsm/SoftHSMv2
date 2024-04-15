#include <sstream>
#include <algorithm>
#include <cctype>
#include <locale>

#include "utils.h"

void utils::ltrim( std::string &s )
{
    s.erase( s.begin(), std::find_if( s.begin(), s.end(),
        []( unsigned char ch ) { return !std::isspace( ch ); } ) );
}

void utils::rtrim( std::string &s )
{
    s.erase( std::find_if( s.rbegin(), s.rend(),
        []( unsigned char ch ) { return !std::isspace( ch ); } ).base(), s.end() );
}

void utils::trim( std::string &s )
{
    rtrim( s );
    ltrim( s );
}
    
std::vector<std::string> utils::split(
    const std::string &s, const char delimiter, const int flags )
{
    const bool trimmed( flags & SPLIT_TRIMMED  )
             , noEmpty( flags & SPLIT_NO_EMPTY )
    ;
    std::vector<std::string> tokens;
    std::stringstream ss( s );
    for( std::string t; getline( ss, t, delimiter ); )
    {
        if( trimmed ) trim( t );
        if( noEmpty && t.empty() ) continue;
        tokens.push_back( t );
    }
    return tokens;
}