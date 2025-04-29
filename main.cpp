#include <stdlib.h> // exit()
#include <time.h> // localtime_r() strptime()
#include <string.h> // strncasecmp()
#include <ctype.h> // tolower(), isdigit()
#include <errno.h> // strerror(), errno
#include <assert.h>

#define __FILENAME__ (strrchr(__FILE__, '/') ? strrchr(__FILE__, '/') + 1 : __FILE__)


#include "sqlite3.h"


#include <iostream>
#include <string>
#include <utility> // min()
#include <exception> // runtime_error
#include <chrono>
#include <regex>
#include <algorithm> // count(), copy_backward()
#include <array>
#include <type_traits> // to_underlaying(), underlaying_type
#include <algorithm> // find_if_not()
#include <initializer_list>
#include <bitset>
#include <charconv> // from_chars()
#include <set>
#include <filesystem>
#include <functional> // bind()
#include <memory>
#include <future> // async()
#include <filesystem>


template <typename Enum>
auto to_underlying(Enum e)
{
    return static_cast<
        typename std::underlying_type<Enum>::type>(e);
}

// CPPHTTPLIB_OPENSSL_SUPPORT
// CPPHTTPLIB_ZLIB_SUPPORT
#include "httplib.h"


#include "boost/url.hpp"
#include "boost/url/pct_string_view.hpp"
namespace url = boost::urls;

#include "boost/utility/string_view.hpp"

#include "boost/tti/has_member_function.hpp"
#include "boost/system.hpp"

#include <boost/format.hpp>
using format = boost::format;

#include "lyra.hpp"

template <typename T>
using result = boost::system::result<T>;


namespace cooker_url_utils_ns
{
    /* site is allowed set the domain or it's subdomains */
    bool
    IsSubdomain(const std::string& likelySubdomain, 
        const std::string& domain)
    {
        const auto likelySubdomain_len = likelySubdomain.length(),
            domain_len = domain.length();

        if (likelySubdomain_len < domain_len)
        {
            return false;
        } else if (likelySubdomain_len == domain_len)
        {
            return likelySubdomain == 
                domain;
        }

        const auto diff_len = likelySubdomain.length() - 
            domain.length();
        return likelySubdomain.compare(
            diff_len, std::string::npos, domain) == 0 && 
                likelySubdomain[diff_len - 1] == '.';
    };



    /**
     * == 0, full match 
     *  > 0, first is second's subdomain
     *  < 0, else
     * */
    int
    DomainSpaceshipOp(const std::string& l_domain, 
        const std::string& r_domain)
    {
        bool isDomain = IsSubdomain(l_domain, r_domain);

        if (isDomain)
        {
            if (l_domain.length() > r_domain.length())
            {
                return 1;
            } else if (l_domain.length() == r_domain.length())
            {
                return 0;
            }           
        }

        return -1;
    };



    void ReplaceUrlResource(std::string& url, const std::string& replacingResource)
    {
        constexpr const auto npos = std::string::npos;
        std::size_t replacingPos = url.find(url.find('/') + 1, '/');
        if (replacingPos == npos)
        {
            url.append(replacingResource);
            return ;
        }

        url.replace(replacingPos, url.length(), replacingResource);
    };



    void RemoveQueryAndFrag(std::string& url)
    {
        constexpr const auto npos = std::string::npos;
        std::size_t removingPos = url.rfind('#');
        if (removingPos != npos)
        {
            const std::size_t savedRemovingPos = removingPos;
            removingPos = url.rfind('?', removingPos - 1);
            if (removingPos == npos)
            {
                removingPos = savedRemovingPos;
            }

            url.erase(removingPos);
        }
    };



    void AppendPath(std::string& url, const std::string& appendingPath)
    {
        if (url.back() != '/')
        {
            url.push_back('/');
        }

        url.append(appendingPath);
    };
}; // namespace cooker_url_utils_ns


namespace cooker_HTTP_ns
{
    const char* PUT     = "PUT";
    const char* GET     = "GET";
    const char* HEAD    = "HEAD";
    const char* OPTIONS = "OPTIONS";
    const char* POST    = "POST";
    const char* PATCH   = "PATCH";
    const char* DELETE  = "DELETE";
    const char* TRACE   = "TRACE";
    const char* CONNECT = "CONNECT";



    static const char* methods[] = {
        PUT, GET, HEAD, OPTIONS, POST, PATCH, DELETE, TRACE, CONNECT
    };

    constexpr std::size_t methodsNum = sizeof methods;

    enum MethodHashValue : std::size_t
    {
        PUT_hv = 0,
        GET_hv,
        HEAD_hv,
        OPTIONS_hv,
        POST_hv,
        PATCH_hv,
        DELETE_hv,
        TRACE_hv,
        CONNECT_hv
    };



    struct method_hash
    {
        std::size_t operator()(std::string_view method, std::size_t methodHashValue = 0)
        {
            return method == methods[methodHashValue] ? methodHashValue : operator()(method, methodHashValue + 1);
        };
    };



    bool IsHttpStatusCodeInList(int statusCode, std::initializer_list<int> list){
        return std::find(list.begin(), list.end(), statusCode) != list.begin();
    };
}; // namespace HTTP_cooker


namespace cooker_details
{
    bool ichar_equals(char a, char b)
    {
        return std::tolower(static_cast<unsigned char>(a)) ==
               std::tolower(static_cast<unsigned char>(b));
    }



    int safe_strncasecmp(const char* lhs, std::size_t lhs_len, 
        const char* rhs, std::size_t rhs_len)
    {
        if (lhs_len != rhs_len)
        {
            if (lhs_len < rhs_len)
            {
                return -rhs[lhs_len];
            } else
            {
                return lhs[rhs_len];
            }
        }

        return strncasecmp(lhs, rhs, lhs_len);
    };



    [[deprecated]]
    bool starts_with_case(const char* lhs, std::size_t lhs_len, 
        const char* rhs, std::size_t rhs_len)
    {
        if (lhs_len < rhs_len)
        {
            return false;
        }

        return std::equal(rhs, rhs + rhs_len, lhs, ichar_equals);
    };



    bool starts_with_case(std::string_view lhs, std::string_view rhs)
    {
        if (lhs.length() < rhs.length())
        {
            return false;
        }

        return std::equal(rhs.begin(), rhs.end(), lhs.begin(), ichar_equals);
    };



    [[deprecated]]
    bool starts_with(const char* lhs, std::size_t lhs_len, 
        const char* rhs, std::size_t rhs_len)
    {
        if (lhs_len < rhs_len)
        {
            return false;
        }

        return std::equal(rhs, rhs + rhs_len, lhs);
    };



    bool starts_with(std::string_view lhs, std::string_view rhs)
    {
        if (lhs.length() < rhs.length())
        {
            return false;
        }

        return std::equal(rhs.begin(), rhs.end(), lhs.begin());
    };



    bool ends_with(std::string_view lhs, std::string_view rhs)
    {
        if (lhs.length() < rhs.length())
        {
            return false;
        }

        return std::equal(rhs.rbegin(), rhs.rend(), 
            lhs.rbegin());
    };




    std::string_view 
    TrimPrefixWhitespace(std::string_view view)
    {
        return view.substr(view.find_first_not_of(" "));
    };



    // One of Jan, Feb, Mar, Apr, May, Jun, Jul, Aug, Sep, Oct, Nov, Dec (case sensitive).
    const char* 
    ConvertJSDateNameMonthToFull(const std::string& jsNameWeek)
    {
        const char* fullNames[] = {
            "January", "February", "March", "April", "May", "June", "July", "August", 
            "September", "October", "November", "December"
        };

        using Containter_T = std::array<const char*, 12>;
        Containter_T jsNames = {
            "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"
        };


        std::size_t i = 0ull;
        for ( ; i < jsNames.size(); ++i)
        {
            if (!std::strcmp(jsNames[i], jsNameWeek.c_str()))
            {
                break;
            }
        }

        return fullNames[i];
    };



    int
    ConvertJSDateNameMonthToInt(const std::string& jsNameWeek)
    {
        struct C_StrComparer
        {
            constexpr bool operator()(const char* lhs, const char* rhs) const noexcept
            {
                return std::strcmp(lhs, rhs) < 0;
            };
        };

        using Containter_T = std::map<const char*, int, C_StrComparer>;
        static const Containter_T jsNames = {
            {"Jan", 0}, {"Feb", 1}, {"Mar", 2}, {"Apr", 3}, {"May",  4}, {"Jun",  5}, 
            {"Jul", 6}, {"Aug", 7}, {"Sep", 8}, {"Oct", 9}, {"Nov", 10}, {"Dec", 11}
        };

        auto foundIter = jsNames.find(jsNameWeek.c_str());
        return foundIter != jsNames.cend() ? foundIter->second : -1;
    };



    // One of Mon, Tue, Wed, Thu, Fri, Sat, or Sun (case-sensitive).
    int 
    ConvertJSNameDayOfWeekToDemical(const std::string& jsNameDayOfWeek)
    {
        // sunday = 0 !!!
        using Containter_T = std::array<const char*, 7>;
        Containter_T jsNames = {
            "Sun", "Mon", "Tue", "Web", "Thu", "Fri", "Sat"
        };

        int i = 0;
        for ( ; i < jsNames.size(); ++i)
        {
            if (!std::strcmp(jsNames[i], jsNameDayOfWeek.c_str()))
            {
                break;
            }
        }

        return i;
    };
}; // namespace cooker_details



struct Cookie
{
    std::string m_name;
    std::string m_value;

    static std::string defaultSameSiteValue;
    std::string m_sameSite;
    std::string m_domain;
    std::string m_path;

    std::chrono::system_clock::time_point m_creationTime;
    std::chrono::system_clock::time_point m_expires;
    constexpr static const char* timeFormat = "%d %b %Y %T";
    
    // persistent string
    std::string m_cookieLocation;

    bool m_persistent;
    bool m_secure;
    bool m_httpOnly;
    /* TODO: */
    bool m_partitioned;
    bool m_hostOnly;
private:
    Cookie() = default;
public:
    Cookie(const Cookie&) = delete;



    Cookie& operator=(const Cookie&) = delete;



    Cookie(Cookie&& cookie) // maybe default?
        : m_name(std::move(cookie.m_name))
        , m_value(std::move(cookie.m_value))
        , m_sameSite(cookie.m_sameSite)
        , m_domain(std::move(cookie.m_domain))
        , m_expires(std::move(cookie.m_expires))
        , m_path(std::move(cookie.m_path))
        , m_cookieLocation(std::move(cookie.m_cookieLocation))
        , m_persistent(cookie.m_persistent)
        , m_secure(cookie.m_secure)
        , m_httpOnly(cookie.m_httpOnly)
        , m_partitioned(cookie.m_partitioned)
        , m_hostOnly(cookie.m_hostOnly)
    {
        // nothing
    };



    Cookie& operator=(Cookie&& cookie) // weird!
    {
        assert(cookie.m_domain == m_domain && 
            cookie.m_path == m_path &&
                cookie.m_name == m_name &&
                    "Fatal logic error! Overwriting cookies with same Path, Domain attrubute only");

        // auto oldSetCookieOrigin = std::move(m_cookieLocation);
        this->~Cookie();
        ::new (reinterpret_cast<void*>(this)) Cookie(std::move(cookie));
        // oldSetCookieOrigin = std::move(m_cookieLocation);
        return *this; 
    };



    class cookie_error : public std::runtime_error
    {
    public:
        using std::runtime_error::runtime_error;
    };



    class cookie_policy_error : public cookie_error
    {
    public:
        cookie_policy_error(std::string err_msg)
            : cookie_error(std::move(err_msg))
        {
            /* nothing */
        };
    };



    class cookie_parse_error : public cookie_error
    {
    public:
        cookie_parse_error(std::string err_msg)
            : cookie_error(std::move(err_msg))
        {
            /* nothing */
        };
    };



    static const std::string& 
    GetDefaultSameSiteValue()
    {
        return Cookie::defaultSameSiteValue;
    };  



    static 
    Cookie CreateDefaultCookie()
    {
        Cookie cookie;
        /* initialization */
        cookie.m_secure                 = false;
        cookie.m_httpOnly               = false;
        cookie.m_persistent             = false;
        cookie.m_partitioned            = false;
        cookie.m_hostOnly               = false;
        cookie.m_creationTime           = std::chrono::system_clock::now();
        cookie.m_sameSite               = GetDefaultSameSiteValue();
        cookie.m_expires                = std::chrono::system_clock::from_time_t(time_t{0});

        return cookie;
    }



    static
    void CheckCookiePolicy(Cookie& cookie, const std::string& path,
        const std::string& scheme, const std::string& host)
    {
        if (cookie.m_expires > std::chrono::system_clock::now())
        {
            cookie.m_persistent = true;
        }

        if (cookie.m_path.empty() || cookie.m_path.front() != '/')
        {
            cookie.m_path = ComputeCookieDefaultPath(cookie.m_path);
        } else 
        {
            if (cookie.m_path != path && 
                    !(cooker_details::starts_with_case(path, cookie.m_path) && 
                        (cookie.m_path.back() == '/' || path[cookie.m_path.length()] == '/')))
            {
                throw Cookie::cookie_policy_error("Request path does not match cookie path");
            }
        }
        
        if (cookie.m_domain.front() == '.') cookie.m_domain.erase(cookie.m_domain.cbegin());
        for (auto& ch : cookie.m_domain)
        {
            ch = std::tolower(ch);
        }

        if (cookie.m_domain.empty() || cookie.m_domain.back() == '.')
        {
            cookie.m_hostOnly = true;
            cookie.m_domain = host;
        } else if (not (cooker_details::ends_with(host, cookie.m_domain) && // !cooker_url_utils_ns::IsSubdomain(host, cookie.m_domain)
                        *std::next(host.rbegin(), cookie.m_domain.length()) == '.'))
        {
            throw Cookie::cookie_policy_error("Only the current domain can be set as the value,"
                " or a domain of a higher order");
        }

        // public prefix must be rejected!
        if (cookie.m_domain.find('.') == std::string::npos)
        {
            throw Cookie::cookie_policy_error("Public prefix cannot be domain-attribute value!");
        }


        const char* hostPrefix = "__Host-";
        const char* securePrefix = "__Secure-";

        if (cooker_details::starts_with_case(cookie.m_name, hostPrefix))
        {
            if (not (cookie.m_path == "/" && cookie.m_domain.empty() &&
                    cookie.m_secure))
            {
                throw cookie_policy_error("`__Host' prefix policy error!");
            }

            cookie.m_name.erase(cookie.m_name.cbegin(), cookie.m_name.cbegin() + std::strlen(hostPrefix));
        } else if (cooker_details::starts_with_case(cookie.m_name.c_str(), cookie.m_name.length(),
                securePrefix, std::strlen(securePrefix)))
        {
            if (!cookie.m_secure)
            {
                throw cookie_policy_error("`__Secure' prefix policy error!");
            }

            cookie.m_name.erase(cookie.m_name.cbegin(), cookie.m_name.cbegin() + std::strlen(securePrefix));
        }
 
        if (scheme != "https") 
        {
            if (cookie.m_secure)
            {
                constexpr const char* SecureAttrFromHTTPError = "Insecure site "
                         "cannot set cookies with the `Secure' attribute!"; 
                throw cookie_policy_error(SecureAttrFromHTTPError);
            }
        } else
        {
            // cookies from https auto secure!
            if (!cookie.m_secure)
            {
                cookie.m_secure = true;
            }
        }

        if (cookie.m_partitioned && !cookie.m_secure)
        {
            throw cookie_policy_error("Partitioned attribute "
                    "must be set with `Secure'");
        }

        const char* sameSite = cookie.m_sameSite.c_str();
        const bool isSameSiteAttrNone = !strcasecmp(sameSite, "none");
        if (!isSameSiteAttrNone && strcasecmp(sameSite, "strict") &&
                strcasecmp(sameSite, "lax"))
        {
            throw cookie_policy_error("SameSite attribute possible values are: strict, lax, none!");
        }

        if (isSameSiteAttrNone && !cookie.m_secure)
        {
            throw cookie_policy_error("SameSite=None attribute but is missing the `secure' attribute!");
        }
    };



    struct CookieTokenComparer
    {
        /* skip prefix whitespace and compare only length non terminal tokens 
            non casesensitive*/
    private:

    public:
        using ctraits = std::char_traits<char>;



        bool operator()(const std::pair<const char*, std::string&>& lhs, std::string_view rhs) const noexcept
        {
            return operator()(lhs.first, rhs);
        }



        bool operator()(const std::pair<const char*, bool&>& lhs, std::string_view rhs) const noexcept
        {
            return operator()(lhs.first, rhs);
        }



        bool operator()(const char* lhs, std::string_view rhs) const noexcept
        {
            return cooker_details::starts_with_case(rhs.data(), rhs.length(),
                lhs, std::strlen(lhs));
        };
    };



    static std::chrono::time_point<std::chrono::system_clock>
    ParseDateAttribute(const std::string& httpDate)
    {
        std::bitset<4> dateFlags(0ull);

        auto IsDelimiter = [](char ch){
            return ch == 0x09 || (ch >= 0x20 && ch <= 0x2F) ||
                (ch >= 0x3B && ch <= 0x40) || (ch >= 0x5B && ch <= 0x60) || 
                    (ch >= 0x7B && ch <= 0x7E);
        };


        const auto httpDate_cend = httpDate.cend();
        typename std::string::const_iterator tokenEndPos,   
            tokenStartPos = std::find_if_not(httpDate.cbegin(), httpDate_cend - 1, IsDelimiter);
        std::cmatch unused;
        std::tm parsedTime;
        std::memset(&parsedTime, 0, sizeof parsedTime);
        do
        {
            tokenEndPos = std::find_if(tokenStartPos + 1, httpDate_cend, IsDelimiter);
            std::string_view dateToken(&*tokenStartPos, std::distance(tokenStartPos, tokenEndPos));

            if (!dateFlags.test(0))
            {
                const std::regex timeProductionReg("\\d\\d(:\\d\\d){2}");
                if (std::regex_match(dateToken.begin(), dateToken.end(),
                        unused, timeProductionReg))
                {
                    const char* c_str = dateToken.data();
                    std::from_chars(c_str       , c_str + 2, parsedTime.tm_hour);
                    std::from_chars(c_str + 3   , c_str + 5, parsedTime.tm_min );
                    std::from_chars(c_str + 6   , c_str + 8, parsedTime.tm_sec );
                    dateFlags.set(0);
                    continue;
                }
            } 

            if (!dateFlags.test(1))
            {
                /* match day-of-month 1-31*/
                if (dateToken.length() == 2 && 
                        std::isdigit(dateToken[0]) && std::isdigit(dateToken[1]))
                {
                    const char* c_str = dateToken.data();
                    std::from_chars(c_str, c_str + 2, parsedTime.tm_mday);
                    dateFlags.set(1);
                    continue;
                }
            }

            if (!dateFlags.test(2))
            {
                /* match  month <list of month>*/
                if (int monthNum = cooker_details::ConvertJSDateNameMonthToInt(std::string(dateToken)); monthNum != -1)
                {
                    parsedTime.tm_mon = monthNum;
                    dateFlags.set(2);
                    continue;
                }
            }

            if (!dateFlags.test(3))
            {
                /* match time year <0000> */
                const std::regex yearProductionReg("\\d\\d\\d\\d");
                if (std::regex_match(dateToken.begin(), dateToken.end(), 
                        unused, yearProductionReg))
                {
                    const char* c_str = dateToken.data();
                    std::from_chars(c_str, c_str + 4, parsedTime.tm_year);
                    dateFlags.set(3);
                    continue;
                }
            }

            tokenStartPos   = std::find_if_not(tokenEndPos, httpDate_cend, IsDelimiter);
        } while(tokenStartPos != httpDate_cend);

        int& year = parsedTime.tm_year;
        if (year >= 70 && year <= 99)
        {
            year += 1900;
        } else if (year >= 0 && year <= 69)
        {
            year += 2000;
        }

        /* .tm_year is year since 1900 */

        /* check on parsing error */
        if (dateFlags.to_ulong() != 0b1111 || year < 1601 ||
                parsedTime.tm_hour > 23 || parsedTime.tm_min > 59 ||
                    parsedTime.tm_sec > 59)
        {
            throw Cookie::cookie_policy_error("Parsing cookie-date error!");
        }

        year -= 1900;
        
        auto GetTimeZone = [](){
            time_t nowTime = std::time(NULL);
            std::tm calendarTime;
            std::memset(&calendarTime, 0, sizeof calendarTime);
            /* since c23 */
            if (!localtime_r(&nowTime, &calendarTime))
            {
                std::cerr << "localtime_r() failed!" << 
                    strerror(errno) << std::endl;
                std::exit(EXIT_FAILURE);
            }

            return std::chrono::hours(calendarTime.tm_gmtoff / 3600);
        };

        return std::chrono::system_clock::from_time_t(mktime(&parsedTime)) +
            GetTimeZone();
    };
private:
    BOOST_TTI_HAS_MEMBER_FUNCTION(find);
public:
    static
    std::string format(std::chrono::time_point<std::chrono::system_clock> tp)
    {
        constexpr std::size_t timeStrBufSize = 128;
        char timeStrBuf[timeStrBufSize]; // quite enough
        time_t time_tCookieCreated = std::chrono::system_clock::to_time_t(tp);
        // strftime may returns 0 in case not enough buf len
        [[maybe_unused]] std::size_t timeStrLen = strftime(timeStrBuf, timeStrBufSize, Cookie::timeFormat, 
            std::localtime(&time_tCookieCreated));

        return std::string(timeStrBuf);
    }



    static
    std::chrono::time_point<std::chrono::system_clock> unformat(const std::string& formatStrTime)
    {
        struct tm tm; memset(&tm, 0, sizeof tm);
        strptime(formatStrTime.c_str(), Cookie::timeFormat, &tm);
        std::time_t calendarTime = mktime(&tm);
        return std::chrono::system_clock::from_time_t(calendarTime);
    }


    /**
     * considered param is a VALID `Set-Cookie' header value! 
     * NO CHECKING SEMANTIC PARSED COOKIE correctness 
     * */
    static Cookie 
    ParseSetCookieHeaderValue(const std::string& setCookieHeaderValue)
    {
        using namespace std::literals::string_literals;
        // Set-Cookie: <cookie-name>=<cookie-value>; Domain=<domain-value>; Secure; HttpOnly
        // non-terminal symbols : Domain; Secure; HttpOnly, Path, SameSize, 
        // Max-Age, Expires, Partitioned

        Cookie cookie = CreateDefaultCookie();

        // rfc 6265 section 4
#define cookieTokenValueRegex R"([\x21\x23-\x2B\x2D-\x3A\x3C-\x5B\x5D-\x7E]*)"
#define cookieValueRegex cookieTokenValueRegex "|\"" cookieTokenValueRegex "\")(?:;( .*))?";

#define cookieNameRegex R"([\x21-\x27\x2A-\x2E\x30-\x39\x41-\x5A\x5E-\x7A\x7E]+)"

        constexpr const char* setCookieRegexStr = "(" cookieNameRegex ")=(" cookieValueRegex // ")(?:;( .*))?;";

#undef cookieTokenValueRegex
#undef cookieValueRegex
#undef cookieNameRegex
        
        std::regex setCookieRegex(setCookieRegexStr);
        std::smatch setCookieMatchRes;
        if (std::regex_match(setCookieHeaderValue, setCookieMatchRes, setCookieRegex))
        {
            cookie.m_name = setCookieMatchRes[1].str();
            cookie.m_value = setCookieMatchRes[2].str();
        } else 
        {
            throw cookie_parse_error("Invalid set-cookie-string");
        }

        std::string::const_iterator cookieAvBegin = setCookieMatchRes[3].first;
        while (cookieAvBegin != setCookieHeaderValue.cend())
        {
            cookieAvBegin++; // skip whitespace between attrs

            std::string::const_iterator cookieAttrEnd = cookieAvBegin;

            while (cookieAttrEnd != setCookieHeaderValue.cend() && 
                *cookieAttrEnd != '=' && *cookieAttrEnd != ';')
            { 
                cookieAttrEnd++;
            }

            std::string_view cookieAttrName(&*cookieAvBegin, std::distance(cookieAvBegin, cookieAttrEnd));
            std::size_t cookieAttrNameLen = cookieAttrName.length();

            if (cookieAttrEnd != setCookieHeaderValue.cend() && *cookieAttrEnd == '=')
            {
                std::string_view cookieAttrNameLiteral;
                std::string* cookieAttrValuePtr = nullptr;
                if (strncasecmp("Domain", cookieAttrName.data(), cookieAttrNameLen))
                {
                    cookieAttrNameLiteral = "Domain";
                    cookieAttrValuePtr = &cookie.m_domain;
                } else if (strncasecmp("Path", cookieAttrName.data(), cookieAttrNameLen))
                {
                    cookieAttrNameLiteral = "Path";
                    cookieAttrValuePtr = &cookie.m_path;
                } else if (strncasecmp("SameSite", cookieAttrName.data(), cookieAttrNameLen))
                {
                    cookieAttrNameLiteral = "SameSite";
                    cookieAttrValuePtr = &cookie.m_sameSite;
                } else if (strncasecmp("Max-Age", cookieAttrName.data(), cookieAttrNameLen))
                {
                    cookieAttrNameLiteral = "Max-Age";
                    unsigned maxAge = 0ul;
                    std::from_chars_result fromChRes = std::from_chars(cookieAttrName.begin(), cookieAttrName.end(),
                        maxAge);
                    if (fromChRes.ec != std::errc{}) { throw cookie_parse_error("Max-Age attribute value too large"); }
                    cookie.m_expires = std::chrono::system_clock::now() + std::chrono::seconds(maxAge);
                } else if (strncasecmp("Expires", cookieAttrName.data(), cookieAttrNameLen))
                {
                    cookieAttrNameLiteral = "Expires"; 
                    cookie.m_expires = ParseDateAttribute({cookieAttrName.begin(), cookieAttrName.end()});
                } else 
                {
                    std::cerr << "Warning: skip unknown attribute: " << cookieAttrName;
                }

                if (cookieAttrValuePtr)
                {
                    std::string& cookieAttrValue = *cookieAttrValuePtr;
                    if (!cookieAttrValue.empty())
                    {
                        throw cookie_parse_error("Double "s.append(cookieAttrNameLiteral.begin(), cookieAttrNameLiteral.end()).append(" attr"));
                    }

                    cookieAvBegin = cookieAttrEnd;
                    while (cookieAttrEnd != setCookieHeaderValue.cend() && *cookieAttrEnd != ';')
                    {
                        cookieAttrEnd++;
                    }

                    if (cookieAttrEnd == setCookieHeaderValue.cend())
                    {
                        throw cookie_parse_error(std::string(cookieAttrNameLiteral).append(" attr expects value"));
                    }

                    cookieAttrValue.assign(cookieAvBegin + 1, cookieAttrEnd);
                }
            } else
            {
                if (strncasecmp("Secure", cookieAttrName.data(), cookieAttrNameLen))
                {
                    cookie.m_secure = true;
                } else if (strncasecmp("HttpOnly", cookieAttrName.data(), cookieAttrNameLen))
                {
                    cookie.m_httpOnly = true;
                } else 
                {
                    std::cerr << "Warning: skip unknown attribute: " << cookieAttrName;
                }
            }

            if (auto setCookieHeaderValueCend = setCookieHeaderValue.cend(); 
                    cookieAttrEnd != setCookieHeaderValueCend)
            {
                cookieAttrEnd++; if (cookieAttrEnd == setCookieHeaderValueCend) { throw cookie_parse_error("Bad set-cookie"s); }
            }

            cookieAvBegin = cookieAttrEnd;
        }

        return cookie;
    };



    /**
    *  @brief - https://httpwg.org/specs/rfc6265.html#cookie-path realization
    */
    
    static std::string
    ComputeCookieDefaultPath(const std::string_view uriPath)
    {
        if (uriPath.empty() || uriPath.front() != '/')
        {
            return "/";
        }

        std::size_t rightMostSlashPos =
            uriPath.rfind('/');

        if (rightMostSlashPos == 0ull)
        {
            return "/";
        }

        return std::string(uriPath.begin(), uriPath.begin() + rightMostSlashPos);
    };
};

std::string Cookie::defaultSameSiteValue = "None";



template <typename... Args>
std::string
CreateQuery(const char* queryFormat, Args&&... args)
{
    return boost::str((format(queryFormat) % ... % args));
};



int
StorageCookie(sqlite3* dbConn, Cookie&& cookie)
[[gnu::nonnull(1)]];



int
StorageCookie(sqlite3* dbConn, Cookie&& cookie)
{
    std::string sameCookieCondition = CreateQuery(" WHERE name='%s' AND path='%s' AND domain='%s';", 
        cookie.m_name.c_str(), cookie.m_path.c_str(), cookie.m_domain.c_str());
    std::string findExistCookieRq = std::string("SELECT creation_time FROM cookies") + sameCookieCondition;

    // callbackValue, number of columns, values of columns, names of columns
    auto callback_1 = [](void* callbackValue, int columnsNum, char** values, char** columnsNames){
        *reinterpret_cast<std::pair<int, std::string>*>(callbackValue) = std::make_pair(1, std::string(values[0]));
        return 0;
    };

    std::pair<int, std::string> pSameCookieExistFlag_ItsCreationTime;
    if (int queryExecCode = sqlite3_exec(dbConn, findExistCookieRq.c_str(), 
        +callback_1, reinterpret_cast<void*>(&pSameCookieExistFlag_ItsCreationTime), nullptr);
            queryExecCode != SQLITE_OK)
    {
        return queryExecCode;
    }

    findExistCookieRq.clear();

    std::string createdCookieTimeStr;
    if (pSameCookieExistFlag_ItsCreationTime.first)
    {
        std::string deleteOldCookieRq = std::string("DELETE FROM cookies") + sameCookieCondition;
        if (int queryExecCode = sqlite3_exec(dbConn, deleteOldCookieRq.c_str(), nullptr, nullptr, nullptr);
                queryExecCode != SQLITE_OK)
        {
            return queryExecCode;
        }
        
        createdCookieTimeStr = std::move(pSameCookieExistFlag_ItsCreationTime.second);
    } else
    {
        createdCookieTimeStr = Cookie::format(cookie.m_creationTime);
    }

    // TODO: Canonicalized Host Names!
    std::string insertCookieRq = CreateQuery("INSERT INTO cookies VALUES ("
        "'%s', '%s', "
        "'%s', '%s', "
        "'%s', '%s', "
        "'%s', '%s', "
        "'%s', "
        "%d, %d, %d, %d);", cookie.m_name.c_str(), cookie.m_value.c_str(), 
            cookie.m_domain.c_str(), cookie.m_path.c_str(), 
            Cookie::format(cookie.m_expires).c_str(), createdCookieTimeStr.c_str(), 
            Cookie::format(std::chrono::system_clock::now()).c_str(), cookie.m_sameSite.c_str(),
            cookie.m_cookieLocation.c_str(),
            static_cast<int>(cookie.m_hostOnly), static_cast<int>(cookie.m_secure),
            static_cast<int>(cookie.m_httpOnly), static_cast<int>(cookie.m_persistent));

    if (int queryExecCode = sqlite3_exec(dbConn, insertCookieRq.c_str(), nullptr, nullptr, nullptr);
            queryExecCode != SQLITE_OK)
    {
        return queryExecCode;
    }

    return 0;
};



std::string operator+(const std::string& str, url::pct_string_view&& pctStringView)
{
    std::string retStr(str);
    std::transform(pctStringView.cbegin(), pctStringView.cend(),
        std::back_inserter((retStr)), [](const typename url::pct_string_view::value_type& value) { return value; } );

    return retStr;
};



std::string to_string(const url::pct_string_view& pctStringView)
{
    std::string retStr; retStr.reserve(pctStringView.length());
    std::transform(pctStringView.cbegin(), pctStringView.cend(),
        std::back_inserter((retStr)), [](const typename url::pct_string_view::value_type& value) { return value; } );

    return retStr;
};



/**
 * @brief print cookies callback
 * */
int PrettyPrintCookies(void*, int, char** values, char** columnsNames)
{
    std::cout << values[0] << "=" << values[1];
    std::cout << "; Domain=" << values[2];
    std::cout << "; Path=" << values[3];

    std::cout << "; Expires=";
    if (std::atoi(values[9]))
    {
        std::cout << values[4];
    } else
    {
        std::cout << "Sessional";
    }

    std::cout << "; creation_time=" << values[5];
    std::cout << "; last_access_time" << values[6];

    if (std::atoi(values[8]))
    {
        std::cout << "; Secure";
    }

    if (std::atoi(values[9]))
    {
        std::cout << "; HttpOnly";
    }

    std::cout << '\n';
    return 0;
};



httplib::Result InvokeHTTPMethod(const std::string& method, 
    httplib::Client& client, const std::string& path, 
    const httplib::Headers& headers, 
    const char* body = nullptr, std::size_t content_length = 0ull,
    const std::string& content_type = std::string())
{
    httplib::Result res;
    static cooker_HTTP_ns::method_hash requestMethodHasher;
    using namespace cooker_HTTP_ns;

    switch (requestMethodHasher(static_cast<std::string_view>(method)))
    {
        case OPTIONS_hv :
        {
            res = client.Options(path, headers);
            break;
        }
        case GET_hv :
        {
            res = client.Get(path, headers, 
                // reject main document downloading!
                []([[maybe_unused]] const char* responseBody, [[maybe_unused]] std::size_t resBodySize) { return true; });
            break;
        }
        case HEAD_hv :
        {
            res = client.Head(path);
            break;
        }
        case POST_hv :
        {
            if (body != nullptr)
            {
                res = client.Post(path, headers, body, content_length, content_type);
            } else
            {
                res = client.Post(path, headers);
            }
            break;
        }
        case PUT_hv :
        {
            res = client.Put(path, headers, body, content_length, content_type);
            break;
        }
        case DELETE_hv :
        {
            if (body != nullptr)
            {
                res = client.Delete(path, headers, body, content_length, content_type);
            } else
            {
                res = client.Delete(path, headers);
            }
            break;
        }
        case PATCH_hv :
        {
            res = client.Patch(path, headers, body, content_length, content_type);
            break;
        }
        case CONNECT_hv :
        {
            // if (body != nullptr)
            // {
            //  res = client.Connect(path, headers, body, content_length, content_type);
            // }
        }
        default:
        {
            std::cerr << "Unavailable http request method\n";
            std::exit(EXIT_FAILURE);
        }
    }

    return res;
};



using http = httplib::StatusCode;
void TransformRedirectedMethod(std::string& method, int statusCode,
    [[maybe_unused]] httplib::Headers& headers)
{
    if (cooker_HTTP_ns::IsHttpStatusCodeInList(statusCode,
            { http::MovedPermanently_301, http::Found_302, http::SeeOther_303}) && method != cooker_HTTP_ns::GET)
    {
        if (method != "HEAD" || method != "OPTIONS") // request methods without body
        {
            headers.erase("Content-Type");
            headers.erase("Content-Length");
        }

        method = "GET";
    }
};



void CookerLogger(const httplib::Request& req, const httplib::Response& res, 
    int verboseMode);



bool TableExists(sqlite3* dbConn, std::string_view tableName)
[[gnu::nonnull(1)]];



int RemoveObseleteCookies(sqlite3* dbConn, [[maybe_unused]] const std::string& domain)
[[gnu::nonnull(1)]];



std::string GetCookieHeaderValue(sqlite3* dbConn, const std::string& host,
    const std::string& path, bool isHttps)
[[gnu::nonnull(1)]];



[[gnu::always_inline]] inline std::string StringViewToString(std::string_view view);



int main(int argc, char const *argv[])
{
    std::string method = "GET"
        , requestUrl
        , defaultSameSite
        , data
        , header
        , strCaCertFilepath
        , sqliteDBFilepath;


    std::size_t numMaxRedirection = 10; // by default

    bool isShowHelpTip = false
        , followRedirect = false
        , verboseMode = false
        , preloadCookies = false;

    httplib::Headers defaultRequestHeaders;

    auto cliParser = lyra::cli()
    // TODO: add output!
        | lyra::help(isShowHelpTip)
            ("Show this tip")
        | lyra::opt(followRedirect)
            ["--follow-redirect"]["-L"]
            ("Automatic redirection to 3xx http status code location value")
                .optional()
        | lyra::opt(sqliteDBFilepath, "sqlite3 database")
            ["--database"]
            ("sqlite database file")
                .optional()
        | lyra::opt(verboseMode)
            ["--verbose"]["-v"]
            ("Verbose mode")
                .optional()
#if defined CPPHTTPLIB_OPENSSL_SUPPORT
        | lyra::opt(strCaCertFilepath, "certificate path")
            ["--ssl_cert"]["-s"]
            ("Certificate path")
                .optional()
#endif // CPPHTTPLIB_OPENSSL_SUPPORT
        | lyra::opt(numMaxRedirection, "number")
            ["--max_redir"]["-M"]
            ("Number max redirection")
                .optional()
        | lyra::opt(preloadCookies)
            ["--preload"]["-l"]
            ("Preload cookies before request")
        | lyra::opt(defaultSameSite, "default `SameSite' value")
            ["--default-samesite"]["-s"]
            ("Default `SameSize' value of cookie")
                .optional().choices("same", "lax", "none")
        | lyra::opt([&](std::string header) {
                const std::size_t keyValueDelimPos = header.find(':');
                assert(keyValueDelimPos != std::string::npos);
                defaultRequestHeaders.emplace(header.substr(0, keyValueDelimPos),
                    header.substr(keyValueDelimPos + 1));
            }, "<header key : header value>")
            ["--header"]["-H"]
            ("Specify HTTP header")
                .cardinality(0,0)
        | lyra::group([&](const lyra::group&) {
            })  | lyra::opt(method, "request method")
                    ["-X"]
                    ("HTTP method")
                        .optional()
                | lyra::opt(data, "request body")
                    ["--data-raw"]["-d"]
                    ("HTTP request content")
                        .optional()
        | lyra::arg(requestUrl, "url")
            ("Destination url request").required();

    auto parseResult = cliParser.parse({argc, argv});
    if (!parseResult || isShowHelpTip)
    {
        std::cout << cliParser;
        return isShowHelpTip ? EXIT_SUCCESS : 
            EXIT_FAILURE;
    }

    if (!defaultSameSite.empty()) 
    {
        Cookie::defaultSameSiteValue = 
            std::move(defaultSameSite);
    }

    if (sqliteDBFilepath.empty())
    {
        sqliteDBFilepath = "_cookies.sqlite3.db";
    }

    std::for_each(method.begin(), method.end(), [](char& ch) { ch = std::toupper(ch); });
    
    struct DBConnCloser
    {
        void operator()(sqlite3* sqliteConn) const noexcept
        {
            /*  If sqlite3_close_v2() is called with unfinalized prepared statements, 
                unclosed BLOB handlers, and/or unfinished sqlite3_backups, 
                it returns SQLITE_OK regardless, but instead of deallocating the database connection immediately, 
                it marks the database connection as an unusable "zombie" and 
                makes arrangements to automatically deallocate the database connection after all prepared statements 
                are finalized, all BLOB handles are closed, and all backups have finished. 
            */
            if (int closeConnExecCode = sqlite3_close(sqliteConn); closeConnExecCode != SQLITE_OK)
            {
                std::cerr << "Cannot close sqlite3 connection: " << sqlite3_errstr(closeConnExecCode) << std::endl;
            }
        }
    };

    int openDBConnFlags = SQLITE_OPEN_READWRITE | SQLITE_OPEN_FULLMUTEX;

    if (!std::filesystem::exists(sqliteDBFilepath)) // if not exists
    {
        openDBConnFlags |= SQLITE_OPEN_CREATE;
    }

    sqlite3* cookiesStoragePtr = nullptr;
    if (sqlite3_open_v2(sqliteDBFilepath.c_str(), &cookiesStoragePtr, 
            openDBConnFlags, nullptr) != SQLITE_OK)
    {
        std::cerr << "Cannot open sqlite3 connection!\n";
        return EXIT_FAILURE;
    }

    std::shared_ptr<sqlite3> cookiesStorage(std::exchange(cookiesStoragePtr, nullptr), DBConnCloser());

    if (not ((openDBConnFlags & SQLITE_OPEN_CREATE) || TableExists(cookiesStorage.get(), "cookies")))
    {
        constexpr const char* createCookiesTableRq = "CREATE TABLE cookies ("
            "name VARCHAR(255) NOT NULL,"
            "value VARCHAR(255) NOT NULL,"
            "domain VARCHAR(127) NOT NULL,"
            "path VARCHAR(127) NOT NULL,"
            "expires VARCHAR(63) NOT NULL,"
            "creation_time VARCHAR(63) NOT NULL,"
            "last_access_time VARCHAR(63) NOT NULL,"
            "sameSize VARCHAR(15) NOT NULL,"
            "cookie_location VARCHAR(255) NOT NULL,"
            "host INT NOT NULL,"
            "secure INT NOT NULL,"
            "httpOnly INT NOT NULL,"
            "persistent INT NOT NULL);";

        if (sqlite3_exec(cookiesStorage.get(), createCookiesTableRq, nullptr, nullptr, nullptr) != SQLITE_OK)
        {
            std::cerr << "Cannot create table `cookies': " << sqlite3_errmsg(cookiesStorage.get()) << std::endl;
            return EXIT_FAILURE;
        }
    }
    
    auto TryAddHeader = [&defaultRequestHeaders](std::string_view keyView, std::string_view valueView){
        auto key = StringViewToString(keyView);
        if (defaultRequestHeaders.find(key) == defaultRequestHeaders.cend())
        {
            defaultRequestHeaders.emplace(std::move(key), StringViewToString(valueView));
        }
    };

    // check method correctness :
    // -H 'Sec-Fetch-Dest: document'
    // -H 'Sec-Fetch-Mode: navigate' 
    // -H 'Sec-Fetch-Site: cross-site' 
    // -H 'Priority: u=0, i'
    TryAddHeader("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8");
    TryAddHeader("Accept-Language", "en-US;q=1");
    TryAddHeader("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:134.0) Gecko/20100101 Firefox/134.0");

    auto OverwriteHeader = [&defaultRequestHeaders](std::string_view keyView, std::string_view valueView){
        auto key = StringViewToString(keyView);
        auto value = StringViewToString(valueView);
        if (httplib::Headers::iterator headerIter = defaultRequestHeaders.find(key);
                headerIter != defaultRequestHeaders.end())
        {
            httplib::Headers::value_type& header = *headerIter;
            header.second = std::move(value);
        } else
        {
            defaultRequestHeaders.emplace(std::move(key), std::move(value));
        }
    };

    bool isFirstReq = true;
    
    httplib::Result httpResult;
    while (isFirstReq || ((http::MultipleChoices_300 < httpResult->status && httpResult->status < http::MultipleChoices_300 + 99) &&
        numMaxRedirection-- > 0 && followRedirect))
    {
        if (!isFirstReq)
        {
            httplib::Response& res = *httpResult;
            
            std::string locationUrl = res.get_header_value("Location");
            std::string linkHeaderValue = res.get_header_value("Link"); // not case sensitive

            if (!linkHeaderValue.empty())
            {
                // x-default
                // if link includes rel='alternative'
                // link: <url>; key1=value1;...keyN=valueN,...

                constexpr auto npos = std::string::npos;
                constexpr const char* whitespaceDelims = "\t ";
                std::size_t linkHeaderUrlStartPos = locationUrl.find(',');
                if (linkHeaderUrlStartPos == npos) { linkHeaderUrlStartPos = locationUrl.length(); }
                std::string_view linkHeaderUrl(locationUrl.data(), linkHeaderUrlStartPos);

                std::size_t tokenBeginPos = locationUrl.find('<');
                if (tokenBeginPos == npos)
                {
                    std::cerr << "Invalid link http header value\n";    
                } else 
                {
                    std::size_t tokenEndPos = linkHeaderUrl.find('>', tokenBeginPos + 1);
                    if (tokenEndPos == npos)
                    {
                        std::cerr << "Invalid link http header value\n";
                    }; tokenEndPos++;

                    std::string_view url(linkHeaderUrl.data() + tokenBeginPos, tokenEndPos - tokenBeginPos);
                    // skip until `;'
                    
                    tokenBeginPos = linkHeaderUrl.find_first_not_of(whitespaceDelims, tokenEndPos);
                    bool linkIsAlternative = false;
                    while (tokenBeginPos == npos)
                    {
                        if (linkHeaderUrl[tokenBeginPos] != ';')
                        {
                            std::cerr << "Error parsing link http header value: syntax error\n";
                            /* finish */
                        }; tokenBeginPos++;

                        tokenEndPos = linkHeaderUrl.find(';', tokenBeginPos);
                        if (tokenEndPos == npos) { tokenEndPos == linkHeaderUrl.length(); }

                        std::string_view token = linkHeaderUrl.substr(tokenBeginPos, tokenEndPos - tokenBeginPos);
                        std::regex keyValuePairRegex("\\s*(\\w+)\\s*=\\s*(['\"])(\\w+)\2\\s*");
            
                        std::match_results<std::string_view::iterator> matchRes;
                        if (std::regex_match(token.begin(), token.end(), matchRes, keyValuePairRegex))
                        {
                            std::string_view key(matchRes[1].first, matchRes[1].length())
                                , value(matchRes[3].first, matchRes[3].length());
                            if (key == "rel")
                            {
                                if (value == "alternative")
                                {
                                    if (linkIsAlternative)
                                    {
                                        std::cerr << "Double rel param in link http header value\n";
                                        // TODO: finish
                                    }

                                    linkIsAlternative = true;
                                }
                            }
                        } else 
                        {
                            std::cerr << "Error parsing link http header value: syntax error\n";
                            break;
                        }
                    }
                }
            }

            if (locationUrl.empty())
            {
                std::cerr << "Error: redirection response status code but no location header!\n";
                return EXIT_FAILURE;
            }

            result<url::url_view> parseLocationUrlViewResult = url::parse_uri_reference(locationUrl);

            if (!parseLocationUrlViewResult.has_value())
            {
                std::cerr << "Warning: location header value is not valid url!\n";
                return EXIT_FAILURE;
            }

            url::url_view locationUrlView = parseLocationUrlViewResult.value();

            if (locationUrlView.has_scheme()) // url
            {
                requestUrl = locationUrl;
            } else if (locationUrlView.is_path_absolute()) // absolute path
            {
                cooker_url_utils_ns::ReplaceUrlResource(requestUrl, locationUrl);
            } else // relative path
            {
                cooker_url_utils_ns::RemoveQueryAndFrag(requestUrl); 
                cooker_url_utils_ns::AppendPath(requestUrl, locationUrl);
            }

            TransformRedirectedMethod(method, httpResult->status, defaultRequestHeaders);
            defaultRequestHeaders.erase("Cookie");
        }

        /* origin   = scheme://authority */
        /* resource = /path?query#fragment */
        /* target   = /path?:query */
        boost::system::result<url::url_view> parseUrlResult = url::parse_absolute_uri(requestUrl);
        if (!parseUrlResult.has_value())
        {
            std::cerr << "Invalid url!\n";
            return EXIT_FAILURE;
        }

        url::url_view urlView = parseUrlResult.value();

        // TODO: what do with ipv4 and ipv6
        // how storage cookie, what its value domain?
        if (urlView.host_type() != url::host_type::name)
        {
            std::cerr << "Invalid host type: must host_type::name!" 
                << std::endl;
            return EXIT_FAILURE;
        }

        std::string path = urlView.path()
                  , host = urlView.host();
        std::string scheme;

        if (path.empty())
        {
            path = "/";
        }

        if (urlView.scheme_id() == url::scheme::http ||
                urlView.scheme_id() == url::scheme::https)
        {
            scheme = urlView.scheme();
        } else if (urlView.scheme_id() == url::scheme::unknown)
        {
            scheme = "http";
        } else
        {
            std::cerr << "Unavailable scheme: only http/https possible!\n";
            return EXIT_FAILURE;
        }

        // origin = <scheme://host:port>
        url::pct_string_view pctOrigin = urlView.encoded_origin();
        std::string origin(pctOrigin.cbegin(), pctOrigin.cend());
        httplib::Client simpleClient(origin);
        simpleClient.set_logger(std::bind(CookerLogger, std::placeholders::_1, std::placeholders::_2, verboseMode));

#if defined CPPHTTPLIB_OPENSSL_SUPPORT
        if (simpleClient.is_ssl())
        {
            if (strCaCertFilepath.empty())
            {
                std::cerr << "Error: Certificate path must be specified!\n";
                return EXIT_FAILURE;
            }
            
            simpleClient.set_ca_cert_path(strCaCertFilepath);
        }
#endif // CPPHTTPLIB_OPENSSL_SUPPORT

#if defined CPPHTTPLIB_ZLIB_SUPPORT
        simpleClient.set_compress(true);
#endif // CPPHTTPLIB_ZLIB_SUPPORT

        if (preloadCookies || !isFirstReq)
        {
            if (RemoveObseleteCookies(cookiesStorage.get(), host) != 0)
            {
                std::cerr << "Remove obselete cookies failed: <unknown error>\n";
                return EXIT_FAILURE;
            }

            std::string cookieHeaderValue = GetCookieHeaderValue(cookiesStorage.get(), host, path,
                urlView.scheme_id() == url::scheme::https);
            
            constexpr const char* cookieHeaderKey = "Cookie";
            defaultRequestHeaders.emplace(cookieHeaderKey, std::move(cookieHeaderValue));
        }

        std::cout << "> " << method << " " << requestUrl << "...\n\n";

        httpResult = InvokeHTTPMethod(method, simpleClient,
            path, defaultRequestHeaders, !data.empty() ? data.c_str() : nullptr, data.length());

        if (!httpResult)
        {
            std::cerr << "> " << method << " " << requestUrl << " failed! " << 
                httplib::to_string(httpResult.error()) << "\n\n";
            return EXIT_FAILURE;
        }

        // std::vector<std::future<int>> vecFt;

        httplib::Response& res = *httpResult;
        for (auto&& [setCookieHeaderIter, endRange] = res.headers.equal_range("Set-Cookie"); 
                setCookieHeaderIter != endRange; ++setCookieHeaderIter)
        {
            const httplib::Headers::value_type& setCookieHeader = 
                *setCookieHeaderIter;
            try
            {
                Cookie cookie = Cookie::ParseSetCookieHeaderValue(setCookieHeader.second);

                Cookie::CheckCookiePolicy(cookie, urlView.path(), urlView.scheme(), urlView.host());

                boost::string_view cookieLocation = urlView.buffer();
                cookie.m_cookieLocation.assign(cookieLocation.cbegin(), cookieLocation.cend());
                StorageCookie(cookiesStorage.get(), std::move(cookie));
                // vecFt.emplace_back(std::async(lauchPolicy, &StorageCookie, dbConn, std::move(cookie)));
            } catch(const Cookie::cookie_error& cookiePolicyError)
            {
                std::cerr << "Warning: Cookie (" << setCookieHeader.second << ") from "  << urlView.buffer() << 
                    " is REJECTED. Reason: " <<
                        cookiePolicyError.what() << "\n\n";
            }
        }

        isFirstReq = false;
    }

    return EXIT_SUCCESS;
}



void CookerLogger(const httplib::Request& req, const httplib::Response& res, 
    int verboseMode)
{
    std::cout << "> " << req.method << ' ' << req.path << ' ' << res.version << '\n';
    if (verboseMode)
    {
        for (const auto& [key, value] : req.headers)
        {
            std::cout << "> " << key << ": " << value << '\n';
        }           
    }
    std::cout << ">\n";

    std::cout << "< " << res.version << ' ' << res.status << ' ' << res.reason << '\n';
    if (verboseMode)
    {
        for (const auto& [key, value] : res.headers)
        {
            std::cout << "< " << key << ": " << value << '\n';
        }           
    }
    std::cout << "<\n";
};



int RemoveObseleteCookies(sqlite3* dbConn, [[maybe_unused]] const std::string& domain)
{
    /* @a domain for remove specified domain cookies */
    bool hasObselete = false;
    // TODO: comparing date by no place
    std::string deleteCookiesRq = "DELETE FROM cookies WHERE ROWID IN (";
    if (sqlite3_exec(dbConn, "SELECT ROWID, expires FROM cookies", +[](void* rawArg, int, char** values, char** columnsNames){
            std::string& arg = *reinterpret_cast<std::string*>(rawArg);
            if (Cookie::unformat(values[1]) < std::chrono::system_clock::now())
            {
                arg.append(values[1]).push_back(',');
            }

            return 0;
        }, reinterpret_cast<void*>(&deleteCookiesRq), nullptr) != SQLITE_OK)
    {
        return -1;
    }

    if (deleteCookiesRq.back() != '(')
    {
        deleteCookiesRq.pop_back(); // remove tail `,'
        deleteCookiesRq.append(");");

        return sqlite3_exec(dbConn, deleteCookiesRq.c_str(), nullptr, nullptr, nullptr) == SQLITE_OK 
            ? 0 : -1;
    }

    return 0;
}



std::string GetCookieHeaderValue(sqlite3* dbConn, const std::string& host,
    const std::string& path, bool isHttps)
{   
    const char* ptrHost              = host.c_str();
    const char* ptrSecondLevelDomain = ptrHost +
        host.rfind('.', host.rfind('.') - 1) + 1;

    // TODO: not select obselete cookies
    std::string selectCookiesRq = boost::str(format(
        "SELECT ROWID, name, value, path "
        "FROM cookies "
        "WHERE domain='%1%' AND host=1 OR domain LIKE '%%%2%' AND host=0") %
            host % ptrSecondLevelDomain);
    
    if (isHttps)
    {
        selectCookiesRq += " AND secure=1";
    }

    selectCookiesRq.push_back(';');
    
    std::string cookieHeaderValue;
    std::string condRowidIN = " WHERE ROWID IN (";
    
    auto AppendCookieCallback = [&cookieHeaderValue, &condRowidIN, &path](int, char** values, char** columnsNames) -> int {
        std::string_view cookiePath(values[3]);
        const std::size_t cookiePathLen = cookiePath.length();
        // c++20 starts_with implementation
        if (cookiePathLen <= path.length() && 
                (path.compare(0, cookiePathLen, cookiePath) == 0))
        {
            cookieHeaderValue.append(values[1]).append("=").append(values[2]).push_back(';');
            condRowidIN.append(values[0]);
            condRowidIN.push_back(',');
        }
        return 0;
    };

    typedef decltype(AppendCookieCallback) Callback_t;

    if (sqlite3_exec(dbConn, selectCookiesRq.c_str(), 
            +[](void* appendCookieCallback, int columnsNum, char** values, char** columnsNames){
                return reinterpret_cast<Callback_t*>(appendCookieCallback)->operator()(columnsNum, values, columnsNames);
            }, reinterpret_cast<void*>(&AppendCookieCallback), nullptr) != SQLITE_OK)
    {
        throw std::runtime_error("SQL request failed!");
    }

    if (!cookieHeaderValue.empty()) /* cookie has been added */
    {
        cookieHeaderValue.pop_back(); // remove symbol `;'
        condRowidIN.pop_back(); /* remove symbol `,' */
        condRowidIN.append(");");

        std::string updateCookiesLastAccessDateRq = boost::str(format("UPDATE cookies SET last_access_time='%1%' %2%") %
            Cookie::format(std::chrono::system_clock::now()) % condRowidIN);

        if (sqlite3_exec(dbConn, updateCookiesLastAccessDateRq.c_str(), nullptr, nullptr, nullptr) != SQLITE_OK)
        {
            throw std::runtime_error("SQL request failed!");
        }
    }

    return cookieHeaderValue;
}



using namespace std::literals::chrono_literals;
bool TableExists(sqlite3* dbConn, std::string_view tableName)
{
    constexpr const char* checkTableExistRq = 
        "SELECT name FROM sqlite_master WHERE type='table' AND name=@tableName"; // tableName
    bool isTableExists = false;
    sqlite3_stmt* dbStmtRawPtr = nullptr;

    if (sqlite3_prepare_v2(dbConn, checkTableExistRq, -1,
            &dbStmtRawPtr, nullptr) != SQLITE_OK)
    {
        throw std::runtime_error(
            std::string("sqlite API (sqlite3_prepare()) error: ") + sqlite3_errmsg(dbConn));
    }

    struct SqliteStmtFinalizer
    {
        void operator()(sqlite3_stmt* dbStmtRawPtr) const noexcept
        {
            sqlite3_finalize(dbStmtRawPtr);
        };
    };

    std::unique_ptr<sqlite3_stmt, SqliteStmtFinalizer> dbStmt(
        dbStmtRawPtr, SqliteStmtFinalizer());

    if (sqlite3_bind_text(dbStmt.get(), 1, tableName.data(), tableName.length() * sizeof(std::string_view::value_type),
            SQLITE_STATIC) != SQLITE_OK)
    {
        throw std::runtime_error(
            std::string("sqlite API (sqlite3_bind_()) error: ") + sqlite3_errmsg(dbConn));
    }

    int stmtStepCode = SQLITE_OK;
    while (stmtStepCode != SQLITE_DONE)
    {
        stmtStepCode = sqlite3_step(dbStmt.get());
        switch(stmtStepCode)
        {
            case SQLITE_BUSY:
                std::this_thread::sleep_for(100ms);
                break;
            case SQLITE_ROW:
                isTableExists = true;
                stmtStepCode = SQLITE_DONE;
                break;
            case SQLITE_DONE:
                break;
            default:
                throw std::runtime_error(
                    std::string("sqlite API (sqlite3_step()) error: ") + sqlite3_errmsg(dbConn));
        }       
    }

    return isTableExists;
};



#if defined TESTING
void TableExists_test()
{
    sqlite3* dbConn;
    
    sqlite3_open_v2("./test_db", &dbConn, 
            SQLITE_OPEN_CREATE | SQLITE_OPEN_READWRITE, nullptr);

    sqlite3_exec(dbConn, "CREATE TABLE t_one(t_name VARCHAR(2));", nullptr, nullptr, nullptr);
    sqlite3_exec(dbConn, "CREATE TABLE t_two(t_name VARCHAR(2));", nullptr, nullptr, nullptr);
    sqlite3_exec(dbConn, "CREATE TABLE t_three(t_name VARCHAR(2));", nullptr, nullptr, nullptr);

    assert(TableExists("t_one") && "not passed 1");
    assert(TableExists("t_two") && "not passed 2");
    assert(TableExists("t_three") && "not passed 3");
};
#endif // TESTING



std::string StringViewToString(std::string_view view)
{
    return std::string(view.data(), view.length());
};