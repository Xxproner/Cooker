#include <stdlib.h> // exit()
#include <time.h> // localtime_r() strptime()
#include <string.h> // strncasecmp()
#include <ctype.h> // tolower(), isdigit()
#include <errno.h> // strerror(), errno
#include <assert.h>
#include <sys/stat.h>

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
#include <forward_list>
#include <algorithm> // find_if_not()
#include <initializer_list>
#include <bitset>
#include <charconv> // from_chars()
#include <set>
#include <filesystem>
#include <functional> // bind()
#include <memory>
#include <future> // async()


template <typename Enum>
auto to_underlying(Enum e)
{
	return static_cast<
		typename std::underlying_type<Enum>::type>(e);
}


#define CPPHTTPLIB_OPENSSL_SUPPORT
#define CPPHTTPLIB_ZLIB_SUPPORT
#include "httplib.h"


#include "boost/url.hpp"
#include "boost/url/pct_string_view.hpp"
namespace url = boost::urls;
#include "boost/utility/string_view.hpp"

#include "boost/tti/has_member_function.hpp"
#include "boost/system.hpp"

#include "lyra.hpp"



template <typename T>
using result = boost::system::result<T>;


namespace cooker_url_utils_ns
{
	std::pair<std::string, std::string>
	SplitUrlIntoOriginAndPath(const std::string& url, url::url_view& parsedUrl)
	{
		using pStr = std::pair<std::string, std::string>;
		boost::system::result<url::url_view> parseUrlResult = url::parse_uri_reference(url);
		if (!parseUrlResult)
		{
			throw std::runtime_error("Invalid url!");
		}
		parsedUrl = parseUrlResult.value();

		// TODO: change it
		if (parsedUrl.host_type() != url::host_type::name)
		{
			throw std::runtime_error("Invalid host type: must host_type::name!");
		}

		return pStr(parsedUrl.encoded_origin(), parsedUrl.path());
	};



	/* site is allowed set the domain or it's subdomains */
	bool
	IsSubdomain(const std::string& potentialSubdomain, 
		const std::string& domain)
	{
		const auto potentialSubdomain_len = potentialSubdomain.length(),
			domain_len = domain.length();

		if (potentialSubdomain_len < domain_len)
		{
			return false;
		} else if (potentialSubdomain_len == domain_len)
		{
			return potentialSubdomain == 
				domain;
		} // else ...

		const auto diff_len = potentialSubdomain.length() - 
			domain.length();
		return potentialSubdomain.compare(
			diff_len, std::string::npos, domain) == 0 && 
				potentialSubdomain[diff_len - 1] == '.';
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
		std::size_t replacingPos = url.find('/');
		if (replacingPos == npos)
		{
			replacingPos = url.length();
		}

		url.replace(replacingPos, npos, replacingResource);
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
	const char* PUT = "PUT";
	const char* GET = "GET";
	const char* HEAD = "HEAD";
	const char* OPTIONS = "OPTIONS";
	const char* POST = "POST";
	const char* PATCH = "PATCH";
	const char* DELETE = "DELETE";
	const char* TRACE = "TRACE";
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
		POST_hv,
		OPTIONS_hv,
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
}; // HTTP_cooker


namespace cooker_details
{
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



	bool starts_with_case(const char* lhs, std::size_t lhs_len, 
		const char* rhs, std::size_t rhs_len)
	{
		// basic_string_view(data(), std::min(size(), sv.size())) == sv
		if (lhs_len < rhs_len)
		{
			return false;
		}

		return strncasecmp(lhs, rhs, rhs_len) == 0;
	};



	bool starts_with(const char* lhs, std::size_t lhs_len, 
		const char* rhs, std::size_t rhs_len)
	{
		// basic_string_view(data(), std::min(size(), sv.size())) == sv
		if (lhs_len < rhs_len)
		{
			return false;
		}

		return std::strncmp(lhs, rhs, rhs_len) == 0;
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
};



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



	Cookie(Cookie&& cookie)
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



	Cookie& operator=(Cookie&& cookie)
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



	class cookie_policy_error : public std::runtime_error
	{
	public:
		cookie_policy_error(const char* err_msg)
			: runtime_error(err_msg)
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
		cookie.m_secure 				= false;
		cookie.m_httpOnly 				= false;
		cookie.m_persistent 			= false;
		cookie.m_partitioned 			= false;
		cookie.m_hostOnly 				= false;

		cookie.m_creationTime 			= std::chrono::system_clock::now();
	  	cookie.m_sameSite 				= GetDefaultSameSiteValue();
		return cookie;
	}



	static bool
	PolicyCookiePath(const std::string& cookiePath, 
		const std::string& path)
	{
		// if (cookiePath.empty())
		// {
		// 	return true;
		// }

		auto IsLowerLevelPath = [](const std::string& potentialLowerLevelPath, 
			const std::string& path){
			return cooker_details::starts_with(potentialLowerLevelPath.c_str(), potentialLowerLevelPath.length(),
				path.c_str(), path.length());
		};

		if (!IsLowerLevelPath(path, cookiePath))
		{
			return false;
		}

		return true;
	};



	static
	void CheckCookiePolicy(Cookie& cookie, const url::url_view& boostUrlView)
	{
		if (cookie.m_path.empty() || (cookie.m_path[0] != '/'))
		{
			cookie.SetDefaultPath(boostUrlView.path());
		}

		if (cookie.m_secure && boostUrlView.scheme() != "https") 
		{
			constexpr const char* SecureAttrFromHTTPError = "Insecure site "
					 "cannot set cookies with the `Secure' attribute!"; 
			throw Cookie::cookie_policy_error(SecureAttrFromHTTPError);
		}


		std::string urlHost = boostUrlView.host();

		// public prefix must be rejected!
		if (cookie.m_domain.find('.') == std::string::npos)
		{
			throw Cookie::cookie_policy_error("Public prefix cannot be domain-attribute value!");
		}

		if (!cookie.m_domain.empty() && 
				!cooker_url_utils_ns::IsSubdomain(urlHost, cookie.m_domain))
		{
			throw Cookie::cookie_policy_error("Only the current domain can be set as the value,"
				" or a domain of a higher order");
		} else if (cookie.m_domain.empty())
		{
			cookie.m_hostOnly = true;
			cookie.m_domain = std::move(urlHost);
		} else 
		{
			/* convert the cookie-domain to lower case */
			for (auto& ch : cookie.m_domain)
			{
				ch = std::tolower(ch);
			}
		}

		if (cookie.m_partitioned && !cookie.m_secure)
		{
			if (!cookie.m_secure)
			{
				throw Cookie::cookie_policy_error("Partitioned attribute "
					"must be set with `Secure'");
			}
		}
	}



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
					std::from_chars(c_str		, c_str + 2, parsedTime.tm_hour);
					std::from_chars(c_str + 3	, c_str + 5, parsedTime.tm_min );
					std::from_chars(c_str + 6	, c_str + 8, parsedTime.tm_sec );
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

			tokenStartPos 	= std::find_if_not(tokenEndPos, httpDate_cend, IsDelimiter);
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
		std::string timeString; timeString.resize(48);
		time_t time_tCookieCreated = std::chrono::system_clock::to_time_t(tp);
		strftime(timeString.data(), timeString.size(), Cookie::timeFormat, 
			std::localtime(&time_tCookieCreated));
		return timeString;
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
		// Set-Cookie: <cookie-name>=<cookie-value>; Domain=<domain-value>; Secure; HttpOnly
		// non-terminal symbols : Domain; Secure; HttpOnly, Path, SameSize, 
		// Max-Age, Expires, Partitioned

		Cookie cookie = Cookie::CreateDefaultCookie();

		/* parsing */
		/* parse <cookie-name>=<cookie-value> */
		constexpr char delim 	= ';';
		std::size_t delimPos    = setCookieHeaderValue.find(delim)
				  , oldDelimPos = setCookieHeaderValue.find_first_not_of(" ");

		// only <name>=<value>
		const bool isCommonCookie = delimPos == std::string::npos;

		std::string_view cookieNameAndValue(setCookieHeaderValue.data() + oldDelimPos, 
			(isCommonCookie ? setCookieHeaderValue.length() : delimPos) - oldDelimPos);
		std::size_t cookieNameValueDelimPos = cookieNameAndValue.find('=');
		/* considered it is success */
		const char* hostPrefix = "__Host-";
		const char* securePrefix = "__Secure-";

		/* not possible both! */
		bool 	cookieHasSecurePrefix = false,
				cookieHasHostPrefix = false;
		std::size_t cookieNamePos = oldDelimPos;
		if (cooker_details::starts_with_case(cookieNameAndValue.data(), cookieNameAndValue.length(),
				hostPrefix, std::strlen(hostPrefix)))
		{
			cookieHasHostPrefix = true;
			cookieNamePos += std::strlen(hostPrefix);
		} else if (cooker_details::starts_with_case(cookieNameAndValue.data(), cookieNameAndValue.length(),
				securePrefix, std::strlen(securePrefix)))
		{
			cookieHasSecurePrefix = true;
			cookieNamePos += std::strlen(securePrefix);
		}

		cookie.m_name = cookieNameAndValue.substr(cookieNamePos, cookieNameValueDelimPos - cookieNamePos);
		cookie.m_value = cookieNameAndValue.substr(cookieNameValueDelimPos + 1);
		/* end parsing <cookie-name>=<cookie-value> */

		if (isCommonCookie)
		{
			return cookie;
		}

		std::string maxAge
			, expires
			, sameSite;

		/* case insensitive! */
		using PairValue_T = std::pair<const char*, std::string& >;
		PairValue_T valuedCookieNonTerminals[5] =
			{ {"Domain"		, cookie.m_domain	}, {"Path"		, cookie.m_path	}, 
			  {"SameSite"	, sameSite			}, {"Expires"	, expires		}, 
			  {"Max-Age"	, maxAge			}
			};
		
		using PairOption_T = std::pair<const char*, bool&>;
		PairOption_T optionedCookieNonTerminals[3] =
			{ {"HttpOnly"	, cookie.m_httpOnly		}, {"Secure", cookie.m_secure}, 
			  {"Partitioned", cookie.m_partitioned	}
			};

		auto FindInContainer = [](const auto& value, const auto& storage,
				auto comparer){
			
			using storage_T = decltype(storage);
			using value_T   = decltype(value);

			if constexpr (has_member_function_find<storage_T, value_T>::value)
			{
				return storage.find(value);
			}

			auto iter = std::cbegin(storage);
			for ( ; iter != std::cend(storage); ++iter)
			{
				if (comparer(*iter, value))
				{
					break;
				}
			}

			return iter; 
		};

		constexpr CookieTokenComparer cookieTokenComparer;
		delimPos = setCookieHeaderValue.find(delim, oldDelimPos = delimPos + 1);
		while (delimPos != std::string::npos)
		{
			std::string_view setCookieHeaderToken = 
				std::string_view(setCookieHeaderValue.data() + oldDelimPos, delimPos - oldDelimPos);
			setCookieHeaderToken = cooker_details::TrimPrefixWhitespace(setCookieHeaderToken);
			auto token = FindInContainer(setCookieHeaderToken, valuedCookieNonTerminals, 
				cookieTokenComparer);
			if (token != std::cend(valuedCookieNonTerminals))
			{
				token->second.assign(setCookieHeaderToken.substr(
					std::strlen(token->first) + 1));
			} else 
			{
				auto token = FindInContainer(setCookieHeaderToken, optionedCookieNonTerminals,
					cookieTokenComparer);
				if (token != std::cend(optionedCookieNonTerminals))
				{
					token->second = true;
				}
			}
			
			/* if token unspecified just skip it! */
			oldDelimPos = delimPos + 1;
			delimPos = setCookieHeaderValue.find(delim, oldDelimPos);
		}

		/* parse last attribute */
		std::string_view setCookieHeaderToken = 
			std::string_view(setCookieHeaderValue.data() + oldDelimPos);
		setCookieHeaderToken = cooker_details::TrimPrefixWhitespace(setCookieHeaderToken);
		auto token = FindInContainer(setCookieHeaderToken, valuedCookieNonTerminals, 
			cookieTokenComparer);
		if (token != std::cend(valuedCookieNonTerminals))
		{
			token->second.assign(setCookieHeaderToken.substr(
				std::strlen(token->first) + 1));
		} else 
		{
			auto token = FindInContainer(setCookieHeaderToken, optionedCookieNonTerminals,
				cookieTokenComparer);
			if (token != std::cend(optionedCookieNonTerminals))
			{
				token->second = true;
			}
		}

		/* parse last attribute */
		if (!maxAge.empty())
		{
			char* lastProcessedPos = nullptr;
			long maxAge_s = std::strtol(maxAge.c_str(), &lastProcessedPos, 10);
			if (errno == ERANGE || lastProcessedPos != (maxAge.c_str() + maxAge.length()))
			{
				errno = 0;
				throw cookie_policy_error("Parsing `Max-Age' attribute error!");
			}

			cookie.m_expires = std::chrono::system_clock::now() + 
				std::chrono::seconds(maxAge_s);
			cookie.m_persistent = true;
		} else if (!expires.empty())
		{
			cookie.m_expires = ParseDateAttribute(expires);
			cookie.m_persistent = true;
		}

		/* remove prefix dot from domain cause unnessasary*/
		if (cookie.m_domain.front() == '.') cookie.m_domain.erase(cookie.m_domain.cbegin());

		if (cookieHasHostPrefix && !(cookie.m_path == "/" && cookie.m_domain.empty() &&
				cookie.m_secure))
		{
			throw cookie_policy_error("`__Host' prefix policy error!");
		} else if (cookieHasSecurePrefix && !(cookie.m_secure))
		{
			throw cookie_policy_error("`__Secure' prefix policy error!");
		}

		return cookie;
	};



	bool IsObseleted() const noexcept
	{
		/* zero or negative specifies an immediate expiring */
		return m_expires <= std::chrono::system_clock::now();
	}



	bool IsSessional() const noexcept
	{
		return !m_persistent;
	}


	/* If omitted, this attribute defaults to the host of the current document URL, not including subdomains. */
	bool IsOnlyCurrectDomain() const noexcept
	{
		return m_hostOnly;
	}



	void
	SetDefaultPath(const std::string& uriPath)
	{
		if (uriPath.empty() || uriPath[0] != '/')
		{
			m_path.assign("/");
			return ;
		}

		const std::size_t rightMostSlashPos =
			uriPath.find('/');

		if (rightMostSlashPos == std::string::npos)
		{
			m_path.assign("/");
			return ;
		} // else ...

		m_path.assign(uriPath.substr(0, rightMostSlashPos));
	};
};

std::string Cookie::defaultSameSiteValue = "None";



/* vector by domain, multimap by path */
struct CookiePathComparer
{
	/*constexpr*/ bool 
	operator()(const Cookie& lhs, const Cookie& rhs) const noexcept
	{
		return lhs.m_path < rhs.m_path;
	};


	using is_transparent = std::string;
	bool
	operator()(const Cookie& lhs, const is_transparent& rhs) const noexcept
	{
		return lhs.m_path < rhs;
	};



	bool
	operator()(const is_transparent& lhs, const Cookie& rhs) const noexcept
	{
		return lhs < rhs.m_path;
	};
};


template <typename T>
struct nullable 
{
private:
	T* m_ptr;
public:
	struct null_error : std::runtime_error
	{
		null_error(const char* msg = "null")
			: std::runtime_error(msg)
		{

		};
	};

	nullable(T* ptr)
		: m_ptr(ptr)
	{
	};



	// possible to inline operator= ?
	T* operator=(T* ptr) const noexcept
	{
		m_ptr = ptr;
	};



	T* operator*() const noexcept(false)
	{
		return m_ptr ?: throw null_error();
	};



	T* operator->() const noexcept(false)
	{
		return m_ptr ?: throw null_error();
	};



	explicit operator T*() const
	{
		return m_ptr ?: throw null_error();
	}
};


using CookieUrlTree = std::multiset<Cookie, CookiePathComparer>;
// TODO: change vector to dns tree
using CookieDNSJar = std::vector<std::pair<std::string, CookieUrlTree>>;
// TODO : improve search algo
nullable<CookieUrlTree> FindCookieUrlTree(CookieDNSJar& cookieJar, const std::string& domain)
{
	typename CookieDNSJar::iterator cookieJarIter = 
		std::find_if(cookieJar.begin(), cookieJar.end(), [&domain](const typename CookieDNSJar::value_type& pDomain_CookieUrlTree){
			return pDomain_CookieUrlTree.first == domain;
	});

	return cookieJarIter != cookieJar.end() ? 
		std::addressof(cookieJarIter->second) : nullptr;
};


CookieUrlTree* ForceFindCookieUrlTree(CookieDNSJar& cookieJar, const std::string& domain)
#ifdef __GNUG__
__attribute__((returns_nonnull))
#endif // __GNUG__
;

CookieUrlTree* ForceFindCookieUrlTree(CookieDNSJar& cookieJar, const std::string& domain)
{
	CookieUrlTree* cookieUrlTreePtr = nullptr;
	try
	{
		cookieUrlTreePtr = static_cast<CookieUrlTree*>(FindCookieUrlTree(cookieJar, domain));
	} catch(const std::runtime_error&)
	{
		// not found
		/*cookieUrlTree = */ cookieJar.emplace_back(domain, CookieUrlTree{});
		cookieUrlTreePtr = std::addressof(cookieJar.back().second);
	}

	return cookieUrlTreePtr;
};



std::string
CreateQuery(const char* format, ...)
{
	std::string rq;
	va_list args, args2;
	va_start(args, format);
	va_copy(args2, args);
	const std::size_t rqLen = vsnprintf(nullptr, 0, format, args2);
	rq.resize(rqLen + 1);
	vsnprintf(rq.data(), rqLen + 1, format, args);
	return rq;
};



int
StorageCookie(sqlite3* dbConn, Cookie&& cookie)
__attribute__((nonnull(1)));



int
StorageCookie(sqlite3* dbConn, Cookie&& cookie)
{
	std::string strSameCookieCondition = CreateQuery(" WHERE name='%s' AND path='%s' AND domain='%s';", 
		cookie.m_name.c_str(), cookie.m_path.c_str(), cookie.m_domain.c_str());
	std::string findExistCookieRq = std::string("SELECT creation_time FROM cookies") + strSameCookieCondition;

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
		std::string deleteOldCookieRq = std::string("DELETE FROM cookies") + strSameCookieCondition;
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



// using CookiesView = std::forward_list<const Cookie*>;
// CookiesView FindCookies(const CookieDNSJar& cookieJar,
// 	const std::string& domain, const std::string& path)
// {
// 	CookiesView cookiesView;

// 	// improve search domain
// 	/*****************************************************/
// 	for (const auto& pDomain_CookieUrlTree : cookieJar)
// 	/*****************************************************/
// 	{
// 		// check full match or subdomain
// 		int op = cooker_url_utils_ns::DomainSpaceshipOp(pDomain_CookieUrlTree.first, domain);
// 		if (op < 0)
// 		{
// 			continue;
// 		}

// 		auto cookiesRangeEqPath = pDomain_CookieUrlTree.second.equal_range(path);
// 		std::for_each(cookiesRangeEqPath.first, cookiesRangeEqPath.second, [op, &cookiesView](const typename CookieUrlTree::value_type& cookie){
// 			if ((cookie.IsOnlyCurrectDomain() && (op == 0)) || 
// 					op > 0)
// 			{
// 				cookiesView.push_front(std::addressof(cookie));
// 			}
// 		});
// 	}

// 	return cookiesView;
// };



/* cookie name is unique withing `path' attribute */
// std::string ManageCookies(CookieDNSJar& cookieJar, const std::string& url)
// {
// 	boost::system::result<url::url_view> uriParseResult = url::parse_uri_reference(url);
// 	assert(uriParseResult);
// 	auto boostUrlView = uriParseResult.value();

// 	CookiesView cookiesView = FindCookies(cookieJar, boostUrlView.host(), boostUrlView.path());

// 	std::string cookieHeaderValue; 
// 	if (!cookiesView.empty())
// 	{
// 		for (const auto& cookie : cookiesView)
// 		{
// 			if (!cookie->IsObseleted() && Cookie::PolicyCookiePath(cookie->m_path, boostUrlView.path()) &&
// 					(!cookie->m_secure || boostUrlView.scheme() == "https"))
// 			{
// 				cookieHeaderValue.append(cookie->m_name).append("=")
// 					.append(cookie->m_value).append("; ");
// 			}
// 		}

// 		cookieHeaderValue.pop_back(); // remove tail whitespace
// 		cookieHeaderValue.pop_back(); // remove tail `;'		
// 	}

// 	return cookieHeaderValue;
// };



std::string operator+(const std::string& str, url::pct_string_view&& pctStringView)
{
	std::string retStr(str);
	std::transform(pctStringView.cbegin(), pctStringView.cend(),
		std::back_inserter((retStr)), [](const typename url::pct_string_view::value_type& value) { return value; } );

	return retStr;
};



std::string to_string(const url::pct_string_view& pctStringView)
{
	std::string retStr; retStr.resize(pctStringView.length());
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



// void MergeCookies(CookieDNSJar& cookieJar, CookieDNSJar&& mergingCookies)
// {
// 	for (auto& pDomain_CookieUrlTree : mergingCookies)
// 	{
// 		std::string& domain = pDomain_CookieUrlTree.first;

// 		CookieUrlTree* cookieUrlTree = ForceFindCookieUrlTree(cookieJar, domain);
// 		cookieUrlTree->merge(std::move(pDomain_CookieUrlTree.second));
// 	}
// };



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
			// 	res = client.CONNECT(path, headers, body, content_length, content_type);
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
		method = "GET";

		// remove content-type header
		// auto EraseHeader = [&headers](const std::string& key){
		// 	headers.erase(key);
		// };
		
		// EraseHeader("Content-Type");
		// EraseHeader("Content-Length");
	}
};



void CookerLogger(const httplib::Request& req, const httplib::Response& res, 
	int verboseMode);



auto CreateTable_cookies(sqlite3* dbConn)
	-> decltype(SQLITE_OK)
__attribute__((nonnull(1)));



int RemoveObseleteCookies(sqlite3* dbConn, [[maybe_unused]] const std::string& domain)
__attribute__((nonnull(1)));



int main(int argc, char const *argv[])
{
	std::string method = "GET"
		, requestUrl
		, defaultSameSite
		, data
		, header
		, strCaCertFilepath
		, sqliteDBFilepath;


	bool isShowHelpTip = false
		, followRedirect = false
		, verboseMode = false
		, preloadCookies = false;

	httplib::Headers defaultRequestHeaders;

	auto cliParser = lyra::cli()
		| lyra::help(isShowHelpTip)
			("Show this tip")
		| lyra::opt(followRedirect)
			["--follow-redirect"]["-L"]
			("Automatic redirection to 3xx http status code location value")
				.optional()
		| lyra::opt(sqliteDBFilepath, "sqlite3 database")
			["--database"]
			("sqlite database file")
				.required()
		| lyra::opt(verboseMode)
			["--verbose"]["-v"]
			("Verbose mode")
				.optional()
		| lyra::opt(strCaCertFilepath, "certificate path")
			["--ssl_cert"]["-s"]
			("Certificate path")
				.optional()
		| lyra::opt(preloadCookies)
			["--preload"]["-l"]
			("Preload cookies before request")
		| lyra::opt(defaultSameSite, "default `SameSite' value")
			["--default-samesite"]["-s"]
			("Default `SameSize' value of cookie. (developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Set-Cookie#samesitesamesite-value)")
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
			}) 	| lyra::opt(method, "request method")
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

	struct DBConnCloser
	{
		void operator()(sqlite3* sqliteConn) const noexcept
		{
			/* 	If sqlite3_close_v2() is called with unfinalized prepared statements, 
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

	struct stat unused_1;
	if (stat(sqliteDBFilepath.c_str(), &unused_1) == -1)
	{
		// no such file or directory or system error
		if (errno != ENOENT )
		{
			std::cerr << "stat() failed: " << strerror(errno) << std::endl;
			return EXIT_FAILURE;
		}

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

	bool isTableExists = false;
	if (not (openDBConnFlags & SQLITE_OPEN_CREATE))
	{
		// check is cookies table exist
		const char* checkTableExistRq = "SELECT name FROM sqlite_master WHERE type='table' AND name='cookies'";
		if (int execCodeRq = sqlite3_exec(cookiesStorage.get(), checkTableExistRq, +[](void* flagPtr, int, char** values, char**){
				if (values[0][0] != '\0')
				{
					*reinterpret_cast<bool*>(flagPtr) = true;
				}
				return 0;
			}, reinterpret_cast<void*>(&isTableExists), nullptr); execCodeRq != SQLITE_OK)
		{
			fprintf(stderr, "Request (%s: %s) failed %s\n", __FILENAME__, __LINE__, sqlite3_errstr(execCodeRq));
			return EXIT_FAILURE;
		}
	}


	if (!isTableExists)
	{
		if (CreateTable_cookies(cookiesStorage.get()) != SQLITE_OK)
		{
			std::cerr << "Cannot create table `cookies': " << sqlite3_errmsg(cookiesStorage.get()) << std::endl;
			return EXIT_FAILURE;
		}
	}

	// capitalize method
	std::for_each(method.begin(), method.end(), [](char& ch) { ch = std::toupper(ch); });


	url::url_view boostUrlView;
	auto [urlOrigin, urlPath] = cooker_url_utils_ns::SplitUrlIntoOriginAndPath(requestUrl, boostUrlView);

	if (urlPath.empty())
	{
		urlPath = "/";
	}

	httplib::Client simpleClient(urlOrigin);

	simpleClient.set_logger(std::bind(CookerLogger, std::placeholders::_1, std::placeholders::_2, verboseMode));

	if (simpleClient.is_ssl())
	{
		if (strCaCertFilepath.empty())
		{
			std::cerr << "Error: Certificate path must be specified!\n";
			return EXIT_FAILURE;
		}
		
		simpleClient.set_ca_cert_path(strCaCertFilepath);
	}

	auto TryAddHeader = [&defaultRequestHeaders](std::string key, std::string value){
		if (defaultRequestHeaders.find(key) == defaultRequestHeaders.cend())
		{
			defaultRequestHeaders.emplace(std::move(key), std::move(value));
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

	auto OverwriteHeader = [&defaultRequestHeaders](std::string key, std::string value){
		if (httplib::Headers::const_iterator iter = defaultRequestHeaders.find(key);
				iter != defaultRequestHeaders.cend())
		{
			defaultRequestHeaders.erase(iter);
			defaultRequestHeaders.emplace(std::move(key), std::move(value));
		}
	};

	simpleClient.set_compress(true);
	OverwriteHeader("Accept-Encoding", "gzip");

	if (preloadCookies)
	{
		std::string requestUrlHost = boostUrlView.host();
		const char* ptrRequestUrlHost = requestUrlHost.c_str();
		if (RemoveObseleteCookies(cookiesStorage.get(), requestUrlHost) != 0)
		{
			fprintf(stderr, "Remove obselete cookies failed: <unknown error>");
			return EXIT_FAILURE;
		}

		const char* ptrSecondLevelDomain = ptrRequestUrlHost +
			requestUrlHost.rfind('.', requestUrlHost.rfind('.') - 1) + 1;

		std::string cookiesNameAndValueByDomainAndPathRq = CreateQuery(
			"SELECT ROWID, name, value "
			"FROM cookies "
			"WHERE (domain='%s' AND host=1 OR domain LIKE '%%%s' AND host=0) AND path LIKE '%s%%'",
			ptrRequestUrlHost, ptrSecondLevelDomain, urlPath.c_str());
		if (boostUrlView.scheme() == "https")
		{
			cookiesNameAndValueByDomainAndPathRq += " AND secure=1";
		}
		cookiesNameAndValueByDomainAndPathRq.push_back(';');

		/* load cookies for domain and path and collect obselete cookies' rowid */
		httplib::Headers::iterator iterCookieHeader = defaultRequestHeaders.emplace("Cookie", "");
		
		std::string condRowidIN = " WHERE ROWID IN (";
		
		auto callbackLambda = [&iterCookieHeader, &condRowidIN](int, char** values, char** columnsNames) -> int {
			iterCookieHeader->second.append(values[1]).append("=").append(values[2]).push_back(';');
			condRowidIN.append(values[0]);
			condRowidIN.push_back(',');
			return 0;
		};

		if (sqlite3_exec(cookiesStorage.get(), cookiesNameAndValueByDomainAndPathRq.c_str(), 
				+[](void* callback, int columnsNum, char** values, char** columnsNames){
					return reinterpret_cast<decltype(callbackLambda)*>(callback)->operator()(columnsNum, values, columnsNames);
				}, reinterpret_cast<void*>(&callbackLambda), nullptr) != SQLITE_OK)
		{
			fprintf(stderr, "Request (%s: %s) failed:  %s", __FILENAME__, __LINE__, sqlite3_errmsg(cookiesStorage.get()));
			return EXIT_FAILURE;
		}

		if (!iterCookieHeader->second.empty()) /* cookie has been added */
		{
			iterCookieHeader->second.pop_back();
			/* remove symbol `,' */
			condRowidIN.pop_back(); condRowidIN.append(");");

			std::string updateCookiesLastAccessDateRq = CreateQuery("UPDATE cookies SET last_access_time='%s' %s",
				Cookie::format(std::chrono::system_clock::now()).c_str(), condRowidIN.c_str());

			if (sqlite3_exec(cookiesStorage.get(), updateCookiesLastAccessDateRq.c_str(), nullptr, nullptr, nullptr) != SQLITE_OK)
			{
				fprintf(stderr, "Request (%s: %d) failed:  %s\n", __FILENAME__, __LINE__, sqlite3_errmsg(cookiesStorage.get()));
				return EXIT_FAILURE;
			}
		} else
		{
			defaultRequestHeaders.erase(iterCookieHeader);
		}
	}

	auto in_range = [](int number, int lower, int upper){
		return (unsigned)(number - lower) <= (upper - lower);
	};

	httplib::Result httpResult = InvokeHTTPMethod(method, simpleClient,
		urlPath, defaultRequestHeaders, !data.empty() ? data.c_str() : nullptr, data.length());

	if (!httpResult)
	{
		std::cerr << "> " << method << " " << requestUrl << " failed! " << 
			httplib::to_string(httpResult.error()) << "\n\n";
		return EXIT_FAILURE;
	}

	std::pair<httplib::Headers::const_iterator, 
		httplib::Headers::const_iterator> setCookieHeadersRange = httpResult->headers.equal_range("Set-Cookie");
	// std::vector<std::future<int>> vecFt; vecFt.reserve(std::distance(setCookieHeadersRange.first, 
	// 	setCookieHeadersRange.second));
	for ( ; setCookieHeadersRange.first != setCookieHeadersRange.second; ++setCookieHeadersRange.first)
	{
		const httplib::Headers::value_type& setCookieHeader = 
			*setCookieHeadersRange.first;
		try
		{
			Cookie cookie = Cookie::ParseSetCookieHeaderValue(setCookieHeader.second);

			// check process path
			Cookie::CheckCookiePolicy(cookie, boostUrlView);

			boost::string_view cookieLocation = boostUrlView.buffer();
			cookie.m_cookieLocation.assign(cookieLocation.begin(), cookieLocation.end());
			// vecFt.emplace_back(std::async(std::launch::async, StorageCookie, cookiesStorage.get(), std::move(cookie)));
			if (StorageCookie(cookiesStorage.get(), std::move(cookie)) != SQLITE_OK)
			{
				std::cerr << "Failed storage cookie: " << sqlite3_errmsg(cookiesStorage.get()) << std::endl;
			}
		} catch(const Cookie::cookie_policy_error& cookiePolicyError)
		{
			std::cerr << "Warning: Cookie (" << setCookieHeader.second << ") from "  << requestUrl << 
				" is REJECTED. Reason: " <<
					cookiePolicyError.what() << "\n\n";
		}
	}

	// std::for_each(vecFt.begin(), vecFt.end(), [](std::future<int>& futureObj){
	// 	futureObj.wait();
	// 	int storageCookieExecCode = futureObj.get();
	// 	if (storageCookieExecCode != SQLITE_OK)
	// 	{
	// 		std::cerr << "Storage cookie failed: " << 
	// 			sqlite3_errstr(storageCookieExecCode) << std::endl;
	// 	}
	// });

	// if (followRedirect)
	// {
	// 	typename httplib::Headers::const_iterator cookieHeaderIter = defaultRequestHeaders.cend();
	// 	while (in_range(httpResult->status, http::MultipleChoices_300, http:: MultipleChoices_300 + 99))
	// 	{
	// 		if (cookieHeaderIter != defaultRequestHeaders.cend())
	// 		{
	// 			// remove previous `Cookie' header
	// 			defaultRequestHeaders.erase(cookieHeaderIter);
	// 		}

	// 		TransformRedirectedMethod(method, httpResult->status, defaultRequestHeaders);

	// 		typename httplib::Headers::const_iterator 
	// 			locationHTTPHeader = httpResult->headers.find("Location");

	// 		if (locationHTTPHeader == httpResult->headers.cend())
	// 		{
	// 			std::cout << "Redirect HTTP status but not any `Location' header in response!\n";
	// 			break;
	// 		}

	// 		const std::string& locationUrl = locationHTTPHeader->second;
	// 		result<url::url_view> parsedLocationUrlResult = url::parse_uri_reference(locationUrl);
	// 		if (!parsedLocationUrlResult)
	// 		{
	// 			std::cerr << "Invalid header `Location' value. It is rarely possible!\n";
	// 			sqlite3_exec()
	// 			// PrettyPrintCookies(cookies);
	// 			return EXIT_FAILURE;
	// 		}

	// 		auto boostLocationUrlView = parsedLocationUrlResult.value();
			
	// 		/* origin   = scheme://authority */
	// 		/* resource = /path?query#frag */
	// 		/* target   = /path?:query */
	// 		if (boostLocationUrlView.has_scheme()) // full url
	// 		{
	// 			/* path changes, need to new client */
	// 			simpleClient.operator=(httplib::Client(to_string(boostLocationUrlView.encoded_origin())));
	// 			simpleClient.set_logger(std::bind(CookerLogger, std::placeholders::_1, std::placeholders::_2, verboseMode));
	// 			if (simpleClient.is_ssl())
	// 			{
	// 				if (strCaCertFilepath.empty())
	// 				{
	// 					std::cerr << "Error: Certificate path must be specified!\n";
	// 					return EXIT_FAILURE;
	// 				}

	// 				simpleClient.set_ca_cert_path(strCaCertFilepath);
	// 			}

	// 			urlPath = boostLocationUrlView.encoded_resource();
	// 			url = locationUrl;
	// 		} else if (boostLocationUrlView.is_path_absolute()) // absolute url
	// 		{
	// 			urlPath = locationUrl;
	// 			cooker_url_utils_ns::ReplaceUrlResource(url, locationUrl);
	// 		} else // relative path
	// 		{
	// 			urlPath = boostUrlView.path() + locationUrl;
	// 			cooker_url_utils_ns::RemoveQueryAndFrag(url); 
	// 			cooker_url_utils_ns::AppendPath(url, locationUrl);
	// 		}

	// 		std::string cookieHeaderValue = ManageCookies(cookies, url);
	// 		if (!cookieHeaderValue.empty())
	// 		{
	// 			cookieHeaderIter = defaultRequestHeaders.emplace("Cookie", std::move(cookieHeaderValue));
	// 		} else
	// 		{
	// 			cookieHeaderIter = defaultRequestHeaders.cend();
	// 		}

	// 		std::cout << "> Redirecting to " << url << "\n\n";

	// 		httpResult = InvokeHTTPMethod(method, simpleClient, urlPath,
	// 			defaultRequestHeaders, !data.empty() ? data.c_str() : nullptr, data.length());
	// 		if (!httpResult)
	// 		{
	// 			std::cerr << "> " << method << " " << url << " failed! " << 
	// 				httplib::to_string(httpResult.error()) << "\n\n";
	// 			return EXIT_FAILURE;
	// 		}

	// 		CookieDNSJar setCookies = GrapCookies(httpResult->headers, url);
	// 		// PrintTraceInfo(httpResult->version, httpResult->status,
	// 		// 	method, httpResult->reason, url);
	// 		MergeCookies(cookies, std::move(setCookies));
	// 	}
	// }


	// if (sqlite3_exec(cookiesStorage.get(), "SELECT * FROM cookies", &PrettyPrintCookies, nullptr, nullptr) != SQLITE_OK)
	// {
	// 	fprintf(stderr, "Request (%s: %s) failed:  %s\n", __FILENAME__, __LINE__, sqlite3_errmsg(cookiesStorage.get()));
	// 	return EXIT_FAILURE;
	// }

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



auto CreateTable_cookies(sqlite3* dbConn)
	-> decltype(SQLITE_OK)
{
	const char* createTableRq = "CREATE TABLE cookies ("
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

	return sqlite3_exec(dbConn, createTableRq, nullptr, nullptr, nullptr);
}



int RemoveObseleteCookies(sqlite3* dbConn, const std::string& domain)
{
	// TODO:
	return 0;
}