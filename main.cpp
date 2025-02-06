#include <stdlib.h> // exit()
#include <time.h> // localtime_r() strptime()
#include <string.h> // strncasecmp()
#include <ctype.h> // tolower(), isdigit()
#include <errno.h> // strerror(), errno


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

#include "boost/system.hpp"
#include "boost/tti/has_member_function.hpp"

// #include "boost/property_tree/ptree.hpp"
// template <typename Key, typename T, typename Compare = std::less<Key>>
// using ptree = boost::property_tree::basic_ptree<
// 	Key,
// 	T,
// 	Compare
// >;


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
	std::string m_key;
	std::string m_value;

	static std::string defaultSameSiteValue;
	std::string m_sameSite;
	std::string m_domain;

	std::chrono::system_clock::time_point m_expires;
	std::string m_path;
	
	// persistent container
	std::string m_setCookieOrigin;

	bool m_isSessional;
	bool m_secure;
	bool m_httpOnly;
	/* TODO: */
	bool m_partitioned;
	bool m_isHosted;
	bool m_isOnlyCurrDomain;
// private:
	// bool m_parseSetCookieError;
public:
	// bool IsParseSetCookieError() const
	// { return m_parseSetCookieError; };



	// const char* ParseSetCookieError() const
	// { return m_parseSetCookieError ? m_key.c_str() : ""; };
	// overload move operator


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
		cookie.m_isSessional 			= false;
		cookie.m_partitioned 			= false;
		cookie.m_isHosted 				= false;
		cookie.m_isOnlyCurrDomain 		= false;
		// cookie.m_parseSetCookieError	= false;

	  	cookie.m_sameSite = GetDefaultSameSiteValue();
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




	// inherit from it?
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

		std::string_view cookieNameValue(setCookieHeaderValue.data() + oldDelimPos, 
			isCommonCookie ? setCookieHeaderValue.length() - oldDelimPos : delimPos - oldDelimPos);
		std::size_t cookieNameValueDelimPos = cookieNameValue.find('=');
		/* considered it is success */
		static const char* hostPrefix = "__Host-";
		static const char* securePrefix = "__Secure-";

		/* not possible both! */
		std::size_t cookieNamePos = oldDelimPos;
		if (cooker_details::starts_with_case(cookieNameValue.data(), cookieNameValue.length(),
				hostPrefix, std::strlen(hostPrefix)))
		{
			cookie.m_secure = true;
			cookieNamePos += std::strlen(hostPrefix);
		} else if (cooker_details::starts_with_case(cookieNameValue.data(), cookieNameValue.length(),
				securePrefix, std::strlen(securePrefix)))
		{
			cookie.m_isHosted = true;
			cookieNamePos += std::strlen(securePrefix);
		}

		cookie.m_key = cookieNameValue.substr(cookieNamePos, cookieNameValueDelimPos - cookieNamePos);
		cookie.m_value = cookieNameValue.substr(cookieNameValueDelimPos + 1);
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
		} else if (!expires.empty())
		{
			cookie.m_expires = ParseDateAttribute(expires);
		} else
		{
			cookie.m_isSessional = true;
		}

		/* remove prefix dot from domain cause unnessasary*/
		if (cookie.m_domain.front() == '.') cookie.m_domain.erase(cookie.m_domain.cbegin());
		return cookie;
	};



	bool IsObseleted() const noexcept
	{
		/* zero or negative specifies an immediate expiring */
		return m_expires <= std::chrono::system_clock::now();
	}



	bool IsSessional() const noexcept
	{
		return m_isSessional;
	}



	bool IsHosted() const noexcept
	{
		return m_isHosted;
	}



	/* If omitted, this attribute defaults to the host of the current document URL, not including subdomains. */
	bool IsOnlyCurrectDomain() const noexcept
	{
		return m_domain.empty();
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



	operator T*() const
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


CookieUrlTree* SearchCookieUrlTree(CookieDNSJar& cookieJar, const std::string& domain)
#ifdef __GNUG__
__attribute__((returns_nonnull))
#endif // __GNUG__
;

CookieUrlTree* SearchCookieUrlTree(CookieDNSJar& cookieJar, const std::string& domain)
{
	CookieUrlTree* cookieUrlTreePtr = nullptr;
	try
	{
		cookieUrlTreePtr = FindCookieUrlTree(cookieJar, domain);
	} catch(const std::runtime_error&)
	{
		// not found
		/*cookieUrlTree = */ cookieJar.emplace_back(domain, CookieUrlTree{});
		cookieUrlTreePtr = std::addressof(cookieJar.back().second);
	}

	return cookieUrlTreePtr;
};



const Cookie&
AddCookieToJar(CookieDNSJar& cookieJar, Cookie&& cookie)
{
	CookieUrlTree* cookieTreePtr = SearchCookieUrlTree(cookieJar, cookie.m_domain);

	/*const*/ auto cookiesRangeEqPath = cookieTreePtr->equal_range(cookie.m_path);
	const std::size_t cookiesEqPathNum = std::distance(
		cookiesRangeEqPath.first, cookiesRangeEqPath.second);

	if (cookiesEqPathNum == 0) // this path does not exists
	{
		return cookieTreePtr->emplace(std::move(cookie)).operator*();
	} // else ...

	/* check exists cookie with same key */
	typename CookieUrlTree::iterator sameKeyCookieIter = std::find_if(cookiesRangeEqPath.first, cookiesRangeEqPath.second, 
		[&cookie](const typename CookieUrlTree::value_type& i_cookie){
			return cookie.m_key == i_cookie.m_key;
	});

	if (sameKeyCookieIter != cookiesRangeEqPath.second)
	{
		// overwrite cookie
		// path will not be changed
		// *sameKeyCookieIter = std::move(cookie);

		// workaround ...
		typename CookieUrlTree::node_type cookieTreeNode = cookieTreePtr->extract(sameKeyCookieIter);
		assert(!cookieTreeNode.empty() && "Fatal logic error! Call value() mem_fn on empty node object is ub!");
		cookieTreeNode.value() = std::move(cookie);
		sameKeyCookieIter = cookieTreePtr->insert(std::move(cookieTreeNode));
	} else
	{
		sameKeyCookieIter = 
			cookieTreePtr->emplace_hint(cookiesRangeEqPath.first, std::move(cookie));
	}

	return sameKeyCookieIter.operator*();
};



CookieDNSJar GrapCookies(const httplib::Headers& headers,
	const std::string& requestUrl)
{
	CookieDNSJar cookieJar;

	auto rangeCookies = headers.equal_range("Set-Cookie");
	boost::system::result<url::url_view> parseUriRefResult = url::parse_uri_reference(requestUrl);
		assert(parseUriRefResult && "parse_uri_reference() failed!");
	auto& boostUrlView = parseUriRefResult.value();

	for ( ; rangeCookies.first != rangeCookies.second; rangeCookies.first++)
	{
		auto setCookieHeaderValue = rangeCookies.first->second;
		try
		{
			Cookie cookie = Cookie::ParseSetCookieHeaderValue(setCookieHeaderValue);

			// check process path
			if (cookie.m_path.empty() || (cookie.m_path[0] != '/'))
			{
				cookie.SetDefaultPath(boostUrlView.path());
			}


			if (cookie.m_isHosted)
			{
				assert(cookie.m_path == "/" && 
					cookie.m_domain.empty() && 
						cookie.m_secure);
				/* otherwise */
				throw Cookie::cookie_policy_error("__Host attr error!");
			}
		
			if (cookie.m_secure && boostUrlView.scheme() != "https") 
			{
				constexpr const char* SecureAttrFromHTTPError = "Insecure site "
						 "cannot set cookies with the `Secure' attribute!"; 
				throw Cookie::cookie_policy_error(SecureAttrFromHTTPError);
			}
		

			std::string urlHost = boostUrlView.host();
			if (!cookie.m_domain.empty() && 
					!cooker_url_utils_ns::IsSubdomain(urlHost, cookie.m_domain))
			{
				throw Cookie::cookie_policy_error("Only the current domain can be set as the value,"
					" or a domain of a higher order");
			} else if (cookie.m_domain.empty())
			{
				cookie.m_isOnlyCurrDomain = true;
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

			// decode ptc_string_view (a reference precent-encoded strings)
			url::decode_view urlTarget = *boostUrlView.encoded_target();
			cookie.m_setCookieOrigin.assign(urlTarget.begin(), urlTarget.end());
			AddCookieToJar(cookieJar, std::move(cookie));
		} catch(const Cookie::cookie_policy_error& cookiePolicyError)
		{
			std::cerr << "> Cookie (" << setCookieHeaderValue << ") from "  << requestUrl << 
				" is REJECTED. Reason: " <<
					cookiePolicyError.what() << std::endl;
		}
	}

	return cookieJar;
};



using CookiesView = std::forward_list<const Cookie*>;
CookiesView FindCookies(const CookieDNSJar& cookieJar,
	const std::string& domain, const std::string& path)
{
	CookiesView cookiesView;

	// improve search domain
	/*****************************************************/
	for (const auto& pDomain_CookieUrlTree : cookieJar)
	/*****************************************************/
	{
		// check full match or subdomain
		int op = cooker_url_utils_ns::DomainSpaceshipOp(pDomain_CookieUrlTree.first, domain);
		if (op < 0)
		{
			continue;
		}

		auto cookiesRangeEqPath = pDomain_CookieUrlTree.second.equal_range(path);
		std::for_each(cookiesRangeEqPath.first, cookiesRangeEqPath.second, [op, &cookiesView](const typename CookieUrlTree::value_type& cookie){
			if ((cookie.IsOnlyCurrectDomain() && (op == 0)) || 
					op > 0)
			{
				cookiesView.push_front(std::addressof(cookie));
			}
		});
	}

	return cookiesView;
};



/* cookie name is unique withing `path' attribute */
std::string ManageCookies(CookieDNSJar& cookieJar, const std::string& url)
{
	boost::system::result<url::url_view> uriParseResult = url::parse_uri_reference(url);
	assert(uriParseResult);
	auto boostUrlView = uriParseResult.value();

	CookiesView cookiesView = FindCookies(cookieJar, boostUrlView.host(), boostUrlView.path());

	std::string cookieHeaderValue; 
	if (!cookiesView.empty())
	{
		for (const auto& cookie : cookiesView)
		{
			if (!cookie->IsObseleted() && Cookie::PolicyCookiePath(cookie->m_path, boostUrlView.path()) &&
					(!cookie->m_secure || boostUrlView.scheme() == "https"))
			{
				cookieHeaderValue.append(cookie->m_key).append("=")
					.append(cookie->m_value).append("; ");
			}
		}

		cookieHeaderValue.pop_back(); // remove tail whitespace
		cookieHeaderValue.pop_back(); // remove tail `;'		
	}

	return cookieHeaderValue;
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



void PrettyPrintCookies(const CookieDNSJar& cookieDNSJar)
{
	// just print, TODO : pretty print)
	// cookie token delim
	std::cout << "Cookies: \n";
	constexpr const char* ctd = "; ";
	for (const auto& pDomain_CookieUrlTree : cookieDNSJar)
	{
		// key=value; domain; path; samesite; expires; secure; httponly; partitioned
		for (const auto& cookie : pDomain_CookieUrlTree.second)
		{

			std::cout << cookie.m_key << "=" << cookie.m_value << ctd;
			if (!cookie.IsOnlyCurrectDomain())
			{
				std::cout << "Domain=" << cookie.m_domain << ctd;
			}

			if (!cookie.m_path.empty())
			{
				std::cout << "Path=" << cookie.m_path << ctd;
			}

			std::cout << "SameSize=" << cookie.m_sameSite << ctd;
		
			std::cout << "Expires=";
			if (!cookie.IsSessional())
			{
				constexpr std::size_t kBufSize = 1 << 6;
				char buffer[kBufSize]; 
				const time_t cookieExpiresTime = std::chrono::system_clock::to_time_t(
					cookie.m_expires);
				std::strncpy(buffer, ctime(&cookieExpiresTime), 24);
				buffer[24] = 0; //remove `\n'
				std::cout << buffer;
			} else
			{
				std::cout << "Sessional";
			}

			std::cout << ctd;

			if (cookie.m_secure)
			{
				std::cout << "Secure" << ctd;
			}

			if (cookie.m_httpOnly)
			{
				std::cout << "HttpOnly" << ctd;
			}


			if (cookie.m_partitioned)
			{
				std::cout << "Partitioned";
			}

			std::cout << '\n';
		}
	}			
};



void MergeCookies(CookieDNSJar& cookieJar, CookieDNSJar&& mergingCookies)
{
	for (auto& pDomain_CookieUrlTree : mergingCookies)
	{
		std::string& domain = pDomain_CookieUrlTree.first;

		CookieUrlTree* cookieUrlTree = SearchCookieUrlTree(cookieJar, domain);
		cookieUrlTree->merge(std::move(pDomain_CookieUrlTree.second));
	}
};



void PrintTraceInfo(const std::string& version, int status, const std::string& method, 
	const std::string& reason, const std::string& url)
{
	(void)url;
	(void)method;
	std::cout << version  << " " << status << " " << 
		reason << std::endl;
};



using http = httplib::StatusCode;
int main(int argc, char const *argv[])
{
	std::string method;
	std::string url;
	std::string defaultSameSite;
	bool isShowHelpTip = false
		, followRedirect = false;

	auto cliParser = lyra::cli()
		| lyra::help(isShowHelpTip)
			("Show this tip")
		| lyra::opt(followRedirect)
			["--follow-redirect"]["-l"]
			("Automatic redirection to 3xx http status code location value")
				.optional()
		| lyra::opt(defaultSameSite, "default SameSite value")
			["--default-samesite"]["-s"]
			("Default SameSize value of cookie. (developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Set-Cookie#samesitesamesite-value)")
				.optional().choices("same", "lax", "none")
		| lyra::arg(url, "url")
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

	url::url_view boostUrlView;
	auto [urlHost, urlPath] = cooker_url_utils_ns::SplitUrlIntoOriginAndPath(url, boostUrlView);

	if (urlPath.empty())
	{
		urlPath = "/";
	}

	httplib::Client simpleClient(urlHost);
	std::cerr << "Client certificate verification disabled!\n";
	simpleClient.enable_server_certificate_verification(false);

	// -H 'Sec-Fetch-Dest: document'
	// -H 'Sec-Fetch-Mode: navigate' 
	// -H 'Sec-Fetch-Site: cross-site' 
	// -H 'Priority: u=0, i'
	httplib::Headers defaultRequestHeaders;
	defaultRequestHeaders.emplace("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8");
	defaultRequestHeaders.emplace("Accept-Language", "en-US;q=1");
	defaultRequestHeaders.emplace("Accept-Encoding", "gzip");
	defaultRequestHeaders.emplace("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:134.0) Gecko/20100101 Firefox/134.0");
	
	simpleClient.set_compress(true);
	
	std::cout << "Request (GET " << url << ") processing..." << std::endl;
	httplib::Result httpResult = simpleClient.Get(urlPath, defaultRequestHeaders,
		// reject main document downloading!
		[](const char*, std::size_t ) { return true; });
	auto in_range = [](int number, int lower, int upper){
		return (unsigned)(number - lower) <= (upper - lower);
	};

	if (!httpResult)
	{
		std::cerr << "Request (GET " << url << ") failed! " << 
			httplib::to_string(httpResult.error()) << '\n';
		return EXIT_FAILURE;
	}

	CookieDNSJar cookies = GrapCookies(httpResult->headers, url);
	PrintTraceInfo(httpResult->version, httpResult->status, httpResult->reason, 
		"GET", url);

	auto IsHttpStatusCodeInList = [](int statusCode, std::initializer_list<int> list){
		return std::find(list.begin(), list.end(), statusCode) != list.begin();
	};

	if (followRedirect)
	{
		typename httplib::Headers::const_iterator cookieHeaderIter = defaultRequestHeaders.cend();
		while (in_range(httpResult->status, http::MultipleChoices_300, http:: MultipleChoices_300 + 99))
		{
			if (cookieHeaderIter != defaultRequestHeaders.cend())
			{
				// remove previous `Cookie' header
				defaultRequestHeaders.erase(cookieHeaderIter);
			}

			/* may be relative to the request URL or an absolute URL */
			// accept by cookie, 301, 308, 304?, 302, 303, 307
			auto resStatus = httpResult->status;
			if (!IsHttpStatusCodeInList(resStatus, {http::MovedPermanently_301, 
					http::PermanentRedirect_308, http::Found_302, http::SeeOther_303, http::TemporaryRedirect_307}))
			{
				std::cout << "Follow redirect param is chosen but cooker not support " << 
					resStatus << ' ' << httpResult->reason << " redirection" << std::endl;
				PrettyPrintCookies(cookies);
				return EXIT_SUCCESS;
			}

			typename httplib::Headers::const_iterator 
				locationHTTPHeader = httpResult->headers.find("Location");
			const std::string& locationUrl = locationHTTPHeader->second;
			result<url::url_view> parsedLocationUrlResult = url::parse_uri_reference(locationUrl);
			if (!parsedLocationUrlResult)
			{
				std::cerr << "Invalid header `Location' value. It is rarely possible!\n";
				PrettyPrintCookies(cookies);
				return EXIT_FAILURE;
			}

			auto boostLocationUrlView = parsedLocationUrlResult.value();
			
			/* origin   = scheme://authority */
			/* resource = /path?query#frag */
			/* target   = /path?:query */
			if (boostLocationUrlView.has_scheme()) // full url
			{
				/* path changes, need to new client */
				simpleClient.operator=(httplib::Client(to_string(boostLocationUrlView.encoded_origin())));
				simpleClient.enable_server_certificate_verification(false);
				urlPath = boostLocationUrlView.encoded_resource();
				url = locationUrl;
			} else if (boostLocationUrlView.is_path_absolute()) // absolute url
			{
				urlPath = locationUrl;
				cooker_url_utils_ns::ReplaceUrlResource(url, locationUrl);
			} else // relative path
			{
				urlPath = boostUrlView.path() + locationUrl;
				cooker_url_utils_ns::RemoveQueryAndFrag(url); 
				cooker_url_utils_ns::AppendPath(url, locationUrl);
			}

			std::string cookieHeaderValue = ManageCookies(cookies, url);
			if (!cookieHeaderValue.empty())
			{
				cookieHeaderIter = defaultRequestHeaders.emplace("Cookie", std::move(cookieHeaderValue));
			} else
			{
				cookieHeaderIter = defaultRequestHeaders.cend();
			}

			/* next request depend upon http status code*/
			// TODO:
			std::cout << "Request (GET " << url << ") processing..." << std::endl;
			httpResult = simpleClient.Get(urlPath, defaultRequestHeaders);
			if (!httpResult)
			{
				std::cerr << "Request (GET " << url << ") failed! " << 
					httplib::to_string(httpResult.error()) << '\n';
				return EXIT_FAILURE;
			}

			CookieDNSJar setCookies = GrapCookies(httpResult->headers, url);
			PrintTraceInfo(httpResult->version, httpResult->status, httpResult->reason,
				"GET", url);
			MergeCookies(cookies, std::move(setCookies));
		}
	}

	PrettyPrintCookies(cookies);
	return EXIT_SUCCESS;
}