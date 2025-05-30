# Introdution
Cooker - an utility to manage HTTP cookies in requests. The it's main goal to manage cookies automatic through HTTP redirection
when a server sends 3xx status code and sets cookies with *Set-Cookie* header and waits this cookies on redirecting target, 
usually other server endpoint. Likewise, it is taken by modern browsers.
# In detail
As an utility, it can be tunned by args and options. Simple usage :
```
./cooker <url>
```
Utility sends GET request method to url. Then parse all *Set-Cookie* headers by algos represented on HTTP cookie [specification](https://datatracker.ietf.org/doc/html/rfc6265) and 
display all acceptable (not errors in parsing) in common *Set-Cookie* header format:
```
<cookie-name>=<cookie-value>; Domain=<domain-value>; Path=<path-value>; SameSite=<sameSite-value>; Expires=<expires-value>; Secure; HttpOnly; Partitioned
```

Full usage options showed below: 
```
USAGE:
  cooker [-?|-h|--help] [--follow-redirect|-L] --database <sqlite3 database> [--verbose|-v] [--ssl_cert|-s <certificate path>] [--max_redir|-M <number>] [--preload|-l] [--default-samesite|-s <default `SameSite' value>] [--header|-H <<header key : header value>>] [-X <request method>] [--data-raw|-d <request body>] <url>

Display usage information.

OPTIONS, ARGUMENTS:
  -?, -h, --help          Show this tip
  --follow-redirect, -L   Automatic redirection to 3xx http status code location value
  --database <sqlite3 database>
                          sqlite database file
  --verbose, -v           Verbose mode
  --ssl_cert, -s <certificate path>
                          Certificate path
  --max_redir, -M <number>
                          Number max redirection [default: 10]
  --preload, -l           Preload cookies before request
  --default-samesite, -s <default `SameSite' value>
                          Default `SameSize' value of cookie. (developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Set-Cookie#samesitesamesite-value)
  --header, -H <<header key : header value>>
                          Specify HTTP header
  -X <request method>     HTTP method [default: GET]
  --data-raw, -d <request body>
                          HTTP request content
  <url>                   Destination url request
```

# Dependencies
* [Lyra](https://github.com/bfgroup/Lyra) (one header library)
* [httplib](https://github.com/yhirose/cpp-httplib) (one header library)
* zlib
* openssl
* boost's components: [url](https://www.boost.org/), [system](https://www.boost.org/), [tti](https://www.boost.org/)
_**./3rdParty**_ directory includes two start dependencies. 
# Build
```
mkdir build && cd build
cmake -DCMAKE_PREFIX_PATH=<path_to_boost> -DCMAKE_CXX_FLAGS=<...> -DSSL=<ON|OFF> -DZIB=<ON|OFF> -DWITH_TEST=<ON|OFF> ..
make
```
