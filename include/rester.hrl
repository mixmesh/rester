-ifndef(_RESTER_HRL_).
-define(_RESTER_HRL_, true).

-type path() :: string().
-type user() :: binary().
-type password() :: binary().
-type realm() :: string().
-type ip_address() :: {integer(),integer(),integer(),integer()} |
		      {integer(),integer(),integer(),integer(),integer(),integer()}.
-type cred() :: {basic,path(),user(),password(),realm()} |
		{digest,path(),user(),password(),realm()}. %% Old type
-type guard() :: ip_address() |
		 {ip_address(), integer()} |
		 afunix |
		 http |
		 https.
-type action() :: accept | reject | {accept , list(cred())}.
-type access() :: cred() | {guard(), action()}.

-ifdef(USE_APPTOOLS).
-include_lib("apptools/include/log.hrl").

-define(debug(F,A), ?dbg_log_fmt((F), (A))).
-define(debug(F),   ?dbg_log_fmt((F), [])).

-define(warning(F,A), ?daemon_log_tag_fmt(warning, (F), (A))).
-define(warning(F), ?daemon_log_tag_fmt(warning, (F), [])).

-define(info(F,A), ?daemon_log_tag_fmt(info, (F), (A))).
-define(info(F), ?daemon_log_tag_fmt(info, (F), [])).

-define(error(F,A), ?daemon_log_tag_fmt(error, (F), (A))).
-define(error(F), ?daemon_log_tag_fmt(error, (F), [])).

-else.

-include_lib("kernel/include/logger.hrl").

-define(debug(_Format), ?debug(_Format, [])).
-define(debug(_Format, _Args), ?LOG_DEBUG(_Format, _Args)).

-define(warning(_Format), ?warning(_Format, [])).
-define(warning(_Format, _Args), ?LOG_WARNING(_Format, _Args)).

-define(info(_Format), ?info(_Format, [])).
-define(info(_Format, _Args), ?LOG_INFO(_Format, _Args)).

-define(error(_Format), ?error(_Format, [])).
-define(error(_Format, _Args), ?LOG_ERROR(_Format, _Args)).

-endif.

-endif.
