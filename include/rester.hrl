-ifndef(_RESTER_HRL_).
-define(_RESTER_HRL_, true).

-include_lib("apptools/include/log.hrl").

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

-define(log_debug(F,A), ?dbg_log_fmt((F), (A))).
-define(log_debug(F),   ?dbg_log_fmt((F), [])).

-define(log_warning(F,A), ?daemon_log_tag_fmt(warning, (F), (A))).
-define(log_warning(F), ?daemon_log_tag_fmt(warning, (F), [])).
-define(log_error(F,A), ?daemon_log_tag_fmt(error, (F), (A))).
-define(log_error(F), ?daemon_log_tag_fmt(error, (F), [])).
-define(log_info(F,A), ?daemon_log_tag_fmt(info, (F), (A))).
-define(log_info(F), ?daemon_log_tag_fmt(info, (F), [])).

-endif.
