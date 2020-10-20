-ifndef(_RESTER_HRL_).
-define(_RESTER_HRL_, true).

-include_lib("obscrete/include/log.hrl").

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

-define(RESTER_DEBUG, true).

-ifdef(RESTER_DEBUG).
-define(log_debug(F,A), ?dbg_log_fmt((F), (A))).
-define(log_debug(F),  ?dbg_log_fmt((F), [])).
-else.
-define(log_debug(F,A), ok).
-define(log_debug(F), ok).
-endif.

-define(log_warning(F,A), ?daemon_log_tag_fmt(warning, (F), (A))).
-define(log_warning(F), ?daemon_log_tag_fmt(warning, (F), [])).
-define(log_error(F,A), ?dbg_log_tag_fmt(error, (F), (A))).
-define(log_error(F), ?daemon_log_tag_fmt(error, (F), [])).
-define(log_info(F,A), ?daemon_log_tag_fmt(info, (F), (A))).
-define(log_info(F), ?daemon_log_tag_fmt(info, (F), [])).

%% -ifdef(RESTER_DEBUG).
%% -define(log_debug(F,A), io:format((F)++"\n",(A))).
%% -define(log_debug(F),  io:format((F)++"\n",[])).
%% -else.
%% -define(log_debug(F,A), ok).
%% -define(log_debug(F), ok).
%% -endif.

%% -define(log_warning(F,A), io:format("warning: "++(F)++"\n",(A))).
%% -define(log_warning(F), io:format("warning: "++(F)++"\n",[])).
%% -define(log_error(F,A), io:format("error: "++(F)++"\n",(A))).
%% -define(log_error(F), io:format("error: "++(F)++"\n",[])).
%% -define(log_info(F,A), io:format("info: "++(F)++"\n",(A))).
%% -define(log_info(F), io:format("info: "++(F)++"\n",[])).

-endif.
