%%% @author Tony Rogvall <tony@rogvall.se>
%%% @copyright (C) 2020, Tony Rogvall
%%% @doc
%%%    Start functions
%%% @end
%%% Created : 15 Oct 2020 by Tony Rogvall <tony@rogvall.se>

-module(rester).

-export([start/0, stop/0]).
-export([config_change/3]).

start() ->
    application:ensure_all_started(rester).

stop() ->
    application:stop(rester).

config_change(_Changed,_New,_Removed) ->
    ok.
