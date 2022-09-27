%%% @author Tony Rogvall <tony@rogvall.se>
%%% @copyright (C) 2020, Tony Rogvall
%%% @doc
%%%    stuff
%%% @end
%%% Created : 15 Oct 2020 by Tony Rogvall <tony@rogvall.se>

-module(rester_lib).

-include("../include/rester.hrl").
-include("../include/rester_socket.hrl").

-export([split_options/2]).
-export([validate_access/1]).
-export([handle_access/3]).

%%-----------------------------------------------------------------------------
%% @doc
%% Split a list of Options.
%% Returns one list with the options found in Keys and one list with the rest.
%% @end
%%-----------------------------------------------------------------------------
-spec split_options(Keys::list(term()), 
		    List::list({Key::term(), Value::term()})) ->
			   {List1::list({Key::term(), Value::term()}),
			    List2::list({Key::term(), Value::term()})}.

split_options(Ks, L) ->
    split_options_(Ks, L, []).

split_options_([K|Ks], L, Acc) ->
    case lists:keytake(K, 1, L) of
	{value,Kv,L1} ->
	    split_options_(Ks, L1, [Kv|Acc]);
	false ->
	    split_options_(Ks, L, Acc)
    end;
split_options_([], L, Acc) ->
    {lists:reverse(Acc), L}.

%%-----------------------------------------------------------------------------
%% @doc
%% Verifies that the specified access requirement is valid.
%% @end
%%-----------------------------------------------------------------------------
-spec validate_access(Access::list(term())) ->
			     ok |
			     {error, invalid_access}.
validate_access([]) ->
    ok;
validate_access([{Guard, Action} | Rest]) ->
    case {validate_guard(Guard), validate_action(Action)} of
	{ok, ok} -> validate_access(Rest);
	_O -> {error, invalid_access}
    end;
validate_access([Other | Rest]) ->
    %% Maybe old format?
    case validate_access1(Other) of
	ok -> validate_access(Rest);
	_O -> {error, invalid_access}
    end.
	    
validate_access1({Tag, Path, User, Pass, Realm}) 
  when (Tag =:= basic orelse Tag =:= digest) andalso
       is_list(Path) andalso is_binary(User) andalso
       is_binary(Pass) andalso is_list(Realm) ->
    ok;
validate_access1(_Other) ->
    ?error("Unknown access ~p", [_Other]),
    {error, invalid_access}.

validate_guard([]) ->
    ok;
validate_guard([Guard | Rest]) ->
    case validate_guard(Guard) of
	ok -> validate_guard(Rest);
	E -> E
    end;
validate_guard({Tag, GuardList}) when Tag =:= any; Tag =:= all -> 
    validate_guard(GuardList);
validate_guard({IP, '*'}) -> validate_ip(IP);
validate_guard({IP, Port}) when is_integer(Port) -> validate_ip(IP);
validate_guard(http) -> ok;
validate_guard(https) -> ok;
validate_guard(afunix) -> ok;
validate_guard(IP) 
  when is_tuple(IP) andalso 
       (tuple_size(IP) =:= 4 orelse tuple_size(IP) =:= 8) -> 
    validate_ip(IP);
validate_guard(_Other) -> 
    ?error("Unknown access guard ~p", [_Other]),
    {error, invalid_access}.

validate_ip(_IP={A, B, C, D}) ->
    if (is_integer(A) orelse (A =:= '*')) andalso
       (is_integer(B) orelse (B =:= '*')) andalso
       (is_integer(C) orelse (C =:= '*')) andalso
       (is_integer(D) orelse (D =:= '*')) ->
	    ok;
       true ->
	    ?error("Illegal IP address ~p", [_IP]),
	    {error, invalid_access}
    end;
validate_ip(_IP={A, B, C, D, E, F, G, H}) ->
    if (is_integer(A) orelse (A =:= '*')) andalso
       (is_integer(B) orelse (B =:= '*')) andalso
       (is_integer(C) orelse (C =:= '*')) andalso
       (is_integer(D) orelse (D =:= '*')) andalso
       (is_integer(E) orelse (E =:= '*')) andalso
       (is_integer(F) orelse (F =:= '*')) andalso
       (is_integer(G) orelse (G =:= '*')) andalso
       (is_integer(H) orelse (H =:= '*')) ->
	    ok;
       true ->
	    ?error("Illegal IP address ~p", [_IP]),
	    {error, invalid_access}
    end;
validate_ip(_Other) ->
    ?error("Illegal IP address ~p", [_Other]),
    {error, invalid_access}.
	    
validate_action(Access)
  when Access =:= accept;
       Access =:= reject ->
    ok;
validate_action({accept, AccessList} = A)->
    case lists:all(fun(Access) ->
			   validate_access1(Access) =:= ok
		   end, AccessList) of
	true -> 
	    ok;
	false -> 
	    ?error("Illegal access ~p", [A]),
	    {error, invalid_access}
    end.

%%-----------------------------------------------------------------------------
%% @doc
%% Verifies the given access agains the specified.
%% @end
%%-----------------------------------------------------------------------------
-spec handle_access(Access::list(access()), 
		    Socket::#rester_socket{}, 
		    CredCallback::{atom(), atom(), list()}) ->
			   ok |
			   {error, unauthorised} |
			   term(). %% From CredCallback

handle_access([], _Socket, _CredCallback) ->
    %% No access found
    {error, unauthorised};
handle_access([{Guard, Action} = _Access | Rest], Socket, CredCallback) ->
    ?debug("checking ~p", [_Access]),
    case match_access(Guard, Socket) of
	true -> do(Action, CredCallback);
	false -> handle_access(Rest, Socket, CredCallback)
    end;
handle_access([[{Tag, Path, User, Pass, Realm}| _T] = Creds | Rest], 
	      Socket, CredCallback = {M, F, Args}) 
  when (Tag =:= basic orelse Tag =:= digest) andalso
       is_list(Path) andalso is_binary(User) andalso 
       is_binary(Pass) andalso is_list(Realm) ->
    ?debug("checking ~p", [Creds]),
    %% Is this format possible ???
    case apply(M, F, [Creds | Args]) of
	ok -> ok;
	_ -> handle_access(Rest, Socket, CredCallback)
    end;
handle_access([{Tag, Path, User, Pass, Realm}| _T] = Creds, 
	      _Socket, _CredCallback = {M, F, Args}) 
  when (Tag =:= basic orelse Tag =:= digest) andalso
       is_list(Path) andalso is_binary(User) andalso 
       is_binary(Pass) andalso is_list(Realm) ->
    %% Old way
    ?debug("checking ~p", [Creds]),
    apply(M, F, [Creds | Args]).
	    
do(accept, _CredCallback) -> ok;
do(reject, _CredCallback) -> {error, unauthorised};
do({accept, AccessList}, _CredCallback = {M, F, Args}) ->
    ?debug("checking with ~p", [_CredCallback]),
    apply(M, F, [AccessList | Args]).
    
match_access({any, GuardList}, Socket) ->
    lists:any(fun(Guard) -> match_access(Guard, Socket) end, 
	      GuardList);
match_access({all, GuardList}, Socket) ->
    lists:all(fun(Guard) -> match_access(Guard, Socket) end, 
	      GuardList);
match_access(afunix, #rester_socket {mdata = afunix}) ->
    ?debug("afunix true", []),
    true;
match_access(afunix, _Socket) ->
    ?debug("afunix false", []),
    false;
match_access(ssl, #rester_socket {mdata = ssl, mctl = ssl}) ->
    ?debug("ssl true", []),
    true;
match_access(http, Socket=#rester_socket {mdata = gen_tcp, mctl = inet}) ->
    ?debug("http true ??", []),
    ?debug("socket ~p", [Socket]),
    %%% ???
    not rester_socket:is_ssl(Socket);
match_access(https, Socket=#rester_socket {mdata = ssl, mctl = ssl}) ->
    ?debug("https true ??", []),
    ?debug("socket ~p", [Socket]),
    %%% ???
    true;
match_access({Ip, Port} = _Peer, Socket) ->
    ?debug("checking ~p", [_Peer]),
    case rester_socket:peername(Socket) of
	{ok, {PeerIP, PeerPort}} ->
	    ((Port =:= '*') orelse (Port =:= PeerPort)) andalso
		match_ip(Ip, PeerIP);
	_ -> false
    end;
match_access(Ip, Socket) ->
    ?debug("checking ip ~p", [Ip]),
    case rester_socket:peername(Socket) of
	{ok, {PeerIP, _Port}} -> 
	    ?debug("peer ip ~p", [PeerIP]),
	    match_ip(Ip, PeerIP);
	_Other ->
	    ?debug("no peer ip, got ~p", [_Other]),
	    false
    end.

match_ip({Pa,Pb,Pc,Pd}, {A,B,C,D}) ->
    if ((Pa =:= '*') orelse (Pa =:= A)) andalso
       ((Pb =:= '*') orelse (Pb =:= B)) andalso
       ((Pc =:= '*') orelse (Pc =:= C)) andalso
       ((Pd =:= '*') orelse (Pd =:= D)) ->
	    true;
       true -> false
    end;
match_ip({Pa,Pb,Pc,Pd,Pe,Pf,Pg,Ph}, {A,B,C,D,E,F,G,H}) ->
    if ((Pa =:= '*') orelse (Pa =:= A)) andalso
       ((Pb =:= '*') orelse (Pb =:= B)) andalso
       ((Pc =:= '*') orelse (Pc =:= C)) andalso
       ((Pd =:= '*') orelse (Pd =:= D)) andalso
       ((Pe =:= '*') orelse (Pe =:= E)) andalso
       ((Pf =:= '*') orelse (Pf =:= F)) andalso
       ((Pg =:= '*') orelse (Pg =:= G)) andalso
       ((Ph =:= '*') orelse (Ph =:= H)) ->
	    true;
       true -> false
    end;
match_ip(_, _) ->
    false.

