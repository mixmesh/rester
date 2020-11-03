%%% @author Tony Rogvall <tony@rogvall.se>
%%% @copyright (C) 2020, Tony Rogvall
%%% @doc
%%%    Rester socket wrapper
%%% @end
%%% Created : 15 Oct 2020 by Tony Rogvall <tony@rogvall.se>

-module(rester_socket).

-export([listen/1, listen/2, listen/3]).
-export([accept/1, accept/2]).
-export([async_accept/1, async_accept/2]).
-export([connect/2, connect/3, connect/4, connect/5]).
-export([async_socket/2, async_socket/3]).
-export([close/1, shutdown/2]).
-export([send/2, recv/2, recv/3]).
-export([getopts/2, setopts/2, sockname/1, peername/1]).
-export([controlling_process/2]).
-export([pair/0]).
-export([stats/0, getstat/2]).
-export([tags/1, socket/1]).
-export([request_type/1]).
-export([is_ssl/1]).

-include("../include/rester.hrl").
-include("../include/rester_socket.hrl").

%%
%% List of protocols supported
%%  [tcp]
%%  [tcp,ssl]
%%  [tcp,ssl,http]
%%  [tcp,propbe_ssl,http]
%%  [tcp,http]
%%
%% coming soon: sctcp, ssh
%%
%%
listen(Port) ->
    listen(Port, [tcp], []).

listen(Port, Opts) ->
    listen(Port,[tcp], Opts).

listen(Port, Protos=[tcp|_], Opts0) ->
    Opts1 = proplists:expand([{binary, [{mode, binary}]},
			      {list, [{mode, list}]}], Opts0),
    {TcpOpts, Opts2} = split_options(tcp_listen_options(), Opts1),
    ?log_debug("listen options=~p, other=~p", [TcpOpts, Opts2]),
    Active = proplists:get_value(active, TcpOpts, false),
    Mode   = proplists:get_value(mode, TcpOpts, list),
    Packet = proplists:get_value(packet, TcpOpts, 0),
    {_, TcpOpts1} = split_options([active,packet,mode], TcpOpts),
    TcpListenOpts = [{active,false},{packet,0},{mode,binary}|TcpOpts1],
    case gen_tcp:listen(Port, TcpListenOpts) of
	{ok, L} ->
	    {ok, #rester_socket { mdata    = gen_tcp,
			       mctl     = inet,
			       protocol = Protos,
			       transport = L,
			       socket   = L,
			       active   = Active,
			       mode     = Mode,
			       packet   = Packet,
			       opts     = Opts2,
			       tags     = {tcp,tcp_closed,tcp_error}
			     }};
	Error ->
	    Error
    end.

%%
%%
%%
connect(Host, Port) ->
    connect(Host, Port, [tcp], [], infinity).

connect(Host, Port, Opts) ->
    connect(Host, Port, [tcp], Opts, infinity).

connect(Host, Port, Opts, Timeout) ->
    connect(Host, Port, [tcp], Opts, Timeout).

connect(_Host, File, Protos=[tcp|_], Opts0, Timeout)
  when is_list(File) -> %% unix domain socket
    Opts1 = proplists:expand([{binary, [{mode, binary}]},
			      {list, [{mode, list}]}], Opts0),
    {TcpOpts, Opts2} = split_options(tcp_connect_options(), Opts1),
    Active = proplists:get_value(active, TcpOpts, false),
    Mode   = proplists:get_value(mode, TcpOpts, list),
    Packet = proplists:get_value(packet, TcpOpts, 0),
    {_, TcpOpts1} = split_options([active,packet,mode], TcpOpts),
    TcpConnectOpts = [{active,false},{packet,0},{mode,binary}|TcpOpts1],
    case afunix:connect(File, TcpConnectOpts, Timeout) of
	{ok, S} ->
	    X =
		#rester_socket { mdata   = afunix,
				mctl    = afunix,
				protocol = Protos,
				transport = S,
				socket   = S,
				active   = Active,
				mode     = Mode,
				packet   = Packet,
				opts     = Opts2,
				tags     = {tcp,tcp_closed,tcp_error}
			      },
	    connect_upgrade(X, tl(Protos), Timeout);
	Error ->
	    Error
    end;
connect(Host, Port, Protos=[tcp|_], Opts0, Timeout) -> %% tcp socket
    Opts1 = proplists:expand([{binary, [{mode, binary}]},
			      {list, [{mode, list}]}], Opts0),
    {TcpOpts, Opts2} = split_options(tcp_connect_options(), Opts1),
    Active = proplists:get_value(active, TcpOpts, false),
    Mode   = proplists:get_value(mode, TcpOpts, list),
    Packet = proplists:get_value(packet, TcpOpts, 0),
    {_, TcpOpts1} = split_options([active,packet,mode], TcpOpts),
    TcpConnectOpts = [{active,false},{packet,0},{mode,binary}|TcpOpts1],
    case gen_tcp:connect(Host, Port, TcpConnectOpts, Timeout) of
	{ok, S} ->
	    X =
		#rester_socket { mdata   = gen_tcp,
				mctl    = inet,
				protocol = Protos,
				transport = S,
				socket   = S,
				active   = Active,
				mode     = Mode,
				packet   = Packet,
				opts     = Opts2,
				tags     = {tcp,tcp_closed,tcp_error}
			    },
	    connect_upgrade(X, tl(Protos), Timeout);
	Error ->
	    Error
    end.

connect_upgrade(X, Protos0, Timeout) ->
    ?log_debug("connect protos=~p", [Protos0]),
    case Protos0 of
	[ssl|Protos1] ->
	    Opts = X#rester_socket.opts,
	    {SSLOpts0,Opts1} = split_options(ssl_connect_opts(),Opts),
	    {_,SSLOpts} = split_options([ssl_imp], SSLOpts0),
	    ?log_debug("SSL upgrade, options = ~p", [SSLOpts]),
	    ?log_debug("before ssl:connect opts=~p",
		 [getopts(X, [active,packet,mode])]),
	    case ssl_connect(X#rester_socket.socket, SSLOpts, Timeout) of
		{ok,S1} ->
		    ?log_debug("ssl:connect opt=~p",
			 [ssl:getopts(S1, [active,packet,mode])]),
		    X1 = X#rester_socket { socket=S1,
					  mdata = ssl,
					  mctl  = ssl,
					  opts=Opts1,
					  tags={ssl,ssl_closed,ssl_error}},
		    connect_upgrade(X1, Protos1, Timeout);
		Error={error,_Reason} ->
		    ?log_warning("ssl:connect error=~w\n", [_Reason]),
		    Error
	    end;
	[http|Protos1] ->
	    {_, Close,Error} = X#rester_socket.tags,
	    X1 = X#rester_socket { packet = http,
				  tags = {http, Close, Error }},
	    connect_upgrade(X1, Protos1, Timeout);
	[] ->
	    setopts(X, [{mode,X#rester_socket.mode},
			{packet,X#rester_socket.packet},
			{active,X#rester_socket.active}]),
	    ?log_debug("after upgrade opts=~p",
		 [getopts(X, [active,packet,mode])]),
	    {ok,X}
    end.

ssl_connect(Socket, Options, Timeout) ->
    case ssl:connect(Socket, Options, Timeout) of
	{error, ssl_not_started} ->
	    ssl:start(),
	    ssl:connect(Socket, Options, Timeout);
	Result ->
	    Result
    end.

%% using this little trick we avoid code loading
%% problem in a module doing blocking accept call
async_accept(X) ->
    async_accept(X,infinity).

async_accept(X,infinity) ->
    async_accept(X, -1);
async_accept(X,Timeout) when
      is_integer(Timeout), Timeout >= -1, is_record(X, rester_socket) ->
    case X#rester_socket.protocol of
	[tcp|_] ->
	    case prim_inet:async_accept(X#rester_socket.socket, Timeout) of
		{ok,Ref} ->
		    {ok, Ref};
		Error ->
		    Error
	    end;
	_ ->
	    {error, proto_not_supported}
    end.

async_socket(Listen, Socket) ->
    async_socket(Listen, Socket, infinity).

async_socket(Listen, Socket, Timeout)
  when is_record(Listen, rester_socket), is_port(Socket) ->
    Inherit = [nodelay,keepalive,delay_send,priority,tos],
    case getopts(Listen, Inherit) of
        {ok, Opts} ->  %% transfer listen options
	    %% FIXME: here inet is assumed and currently the only option
	    case inet:setopts(Socket, Opts) of
		ok ->
		    {ok,Mod} = inet_db:lookup_socket(Listen#rester_socket.socket),
		    inet_db:register_socket(Socket, Mod),
		    X = Listen#rester_socket { transport=Socket, socket=Socket },
		    accept_upgrade(X, tl(X#rester_socket.protocol), Timeout);
		Error ->
		    prim_inet:close(Socket),
		    Error
	    end;
	Error ->
	    prim_inet:close(Socket),
	    Error
    end.


accept(X) when is_record(X, rester_socket) ->
    accept_upgrade(X, X#rester_socket.protocol, infinity).

accept(X, Timeout) when
      is_record(X, rester_socket),
      (Timeout =:= infnity orelse (is_integer(Timeout) andalso Timeout >= 0)) ->
    accept_upgrade(X, X#rester_socket.protocol, Timeout).

accept_upgrade(X=#rester_socket { mdata = M }, Protos0, Timeout) ->
    ?log_debug("accept protos=~p", [Protos0]),
    case Protos0 of
	[tcp|Protos1] ->
	    case M:accept(X#rester_socket.socket, Timeout) of
		{ok,A} ->
		    X1 = X#rester_socket {transport=A,socket=A},
		    accept_upgrade(X1,Protos1,Timeout);
		Error ->
		    Error
	    end;
	[ssl|Protos1] ->
	    Opts = X#rester_socket.opts,
	    {SSLOpts0,Opts1} = split_options(ssl_listen_opts(),Opts),
	    {_,SSLOpts} = split_options([ssl_imp], SSLOpts0),
	    ?log_debug("SSL upgrade, options = ~p", [SSLOpts]),
	    ?log_debug("before ssl_accept opt=~p",
		 [getopts(X, [active,packet,mode])]),
	    case ssl:ssl_accept(X#rester_socket.socket, SSLOpts, Timeout) of
		{ok,S1} ->
		    ?log_debug("ssl_accept opt=~p",
			 [ssl:getopts(S1, [active,packet,mode])]),
		    X1 = X#rester_socket{socket=S1,
				      mdata = ssl,
				      mctl  = ssl,
				      opts=Opts1,
				      tags={ssl,ssl_closed,ssl_error}},
		    accept_upgrade(X1, Protos1, Timeout);
		Error={error,_Reason} ->
		    ?log_warning("ssl:ssl_accept error=~p\n",
			 [_Reason]),
		    Error
	    end;
	[probe_ssl|Protos1] ->
	    accept_probe_ssl(X,Protos1,Timeout);
	[http|Protos1] ->
	    {_, Close,Error} = X#rester_socket.tags,
	    X1 = X#rester_socket { packet = http,
				tags = {http, Close, Error }},
	    accept_upgrade(X1,Protos1,Timeout);
	[] ->
	    setopts(X, [{mode,X#rester_socket.mode},
			{packet,X#rester_socket.packet},
			{active,X#rester_socket.active}]),
	    ?log_debug("after upgrade opts=~p",
		 [getopts(X, [active,packet,mode])]),
	    {ok,X}
    end.

accept_probe_ssl(X=#rester_socket { mdata=M, socket=S,
				 tags = {TData,TClose,TError}},
		 Protos,
		 Timeout) ->
    ?log_debug("accept_probe_ssl protos=~p", [Protos]),
    setopts(X, [{active,once}]),
    receive
	{TData, S, Data} ->
	    ?log_debug("Accept data=~p", [Data]),
	    case request_type(Data) of
		ssl ->
		    ?log_debug("request type: ssl",[]),
		    ok = M:unrecv(S, Data),
		    ?log_debug("~p:unrecv(~p, ~p)", [M,S,Data]),
		    %% insert ssl after transport
		    Protos1 = X#rester_socket.protocol--([probe_ssl|Protos]),
		    Protos2 = Protos1 ++ [ssl|Protos],
		    accept_upgrade(X#rester_socket{protocol=Protos2},
				   [ssl|Protos],Timeout);
		_ -> %% not ssl
		    ?log_debug("request type: NOT ssl",[]),
		    ok = M:unrecv(S, Data),
		    ?log_debug("~w:unrecv(~w, ~w)", [M,S,Data]),
		    accept_upgrade(X,Protos,Timeout)
	    end;
	{TClose, S} ->
	    ?log_debug("closed", []),
	    {error, closed};
	{TError, S, Error} ->
	    ?log_warning("error ~w", [Error]),
	    Error
    end.

request_type(<<"GET", _/binary>>) ->    http;
request_type(<<"POST", _/binary>>) ->    http;
request_type(<<"OPTIONS", _/binary>>) ->  http;
request_type(<<"TRACE", _/binary>>) ->    http;
request_type(<<1:1,_Len:15,1:8,_Version:16, _/binary>>) ->
    ssl;
request_type(<<ContentType:8, _Version:16, _Length:16, _/binary>>) ->
    if ContentType == 22 ->  %% HANDSHAKE
	    ssl;
       true ->
	    undefined
    end;
request_type(_) ->
    undefined.

%%
%% rester_socket wrapper for socket operations
%%
close(#rester_socket { mdata = M, socket = S}) ->
    M:close(S).

shutdown(#rester_socket { mdata = M, socket = S}, How) ->
    M:shutdown(S, How).

send(#rester_socket { mdata = M,socket = S } = X, Data) ->
    try M:send(S, Data)
    catch
	error:_ ->
	    shutdown(X, write)
    end.

recv(HSocket, Size) ->
    recv(HSocket, Size, infinity).

recv(#rester_socket { mdata = M, socket = S } = X, Size, Timeout) ->
    try M:recv(S, Size, Timeout)
    catch
	error:E ->
	    shutdown(X, write),
	    erlang:error(E)
    end.

setopts(#rester_socket { mctl = M, socket = S}, Opts) ->
    M:setopts(S, Opts).

getopts(#rester_socket { mctl = M, socket = S}, Opts) ->
    M:getopts(S, Opts).

controlling_process(#rester_socket { mdata = M, socket = S}, NewOwner) ->
    M:controlling_process(S, NewOwner).

sockname(#rester_socket { mctl = M, socket = S}) ->
    M:sockname(S).

peername(#rester_socket { mctl = M, socket = S}) ->
    M:peername(S).

is_ssl(#rester_socket { mctl = ssl}) -> true;
is_ssl(_) -> false.

stats() ->
    inet:stats().

getstat(#rester_socket { transport = Socket}, Stats) ->
    inet:getstat(Socket, Stats).

pair() ->
    pair(inet).
pair(Family) ->  %% inet|inet6
    {ok,L} = gen_tcp:listen(0, [{active,false}]),
    {ok,{IP,Port}} = inet:sockname(L),
    {ok,S1} = gen_tcp:connect(IP, Port, [Family,{active,false}]),
    {ok,S2} = gen_tcp:accept(L),
    gen_tcp:close(L),
    X1 = #rester_socket{socket=S1,
		     mdata = gen_tcp,
		     mctl  = inet,
		     protocol=[tcp],
		     opts=[],
		     tags={tcp,tcp_closed,tcp_error}},
    X2 = #rester_socket{socket=S2,
		     mdata = gen_tcp,
		     mctl  = inet,
		     protocol=[tcp],
		     opts=[],
		     tags={tcp,tcp_closed,tcp_error}},
    {ok,{X1,X2}}.

tags(#rester_socket { tags=Tags}) ->
    Tags.

socket(#rester_socket { socket=Socket }) ->
    Socket.

%% Utils
tcp_listen_options() ->
    [ifaddr, ip, port, fd, inet, inet6,
     tos, priority, reuseaddr, keepalive, linger, sndbuf, recbuf, nodelay,
     header, active, packet, buffer, mode, deliver, backlog,
     exit_on_close, high_watermark, low_watermark, send_timeout,
     send_timeout_close, delay_send, packet_size, raw].

tcp_connect_options() ->
    [ifaddr, ip, port, fd, inet, inet6,
     tos, priority, reuseaddr, keepalive, linger, sndbuf, recbuf, nodelay,
     header, active, packet, packet_size, buffer, mode, deliver,
     exit_on_close, high_watermark, low_watermark, send_timeout,
     send_timeout_close, delay_send,raw].


ssl_listen_opts() ->
    [versions, verify, verify_fun,
     fail_if_no_peer_cert, verify_client_once,
     depth, cert, certfile, key, keyfile,
     password, cacerts, cacertfile, dh, dhfile, cihpers,
     %% deprecated soon
     ssl_imp,   %% always new!
     %% server
     verify_client_once,
     reuse_session, reuse_sessions,
     secure_renegotiate, renegotiate_at,
     debug, hibernate_after, erl_dist ].

ssl_connect_opts() ->
    [versions, verify, verify_fun,
     fail_if_no_peer_cert,
     depth, cert, certfile, key, keyfile,
     password, cacerts, cacertfile, dh, dhfile, cihpers,
     debug].


split_options(Keys, Opts) ->
    split_options(Keys, Opts, [], []).

split_options(Keys, [{Key,Value}|KVs], List1, List2) ->
    case lists:member(Key, Keys) of
	true -> split_options(Keys, KVs, [{Key,Value}|List1], List2);
	false -> split_options(Keys, KVs, List1, [{Key,Value}|List2])
    end;
split_options(Keys, [Key|KVs], List1, List2) ->
    case lists:member(Key, Keys) of
	true -> split_options(Keys, KVs, [Key|List1], List2);
	false -> split_options(Keys, KVs, List1, [Key|List2])
    end;
split_options(_Keys, [], List1, List2) ->
    {lists:reverse(List1), lists:reverse(List2)}.
