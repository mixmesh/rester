%%% @author Tony Rogvall <tony@rogvall.se>
%%% @copyright (C) 2020, Tony Rogvall
%%% @doc
%%%    http server
%%% @end
%%% Created : 15 Oct 2020 by Tony Rogvall <tony@rogvall.se>

-module(rester_http_server).

-behaviour(rester_socket_server).

-include("../include/rester.hrl").

%% rester_socket_server callbacks
-export([init/2,
	 data/3,
	 info/3,
	 close/2,
	 error/3,
	 control/4]).

-include("../include/rester_socket.hrl").
-include("../include/rester_http.hrl").

-define(Q, $\").

-define(SEND_FILE_SEND_SIZE, 8192).

-type socket() :: #rester_socket{}.
-type ustate() :: term().

-record(cb,
	{
	 init ::
	   fun ((Socket::socket(),Options::[{Key::atom(),Value::term()}]) ->
		       UState::ustate()),
	 data ::
	   fun ((Socket::socket(),Data::term(),RState::ustate()) -> 
		       {ok,UState::ustate()} |
		       {stop,{error,Reason::term()},UState::ustate()}),
	 info ::
	   fun ((Socket::socket(),Info::term(),UState::ustate()) ->
		       {ok, UState1::ustate()} |
		       {stop, {error, Reason::term()}, UState1::ustate()}),
	 close ::
	   fun ((Socket::socket(), UState::ustate()) -> 
		       {ok, UState1::ustate()}),
	 error ::
	   fun ((Socket::socket(), Error::term(), UState::ustate()) -> 
		   {stop, {error, Reason::term()}, UState1::ustate()}),
	 control ::
	   fun ((Socket::socket(), Request::term(), From::term(),
		 UState::ustate()) ->
		       {ignore, UState1::ustate()}),
	 http_request ::
	   fun ((Socket::socket(), Request::term(), Body::term(), UState::ustate()) ->
		       {ok, UState1::ustate()} |
		       {stop, {error, Reason::term()}, UState1::ustate()}),
	 creds ::
	   fun ((Socket::socket(), Request::term(), Body::term(), 
		 UState::ustate()) ->
		       {ok, UState1::ustate()} |
		       {stop, {error, Reason::term()}, UState1::ustate()})
	}).

-record(state,
	{
	  request,
	  response,
	  authorized = false :: boolean(),
	  private_key = "" :: string(),
	  access = [] :: [access()],
	  request_module :: undefined | atom(),
	  request_handler,
	  request_state :: undefined | term(),
	  request_cb :: #cb{},
          neighbour_workers :: [{atom(), pid()}]
	}).

-type state() ::  #state{}.

%% configurable start
-export([start/2,
	 start_link/2,
	 stop/1]).

%% http specific auth-handling
-export([handle_creds/5]).


%% send on socket
-export([response/5,
	 response/6]).
-export([response_r/6]).  %% use this one

%% for testing
-export([test/0, test/1]).
-export([test_cb/0, test_cb/1]).
-export([handle_http_request/3]).
-export([exported_info/3]).
%%-----------------------------------------------------------------------------
%% @doc
%%  Starts a socket server on port Port with server options ServerOpts
%% that are sent to the server when a connection is established,
%% i.e init is called.
%%
%% @end
%%-----------------------------------------------------------------------------
-spec start(Port::integer(),
	    ServerOptions::list({Option::atom(), Value::term()})) ->
		   {ok, ChildPid::pid()} |
		   {error, Reason::term()}.

start(Port, Options) ->
    do_start(start, Port, Options).

%%-----------------------------------------------------------------------------
%% @doc
%%  Starts and links a socket server on port Port with server options ServerOpts
%% that are sent to the server when a connection is established,
%% i.e init is called.
%%
%% @end
%%-----------------------------------------------------------------------------
-spec start_link(Port::integer(),
		 ServerOptions::list({Option::atom(), Value::term()})) ->
			{ok, ChildPid::pid()} |
			{error, Reason::term()}.

start_link(Port, Options) ->
    do_start(start_link, Port, Options).


do_start(Start, Port, Options) ->
    ?debug("~w: port ~p, server options ~p", [Start, Port, Options]),
    SessionKeys = [request_handler, request_module,
		   access,
		   private_key,
		   neighbour_workers,
		   idle_timeout,
		   %% individual callbacks (optional)
		   init,data,info,close,error,control,
		   http_request,creds],

    {SessionOptions,ServerOptions} =
	rester_lib:split_options(SessionKeys, Options),
    %% Dir = code:priv_dir(rester),
    %% io:format("SessionOptions: ~p~n", [SessionOptions]),
    %% io:format("ServerOptions: ~p~n", [ServerOptions]),

    Access = proplists:get_value(access, SessionOptions, []),
    case rester_lib:validate_access(Access) of
	ok ->
	    rester_socket_server:Start(Port,
				       [tcp,probe_ssl,http],
				       [{active,once},{reuseaddr,true},
					{verify, verify_none}
					%% {keyfile, filename:join(Dir, "host.key")},
					%% {certfile, filename:join(Dir, "host.cert")}
				       | ServerOptions],
				       ?MODULE, SessionOptions);
	E -> E
    end.

%%-----------------------------------------------------------------------------
%% @doc
%%  Stops the socket server.
%%
%% @end
%%-----------------------------------------------------------------------------
-spec stop(Pid::pid()) ->
		   {ok, ChildPid::pid()} |
		   {error, Reason::term()}.
stop(Pid) ->
    rester_socket_server:stop(Pid).

%%-----------------------------------------------------------------------------
%% @doc
%%  Init function called when a connection is established.
%%
%% @end
%%-----------------------------------------------------------------------------
-spec init(Socket::socket(),
	   ServerOptions::list({Option::atom(), Value::term()})) ->
		  {ok, State::state()}.

init(Socket, Options) ->
    ?debug("connection on: ~p ", [Socket]),
    _PeerName = rester_socket:peername(Socket),
    _SockName = rester_socket:sockname(Socket),
    ?debug("connection from peer: ~p, sockname: ~p,"
		"options ~p", [_PeerName, _SockName, Options]),
    %% rester_socket:setopts(Socket, [{nodelay,true}]),
    Access = proplists:get_value(access, Options, []),
    RH = proplists:get_value(request_handler, Options, undefined),
    Module = proplists:get_value(request_module, Options, undefined),
    RCb = load_callbacks(Module, #cb{}, Options),
    PrivateKey = proplists:get_value(private_key, Options, ""),
    NeighbourWorkers = proplists:get_value(neighbour_workers, Options, undefined),
    S0 = #state{request_module = RH,
		request_cb = RCb,
		request_state = #{} },
    S1 = cb(init, [Socket,Options], S0),
    {ok, S1#state{access = Access, private_key=PrivateKey, 
		  neighbour_workers = NeighbourWorkers}}.

%% To avoid a compiler warning. Should we actually support something here?
%%-----------------------------------------------------------------------------
%% @doc
%%  Control function - not used.
%%
%% @end
%%-----------------------------------------------------------------------------
-spec control(Socket::socket(),
	      Request::term(), From::term(), State::state()) ->
		     {ignore, State::state()}.

control(_Socket, _Request, _From, State) ->
    {ignore, State}.

%%-----------------------------------------------------------------------------
%% @doc
%%  Data function called when data is received.
%%
%% @end
%%-----------------------------------------------------------------------------
-spec data(Socket::socket(),
	   Data::term(),
	   State::state()) ->
		  {ok, NewState::state()} |
		  {stop, {error, Reason::term()}, NewState::state()}.

data(Socket, Data, State) ->
    ?debug("~w: data = ~w", [self(),Data]),
    case Data of
	{http_request, Method, Uri, Version} ->
	    CUri = rester_http:convert_uri(Uri),
	    Req  = #http_request { method=Method,uri=CUri,version=Version},
	    case rester_http:recv_headers(Socket, Req) of
		{ok, Req1} ->
		    handle_request(Socket, Req1, State);
		Error ->
		    {stop, Error, State}
	    end;
	{http_error, ?CRNL} ->
	    {ok, State};
	{http_error, ?NL} ->
	    {ok, State};
	_ when is_list(Data); is_binary(Data) ->
	    ?debug("request data: ~p", [Data]),
	    {stop, {error,sync_error}, State};
	Error ->
	    {stop, Error, State}
    end.

%%-----------------------------------------------------------------------------
%% @doc
%%  Info function called when info is received.
%%
%% @end
%%-----------------------------------------------------------------------------
-spec info(Socket::socket(),
	   Info::term(),
	   State::state()) ->
	  {ok, NewState::state()} |
	  {stop, {error, Reason::term()}, NewState::state()}.

info(Socket, Info, State) ->
    ?debug("~w: info = ~w", [self(),Info]),
    cb(info, [Socket,Info], State).

%%-----------------------------------------------------------------------------
%% @doc
%%  Close function called when a connection is closed.
%%
%% @end
%%-----------------------------------------------------------------------------
-spec close(Socket::socket(),
	    State::state()) ->
		   {ok, NewState::state()}.

close(Socket, State) ->
    ?debug("close"),
    cb(close, [Socket], State).

%%-----------------------------------------------------------------------------
%% @doc
%%  Error function called when an error is detected.
%%  Stops the server.
%%
%% @end
%%-----------------------------------------------------------------------------
-spec error(Socket::socket(),
	    Error::term(),
	    State::state()) ->
		   {stop, {error, Reason::term()}, NewState::state()}.

error(Socket,Error,State) ->
    ?debug("error = ~p", [Error]),
    cb(error, [Socket,Error], State).


handle_request(Socket, R, State) ->
    ?debug("request = ~s",
	 [[rester_http:format_request(R),?CRNL,
	   rester_http:format_hdr(R#http_request.headers),
	   ?CRNL]]),
    case rester_http:recv_body(Socket, R) of
	{ok, Body} ->
	    ?debug("body = ~p", [Body]),
	    case handle_auth(Socket, R, Body, State) of
		ok ->
		    handle_body(Socket, R, Body, State);
		{required,AuthenticateValue,State} ->
		    ?debug("autentication required"),
		    V = response_r(Socket,R,401,"Unauthorized", "",
				   [{'WWW-Authenticate', AuthenticateValue}]),
		    case V of
			ok -> {ok,State};
			stop -> {stop, normal, State}
		    end;
		{error, unauthorised} ->
		    ?debug("unauthorised"),
		    V = response_r(Socket,R,401,"Unauthorized","",[]),
		    case V of
			ok -> {ok,State};
			stop -> {stop, normal, State}
		    end
	    end;

	{error, closed} ->
	    ?warning("socket closed"),
	    {stop, normal,State};
	Error ->
	    ?warning("socket error ~p", [Error]),
	    {stop, Error, State}
    end.

handle_auth(_Socket, _Request, _Body, State)
  when State#state.authorized ->
    ok;
handle_auth(_Socket, _Request, _Body, State=#state {access = []})
  when not State#state.authorized ->
    %% No access specied, all is allowed.
    ok;
handle_auth(Socket, Request, Body, State=#state {access = Access})
  when not State#state.authorized ->
    rester_lib:handle_access(Access, Socket,
                             {?MODULE, handle_creds,
                              [Socket, Request, Body, State]}).

handle_creds(Creds, Socket, Request, Body, State) ->
    Header = Request#http_request.headers,
    Autorization = get_authorization(Header#http_chdr.authorization),
    ?debug("authorization = ~p", [Autorization]),
    case match_access_path(Request#http_request.uri, Creds) of
	[Cred={basic,_Path,_User,_Password,_Realm}|_] ->
	    ?debug("cred = ~p", [Cred]),
	    handle_basic_auth(Socket, Request, Body, Autorization,
			      Cred, State);
	[Cred={digest,_Path,_User,_Password,_Realm}|_] ->
	    handle_digest_auth(Socket, Request, Body, Autorization,
				       Cred, State);
	[] -> ok
    end.

handle_basic_auth(_Socket, _Request, _Body, {basic,AuthParams},
		  _Cred={basic,_Path,User,Password,Realm}, State) ->
    AuthUser =  proplists:get_value(<<"user">>, AuthParams),
    AuthPassword = proplists:get_value(<<"password">>, AuthParams),
    if AuthUser =:= User, AuthPassword =:= Password ->
	    ok;
       true ->
	    {required, ["Basic realm=",?Q,Realm,?Q], State}
    end;
handle_basic_auth(_Socket, _Request, _Body, _,
		  _Cred={basic,_Path,_User,_Password,Realm}, State) ->
    {required, ["Basic realm=",?Q,Realm,?Q], State}.


handle_digest_auth(_Socket, Request, _Body, {digest,AuthParams},
		   Cred={digest,_Path,_User,_Password,_Realm}, State) ->
    Response = proplists:get_value(<<"response">>,AuthParams,""),
    Method = Request#http_request.method,
    Digest = rester_http:make_digest_response(Cred, Method, AuthParams),
    %% io:format("response=~p, digest=~p", [Response,Digest]),
    if Digest =:= Response ->
	    ok;
       true ->
	    digest_required(Request, Cred, State)
    end;
handle_digest_auth(_Socket, Request, _Body, _, Cred, State) ->
    digest_required(Request, Cred, State).

digest_required(Request,_Cred={digest,_Path,_User,_Password,Realm},State) ->
    Nonce = nonce_value(Request, State),
    {required, ["Digest realm=",?Q,Realm,?Q," ",
%%		"url=",?Q,Path,?Q," ",
		"nonce=",?Q,Nonce,?Q], State}.

nonce_value(Request, State) ->
    Header = Request#http_request.headers,
    ETag = unq(proplists:get_value('ETag',Header#http_chdr.other,"")),
    T = now64(),
    TimeStamp = hex(<<T:64>>),
    hex(crypto:hash(md5,[TimeStamp,":",ETag,":",State#state.private_key])).


%% convert binary to ASCII hex
hex(Bin) ->
    [ element(X+1, {$0,$1,$2,$3,$4,$5,$6,$7,$8,$9,$a,$b,$c,$d,$e,$f}) ||
	<<X:4>> <= Bin ].

now64() ->
    try
	erlang:system_time(milli_seconds)
    catch
	error:undef ->
	    {M,S,Us} = erlang:timestamp(),
	    (M*1000000+S)*1000000+Us
    end.

match_access_path(Url, Access) ->
    match_access_path(Url, Access, []).

match_access_path(Url, [A={_Type,Path,_U,_P,_R}|Access], Acc) ->
    case lists:prefix(Path, Url#url.path) of
	true ->
	    match_access_path(Url, Access, [A|Acc]);
	false ->
	    match_access_path(Url, Access, Acc)
    end;
match_access_path(_Url, [], Acc) ->
    %% find the access with the longest path match
    lists:sort(
      fun({_,Path1,_,_,_},{_,Path2,_,_,_}) ->
	      length(Path1) > length(Path2)
      end, Acc).


%% Read and parse Authorization header value
get_authorization(undefined) ->
    {none,[]};
get_authorization([]) ->
    {none,[]};
get_authorization([$\s|Cs]) ->
    get_authorization(Cs);
get_authorization("Basic "++Cs) ->
    [User,Password] = binary:split(base64:decode(Cs), <<":">>),
    {basic, [{<<"user">>,User}, {<<"password">>, Password}]};
get_authorization("Digest "++Cs) ->
    {digest, get_params(list_to_binary(Cs))}.

get_params(Bin) ->
    Ps = binary:split(Bin, <<", ">>, [global]),
    [ case binary:split(P, <<"=">>) of
	  [K,V] -> {K,unq(V)};
	  [K] -> {K,true}
      end || P <- Ps ].

%% "unquote" a string or a binary
unq(String) when is_binary(String) -> unq(binary_to_list(String));
unq([$\s|Cs]) -> unq(Cs);
unq([?Q|Cs]) -> unq_(Cs);
unq(Cs) -> Cs.

unq_([?Q|_]) -> [];
unq_([C|Cs]) -> [C|unq_(Cs)];
unq_([]) -> [].

handle_body(Socket, Request, Body, State) ->
    RH = State#state.request_handler,
    ?debug("calling ~p with -BODY:\n~p\n-END-BODY", [RH, Body]),
    case (State#state.request_cb)#cb.http_request of
	undefined ->
	    {M, F, As} = request_handler(RH, Socket, Request, Body, State),
	    try apply(M, F, As) of
		ok -> {ok, State};
		stop -> {stop, normal, State};
		{error, Error} ->  {stop, Error, State}
	    catch error:_E ->
		    ?error("call to request_handler ~p failed, reason ~p",
			   [RH, _E]),
		    {stop, internal_error, State}
	    end;
	_HttpRequest ->
	    cb(http_request, [Socket, Request, Body], State)
    end.

%% @private
request_handler(undefined, Socket, Request, Body, _State) ->
    {?MODULE, handle_http_request, [Socket, Request, Body]};
request_handler(Module, Socket, Request, Body, _State) when is_atom(Module) ->
    {Module, handle_http_request, [Socket, Request, Body]};
request_handler({Module, Function}, Socket, Request, Body, _State) ->
    {Module, Function, [Socket, Request, Body]};
request_handler({Module, Function, XArgs}, Socket, Request, Body, State)
  when is_list(XArgs) ->
    {Module, Function, [Socket, Request, Body, [{neighbour_workers, State#state.neighbour_workers}|XArgs]]};
request_handler({Module, Function, XArgs}, Socket, Request, Body, _State) ->
    {Module, Function, [Socket, Request, Body, XArgs]}.

%%-----------------------------------------------------------------------------
%% @doc
%%  Support function for sending an http response.
%%
%% @end
%%-----------------------------------------------------------------------------
-spec response(Socket::socket(),
	       Connection::string() | undefined,
	       Status::integer(),
	       Phrase::string(),
	       Body::string()) -> ok | {error, Reason::term()}.

response(S, Connection, Status, Phrase, Body) ->
    response(S, Connection, Status, Phrase, Body, []).

%%-----------------------------------------------------------------------------
%% @doc
%%  Support function for sending an http response.
%%
%% @end
%%-----------------------------------------------------------------------------
-spec response(Socket::socket(),
	       Connection::string() | undefined,
	       Status::integer(),
	       Phrase::string(),
	       Body::string(),
	       Opts::list()) -> ok | {error, Reason::term()}.

response(S, Connection, Status, Phrase, Body, Opts) ->
    {Version, Opts0} = opt_take(version, Opts, {1,1}),
    {Content_type, Opts1} = opt_take(content_type, Opts0, "text/plain"),
    {Set_cookie, Opts2} = opt_take(set_cookie, Opts1, undefined),
    {Transfer_encoding,Opts3} =
	if Version > {1,0} ->
		opt_take(transfer_encoding, Opts2, undefined);
	   true ->
		{_,Opts3_1} = opt_take(transfer_encoding, Opts2, undefined),
		{undefined, Opts3_1}
	end,
    {Location,Opts4} = opt_take(location, Opts3, undefined),
    ContentLength = if Transfer_encoding =:= "chunked", Body =:= "" ->
			    undefined;
		       true ->
			    content_length(Body)
		    end,
    Connection1 = if Version =:= {1,0}, Connection =/= "keep-alive" ->
			  "close";
		     Version > {1,0}, Connection =:= "close" ->
			  "close";
		     true ->
			  Connection
		  end,

    H = #http_shdr { connection = Connection1,
		     content_length = ContentLength,
		     content_type = Content_type,
		     set_cookie = Set_cookie,
		     transfer_encoding = Transfer_encoding,
		     location = Location,
		     other = Opts4 },

    R = #http_response { version = Version,
			 status = Status,
			 phrase = Phrase,
			 headers = H },
    Response = [rester_http:format_response(R),
		?CRNL,
		rester_http:format_hdr(H),
		?CRNL,
		Body],
    ?debug("response:\n~s", [Response]),
    rester_socket:send(S, Response),
    if Connection1 =:= "close" ->
	    stop;
       true ->
	    ok
    end.

%% replace the above with this code instead
%% response version is 1.1
-define(SERVER_HTTP_VSN, {1,1}).

response_r(S, Request, Status, Phrase, Body, Opts) ->
    {Version, Opts0} = opt_take(version, Opts, ?SERVER_HTTP_VSN),
    {Content_type0, Opts1} = opt_take(content_type, Opts0, "text/plain"),
    case Content_type0 of
        {url, Url} ->
            Content_type = mime_type(Url, "application/octet-stream");
        _ ->
            Content_type = Content_type0
    end,
    {Set_cookie, Opts2} = opt_take(set_cookie, Opts1, undefined),
    {Transfer_encoding,Opts3} =
	if Request#http_request.version > {1,0} ->
		opt_take(transfer_encoding, Opts2, undefined);
	   true ->
		{_,Opts3_1} = opt_take(transfer_encoding, Opts2, undefined),
		{undefined, Opts3_1}
	end,
    {Location,Opts4} = opt_take(location, Opts3, undefined),
    CH = Request#http_request.headers,
    {Connection0,Opts5} = opt_take(connection, Opts4, CH#http_chdr.connection),
    Connection = if Connection0 =:= undefined -> undefined;
		    is_list(Connection0) -> string:to_lower(Connection0)
		 end,
    ContentLength = if Transfer_encoding =:= "chunked", Body =:= "" ->
			    undefined;
		       true ->
			    content_length(Body)
		    end,
    Connection1 = if Request#http_request.version =:= {1,0},
		     Connection =/= "keep-alive" ->
			  "close";
		     true ->
			  Connection
		  end,
    H = #http_shdr { connection = Connection1,
		     content_length = ContentLength,
		     content_type = Content_type,
		     set_cookie = Set_cookie,
		     transfer_encoding = Transfer_encoding,
		     location = Location,
		     other = Opts5 },
    R = #http_response { version = Version,
			 status = Status,
			 phrase = Phrase,
			 headers = H },
    Response = [rester_http:format_response(R),
		?CRNL,
		rester_http:format_hdr(H),
		?CRNL,
		case Body of
                    {file, _Filename} ->
                        [];
                    {skip_body, _} ->
                        [];
                    _ ->
                        Body
                end],
    ?debug("response:\n~s", [Response]),
    rester_socket:send(S, Response),
    case Body of
        {file, Filename} ->
            sendfile(Filename, S);
        _ ->
            ok
    end,
    if Connection1 =:= "close" ->
	    stop;
       true ->
	    ok
    end.

sendfile(Filename, #rester_socket{protocol = Protocol, socket = Socket})
  when Protocol == tcp orelse Protocol == http ->
    file:sendfile(Filename, Socket);
%% https://bugs.erlang.org/projects/ERL/issues/ERL-1293
sendfile(Filename, S) ->
    case file:open(Filename, [read, binary]) of
        {error, Reason} ->
            {error, Reason};
        {ok, File} ->
            _ = senddata(S, File),
            file:close(File)
    end.

senddata(S, File) ->
    case file:read(File, ?SEND_FILE_SEND_SIZE) of
        {ok, Chunk} ->
            _ = rester_socket:send(S, Chunk),
            case size(Chunk) < ?SEND_FILE_SEND_SIZE of
                true ->
                    ok;
                false ->
                    senddata(S, File)
            end;
        _ ->
            ok
    end.

mime_type(Url, DefaultMimeType) ->
    case mime_type(string:lowercase(filename:extension(Url))) of
        not_found ->
            DefaultMimeType;
        MimeType ->
            MimeType
    end.

%% This is an inferior solution
mime_type(".html") -> "text/html";
mime_type(".css") -> "text/css";
mime_type(".js") -> "application/javascript";
mime_type(".gif") -> "image/gif";
mime_type(".png") -> "image/png";
mime_type(".jpg") -> "image/jpeg";
mime_type(".svg") -> "image/svg+xml";
mime_type(".ico") -> "image/x-icon";
mime_type(".webmanifest") -> "application/manifest+json";
mime_type(_) -> not_found.

content_length({file, Filename}) ->
    filelib:file_size(Filename);
content_length({skip_body, ContentLength}) ->
    ContentLength;
content_length(B) when is_binary(B) ->
    byte_size(B);
content_length(L) when is_list(L) ->
    iolist_size(L).

%% return value or defaule and the option list without the key
opt_take(K, L, Def) ->
    case lists:keytake(K, 1, L) of
	{value,{_,V},L1} -> {V,L1};
	false -> {Def,L}
    end.

%% @private
handle_http_request(Socket, Request, Body) ->
    Url = Request#http_request.uri,
    ?debug("\n-BODY:\n~s\n-END-BODY", [Body]),
    if Request#http_request.method =:= 'GET',
       Url#url.path =:= "/quit" ->
	    response_r(Socket, Request, 200, "OK", "QUIT",
		       [{connection,"close"}]),
	    rester_socket:shutdown(Socket, write),
	    stop;
       Url#url.path =:= "/test" ->
	    response_r(Socket, Request, 200, "OK", "OK", []),
	    ok;
       true ->
	    response_r(Socket, Request, 404, "Not Found",
		       "Object not found", []),
	    ok
    end.

load_callbacks(undefined, RHb, Options) ->
    load_exports(undefined, [], RHb, Options);
load_callbacks(Module, RHb, Options) when is_atom(Module) ->
    Exports = load_module(Module),
    load_exports(Module, Exports, RHb, Options).


load_exports(Module, Exports, RHb, Options) ->
    Init = load_cb(Module, init, 2, Exports, Options),
    Data = load_cb(Module, data, 3, Exports, Options),
    Info = load_cb(Module, info, 3, Exports, Options),
    Close = load_cb(Module, close, 2, Exports, Options),
    Error = load_cb(Module, error, 3, Exports, Options),
    Control = load_cb(Module, control, 4, Exports, Options),
    HttpRequest = load_cb(Module, http_request, 4, Exports, Options),
    Creds = load_cb(Module, creds, 4, Exports, Options),
    RHb#cb{init = Init,
	   data = Data,
	   info = Info,
	   close = Close,
	   error = Error,
	   control = Control,
	   http_request = HttpRequest,
	   creds = Creds
	  }.

load_cb(Module, Function, Arity, Exports, Options) ->
    case proplists:get_value(Function, Options, undefined) of
	undefined ->
	    case lists:member({Function,Arity},Exports) of
		true ->
		    fun Module:Function/Arity;
		false ->
		    ?debug("function ~s:~s/~w not exported",
			   [ Module, Function, Arity]),
		    undefined
	    end;
	Function1 when is_atom(Function1) ->
	    case lists:member({Function1,Arity},Exports) of
		true ->
		    fun Module:Function1/Arity;
		false ->
		    ?debug("function ~s:~s/~w not exported",
			   [ Module, Function1, Arity]),
		    undefined
	    end;
	{Module1,Function1} when is_atom(Module1), is_atom(Function1) ->
	    Exports1 = load_module(Module1),
	    case lists:member({Function1,Arity},Exports1) of
		true ->
		    fun Module1:Function1/Arity;
		false ->
		    ?debug("function ~s:~s/~w not exported",
			   [Module1, Function1, Arity]),
		    undefined
	    end;
	Fun when is_function(Fun,Arity) ->
	    Fun
    end.

load_module(Module) ->
    try code:ensure_loaded(Module) of
	{module, Module} ->
	    Module:module_info(exports);
	{error, nofile} ->
	    ?debug("loading module ~p failed, reason ~p", [Module, nofile]),
	    []
    catch
	error:Reason ->
	    ?debug("loading module ~p failed, reason ~p", [Module, Reason]),
	    []
    end.
    

%% Callbacks
cb(init, [Socket,Options], State) ->
    case (State#state.request_cb)#cb.init of
	undefined ->
	    State#state { request_state = #{}};  %% dummy state
	Cb ->
	    try Cb(Socket, Options) of
		{ok, RState} ->
		    State#state { request_state = RState }
	    catch
		error:_ ->
		    State#state { request_state = #{}}  %% dummy state
	    end
    end;
cb(info, [Socket,Info], State) ->
    case (State#state.request_cb)#cb.info of
	undefined -> 
	    {ok,State};
	Cb ->
	    RState = State#state.request_state,
	    try Cb(Socket,Info,RState) of
		{ok,RState1} ->
		    {ok, State#state{request_state = RState1}};
		{stop, Error, RCbState} ->
		    {stop, Error, State#state{request_state = RCbState}}
	    catch
		error:Reason -> 
		    %% fixme: log error
		    {stop, Reason, State}
	    end
    end;
cb(close, [Socket], State) ->
    case (State#state.request_cb)#cb.close of
	undefined ->
	    {ok,State};
	Cb ->
	    RState = State#state.request_state,
	    try Cb(Socket, RState) of
		{ok,RState1} ->
		    {ok, State#state{request_state = RState1}}
	    catch
		error:_Reason -> 
		    %% fixme: log error
		    {ok, State}
	    end
    end;
cb(error, [Socket,Error], State) ->
    case (State#state.request_cb)#cb.close of
	undefined ->
	    {ok,State};
	Cb ->
	    RState = State#state.request_state,
	    try Cb(Socket,Error,RState) of
		{stop,Error,RState1} ->
		    {stop,Error,State#state{request_state = RState1}}
	    catch
		error:_Reason -> 
		    %% fixme: log error
		    {ok, State}
	    end
    end;
cb(http_request, [Socket, Request, Body], State) ->
    case (State#state.request_cb)#cb.http_request of
	false ->
	    {ok, State};
	Cb ->
	    RState = State#state.request_state,
	    try Cb(Socket, Request, Body, RState) of
		ok -> 
		    {ok, State};
		{ok, RState1} ->
		    {ok, State#state{request_state = RState1}};
		stop ->
		    {stop, normal, State};
		{stop, Error, RState1} ->
		    {stop, Error, State#state{request_state = RState1}};
		{error, Error} ->
		    {stop, Error, State}
	    catch
		error:Reason ->
		    ?error("call to request_handler ~p failed, reason ~p",
			   [{State#state.request_module,handle_http_request,4},
			    Reason]),
		    {stop, internal_error, State}
	    end
    end.

%%-----------------------------------------------------------------------------
test() ->
    %% Access = [],
    Access = [{basic,"/foo",<<"user">>,<<"password">>,"world"},
	      {digest,"/test/a",<<"test">>,<<"a">>,"region"},
	      {digest,"/test/b",<<"test">>,<<"b">>,"region"},
	      {digest,"/test/b/c",<<"test">>,<<"c">>,"region"},
	      {digest,"/test/b/d",<<"test">>,<<"d">>,"region"},
	      {digest,"/test",<<"test">>,<<"x">>,"region"},
	      {digest,"/bar",<<"test">>,<<"bar">>,"region"}
	     ],
    test(Access).

test(old) ->
    test();
test(new) ->
   Access = [{afunix, accept},
	     {{127, 0, 0, 1},
	      {access, [
			{basic,"/foo",<<"user">>,<<"password">>,"world"},
			{digest,"/test/a",<<"test">>,<<"a">>,"region"},
			{digest,"/test/b",<<"test">>,<<"b">>,"region"},
			{digest,"/test/b/c",<<"test">>,<<"c">>,"region"},
			{digest,"/test/b/d",<<"test">>,<<"d">>,"region"},
			{digest,"/test",<<"test">>,<<"x">>,"region"},
			{digest,"/bar",<<"test">>,<<"bar">>,"region"}]}}
	     ],
    test(Access);
test(Access) ->
    Dir = code:priv_dir(rester),
    rester:start(),
    rester_socket_server:start(9000, [tcp,probe_ssl,http],
			       [{active,once},{reuseaddr,true},
				{verify, verify_none},
				{keyfile, filename:join(Dir, "host.key")},
				{certfile, filename:join(Dir, "host.cert")}],
			       ?MODULE, [{access,Access}]).

test_cb() ->
    test_cb(8888).

test_cb(Port) when is_integer(Port), Port >= 1, Port =< 65535 ->
    Callbacks = [
		 {init, fun (_Socket, _Options) ->
				io:format("INIT ~w\n", [self()]),
				self() ! test_info,
				{ok, #{}}
			end},

		 {data, fun (_Socket, _Data, State) ->
				io:format("DATA ~p\n", [_Data]),
				{ok, State}
			end},

		 {info, {?MODULE,exported_info}},

		 {close, fun local_close/2},
 
		 {error, fun (_Socket, _Error, State) ->
				 io:format("ERROR ~p\n", [_Error]),
				 {stop, normal, State}
			 end},

		 {http_request, fun (_Socket, _Request, _Body, State) ->
					io:format("HTTP(~w) ~p\n", 
						  [self(),_Request]),
					handle_http_request(_Socket, _Request, _Body),
					{ok, State}
				end}
		],
    rester:start(),
    rester_http_server:start(Port, [{access,[]} | Callbacks]).

local_close(_Socket, State) ->
    io:format("CLOSE\n"),
    {ok, State}.

exported_info(_Socket, _Info, State) ->
    io:format("INFO ~p\n", [_Info]),
    {ok, State}.
