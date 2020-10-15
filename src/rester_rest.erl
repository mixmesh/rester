%%% @author Tony Rogvall <tony@rogvall.se>
%%% @copyright (C) 2020, Tony Rogvall
%%% @doc
%%%    REST server
%%% @end
%%% Created : 15 Oct 2020 by Tony Rogvall <tony@rogvall.se>

-module(rester_rest).

-include("../include/rester.hrl").
-include("../include/rester_socket.hrl").
-include("../include/rester_http.hrl").

-include_lib("pki/include/pki_serv.hrl").

%% API
-export([start/1]).
-export([start_link/1]).
-export([handle_http_request/4]).

-define(IDLE_TIMEOUT, infinity). %% 60 * 1000).
-define(SEND_TIMEOUT, infinity). %% default send timeout

-define(DEFAULT_PORT, 7777).
-define(DEFAULT_XYLAN, "/tmp/hoc33").
-define(LATEST_VSN, v1).

-ifdef(OTP_RELEASE). %% this implies 21 or higher
-define(EXCEPTION(Class, Reason, Stacktrace), Class:Reason:Stacktrace).
-define(GET_STACK(Stacktrace), Stacktrace).
-else.
-define(EXCEPTION(Class, Reason, _), Class:Reason).
-define(GET_STACK(_), erlang:get_stacktrace()).
-endif.


start(Args) ->
    do_start(start, Args).

start_link(Args) ->
    do_start(start_link, Args).

do_start(Start, Args0) ->
    ?log_debug("starting with ~p", [Args0]),
    Dir = code:priv_dir(rester),
    case proplists:get_value(port, Args0) of
	undefined -> {error, no_port};
	Port ->
	    ?log_info("starting on ~p", [Port]),
	    SO = socket_options(Args0),
	    IdleTimeout = 
		case proplists:get_value(idle_timeout, SO, ?IDLE_TIMEOUT) of
		    I when is_integer(I) -> I + 100; %% Give exo extra time
		    T -> T
		end,
	    SendTimeout = 
		proplists:get_value(send_timeout, SO, ?SEND_TIMEOUT),

	    SO1 = lists:foldl(fun(Key,Ai) ->
				      proplists:delete(Key,Ai)
			      end, SO, [port,idle_timeout,send_timeout]),
	    ExoArgs = [{request_handler, 
			{?MODULE, handle_http_request, []}},
		       {verify, verify_none},
		       {keyfile, filename:join(Dir, "key.pem")},
		       {certfile, filename:join(Dir, "cert.pem")},
		       {nodelay, true},
		       {idle_timeout, IdleTimeout},
		       {send_timeout, SendTimeout} | SO1],
	    rester_http_server:Start(Port, ExoArgs)
    end.

socket_options() ->
    socket_options(application:get_all_env(rester)).

socket_options(Args) ->
    case proplists:get_value(socket_options, Args, undefined) of
	undefined -> Args; %% backwards compatible
	Options -> Options
    end.

handle_http_request(Socket, Request, Body, Options) ->
    ?log_debug("request = ~s, headers=~s, body=~p", 
		[rester_http:format_request(Request),
		 rester_http:format_hdr(Request#http_request.headers),
		 Body]),
    put(test, proplists:get_value(test, Options, false)),
    try handle_http_request_(Socket, Request, Body) of
	Result -> Result
    catch
	?EXCEPTION(error,Reason,_StackTrace) ->
	    ?log_error("handle_http_request: crash reason=~p\n~p\n",
		       [Reason, ?GET_STACK(_StackTrace)]),
	    erlang:error(Reason)
    end.

handle_http_request_(Socket, Request, Body) ->
    case Request#http_request.method of 
	'GET' ->
	    handle_http_get(Socket, Request, Body);
	'PUT' ->
	    handle_http_put(Socket, Request, Body);
	'POST' ->
	    handle_http_post(Socket, Request, Body);
	_ ->
	    response(Socket, Request, {error, not_allowed})
    end.

%%
%% Handle GET request
%% - [vi]/index.htm[l]
%% - /versions                        return an json array of supported versions
%%

handle_http_get(Socket, Request, Body) ->
    Url = Request#http_request.uri,
    case string:tokens(Url#url.path,"/") of
	["versions"] ->
	    Object = jsone:encode([v1,v2,v3]),
	    rester_http_server:response_r(Socket,Request,200, "OK",
					  Object,
					  [{content_type,"application/json"}]);
	["v1" | Tokens] -> 
	    handle_http_get(Socket, Request, Url, Tokens, Body, v1);
	["v2" | Tokens] -> 
	    handle_http_get(Socket, Request, Url, Tokens, Body, v2);
	["v3" | Tokens] ->
	    handle_http_get(Socket, Request, Url, Tokens, Body, v3);
	%% index page in serveral flavours
	Tokens = ["index.html"] ->
	    handle_http_get(Socket, Request, Url, Tokens, Body, v3);
	Tokens = ["index.htm"] ->
	    handle_http_get(Socket, Request, Url, Tokens, Body, v3);
	Tokens = ["index"] ->
	    handle_http_get(Socket, Request, Url, Tokens, Body, v3);
	Tokens = [] ->
	    handle_http_get(Socket, Request, Url, Tokens, Body, v3);
	["v4" | _Tokens] ->
	    response(Socket, Request, 
		     {error, bad_request, "v4 not implemented"});
	Tokens ->
	    handle_http_get(Socket, Request, Url, Tokens, Body, v1)
    end.

handle_http_get(Socket, Request, Url, Tokens, Body, v3) ->
    Access = access(Socket),
    Accept = rester_http:accept_media(Request),
    case Tokens of
	[] ->
	    response(Socket, Request, index(Accept));
	["index.html"] ->
	    response(Socket, Request, index(Accept));
	["index.htm"] ->
	    response(Socket, Request, index(Accept));
	["index"] ->
	    response(Socket, Request, index(Accept));
	["system-time"] ->
	    response(Socket, Request, 
		     {ok, integer_to_list(erlang:system_time(milli_seconds))});
	["event-channel"] ->
	    F = parse_filter(Url#url.querypart),
	    event_channel(Access, Socket, Request, F, v3);
	["event-channel", Id, "refresh"] ->
	    response(Socket, Request, 
		     rester_channel:refresh_event_channel(Access, Id));
	_Other ->
	    handle_http_get(Socket, Request, Url, Tokens, Body, v2)
    end;
handle_http_get(Socket, Request, Url, Tokens, Body, v2) ->
    case Tokens of
	["event-channel"] ->
	    F = parse_filter(Url#url.querypart),
	    event_channel(access(Socket), Socket, Request, F, v2);
	_Other ->
	    handle_http_get(Socket, Request, Url, Tokens, Body, v1)
    end;
handle_http_get(Socket, Request, Url, Tokens, _Body, v1) ->
    Access = access(Socket),
    case Tokens of
	["public"] ->
	    %% list public keys in a table
	    Tab = ets:foldl(
		    fun(#pki_user{name=Name,public_key=Pk}, Acc) ->
			    MD5 = crypto:hash(md5, belgamal:public_key_to_binary(Pk)),
			    Fs = [tl(integer_to_list(B+16#100,16)) || 
				     <<B>> <= MD5],
			    [{Name, Fs}|Acc]
		    end, [], pki_db),
	    response(Socket,Request,html_doc(html_table(Tab)));

	["event-channel"] ->
	    F = parse_filter(Url#url.querypart),
	    event_channel(Access, Socket, Request, F, v1);
	Tokens ->
	    ?log_debug("~p not found", [Tokens]),
	    response(Socket, Request, {error, not_found})
    end.

%% General PUT request uri:
%% inventory/<label>/present  set present for item
%% inventory/present/<label>  set present for item
%% parameter/<label>/<param>  set value for param on label(channel)
%% value/<label>              set item value
%% <label>/parameter/<param>  set value for param on label(channel)
%% <label>/value              set item value
%% <node-id>/output/<i>
%% <node-id>/output/<i>/<param>
%% <node-id>/input/<i>
%% <node-id>/input/<i>/<param>
%% <node-id>/adc/<i>
%% <node-id>/param
%%
handle_http_put(Socket, Request, Body) ->
    Url = Request#http_request.uri,
    case string:tokens(Url#url.path,"/") of
	["v1" | Tokens] ->
	    handle_http_put(Socket, Request, Url, Tokens, Body, v1);
	["v2" | Tokens] ->
	    handle_http_put(Socket, Request, Url, Tokens, Body, v2);
	["v3" | Tokens] ->
	    handle_http_put(Socket, Request, Url, Tokens, Body, v3);
	Tokens ->
	    handle_http_put(Socket, Request, Url, Tokens, Body, v1)
    end.

handle_http_put(Socket, Request, Url, Tokens, Body, v3) ->
    case Tokens of
	_Other ->
	    handle_http_put(Socket, Request, Url, Tokens, Body, v2)
    end;
handle_http_put(Socket, Request, Url, Tokens, Body, v2) ->
    case Tokens of
	_Other ->
	    handle_http_put(Socket, Request, Url, Tokens, Body, v1)
    end;
handle_http_put(Socket, Request, _Url, Tokens, Body, v1) ->
    case Tokens of
	Tokens ->
	    ?log_debug("~p not found", [Tokens]),
	    response(Socket, Request, {error, not_found})
    end.

%% General POST request uri:
%% - [/vi]/item
%%
handle_http_post(Socket, Request, Body) ->
   Url = Request#http_request.uri,
    case string:tokens(Url#url.path,"/") of
	["v1" | Tokens] -> 
	    handle_http_post(Socket, Request, Url, Tokens, Body, v1);
	["v2" | Tokens] -> 
	    handle_http_post(Socket, Request, Url, Tokens, Body, v2);
	["v3" | Tokens] ->
	    handle_http_post(Socket, Request, Url, Tokens, Body, v3);
	Tokens ->
	    handle_http_post(Socket, Request, Url, Tokens, Body, v1)
    end.

handle_http_post(Socket, Request, Url, Tokens, Body, v3) ->
    case Tokens of
	_Other ->
	    handle_http_post(Socket, Request, Url, Tokens, Body, v2)
    end;
handle_http_post(Socket, Request, Url, Tokens, Body, v2) ->
    Data = parse_body(Request,Body),
    
    case Tokens of
	_Other ->
	    handle_http_post(Socket, Request, Url, Tokens, Body, v1)
    end;
handle_http_post(Socket, Request, _Url, Tokens, Body, v1) ->
    Access = access(Socket),
    Data = parse_body(Request,Body),
    case Tokens of
	Tokens ->
	    ?log_debug("~p not found", [Tokens]),
	    response(Socket, Request, {error, not_found})
    end.
    
%%%-------------------------------------------------------------------
%%% Parsing
%%%-------------------------------------------------------------------
parse_filter(QueryString) ->
    case rester_http:parse_alt_query(QueryString) of
	{any,Ds} ->
	    {any, [ {all,[{Op,K,parse_filter_value(K,V)} ||
			     {Op,K,V} <- Cs]} ||
		      {all,Cs} <- Ds]};
	{all,Cs} ->
	    {all,[{Op,K,parse_filter_value(K,V)} || {Op,K,V} <- Cs]}
    end.

parse_filter_value(K,[V|Vs]) ->
    case V of
	"true" -> [true|parse_filter_value(K,Vs)];
	"false" -> [false|parse_filter_value(K,Vs)];
	_ when K =:= label ->
	    [V|parse_filter_value(K,Vs)];
	[C|_] when C >= $0, C =< $9 ->
	    if K =:= value;
	       K =:= 'channel-id' ->
		    try list_to_integer(V) of
			I -> [I|parse_filter_value(K,Vs)]
		    catch
			error:_ ->
			    [parse_filter_string(V)|parse_filter_value(K,Vs)]
		    end;
	       true ->
		    [parse_filter_string(V)|parse_filter_value(K,Vs)]
	    end;
	_ ->
	    [parse_filter_string(V)|parse_filter_value(K,Vs)]
    end;
parse_filter_value(_K,[]) ->
    [].

parse_filter_string(String) ->
    try erlang:list_to_existing_atom(String) of
	Atom -> Atom
    catch
	error:_ ->
	    String
    end.


parse_body(Request, Body) ->
    ?log_debug("body ~p", [Body]),
    case try_parse_body(Request, Body) of
	{ok, {struct, [{"data", Data}]}} -> parse_data(Data);
	{ok, {struct, List}} -> List;
	{ok, {array, List}} -> List;
	{ok, Data} ->  parse_data(Data);
	[{"data", Data}] -> parse_data(Data);
	[{Data, true}] -> parse_data(Data);  %% default is urlencoded
	List when is_list(List) -> List;
	Error -> Error
    end.
   
      
try_parse_body(Request, Body) ->
    try parse_data(Request, Body) of
	{error, _Reason} ->
	    ?log_warning("parse failed, reason ~p", [_Reason]),
	    {error, badarg};
	Result -> Result
    catch error:Reason -> {error, Reason}
    end.
    

parse_data(Request, Body) when is_binary(Body)->
    parse_data(Request, binary_to_list(Body));
parse_data(Request, Body) ->
    Type = (Request#http_request.headers)#http_chdr.content_type,
    ?log_debug("type ~p, body ~p", [Type, Body]),
    case Type of
	"*/*" -> %% Accept?
	    {ok,parse_data(Body)};
	"text/plain" ->
	    {ok,parse_data(Body)};
	"application/json" ->
	    parse_json_string(Body);
	"application/x-www-form-urlencoded" ->
	    rester_http:parse_query(Body);
	_Type ->
	    ?log_debug("type: ~p~n", [_Type]),
	    {error, "Unknown content type"}
    end.

parse_json_string(Data) ->
    try jsone:decode(iolist_to_binary(Data)) of
	Term -> {ok,Term}
    catch
	error:Reason ->
	    {error, Reason}
    end.

parse_data(I) when is_integer(I) -> 
    I;
parse_data(F) when is_float(F) -> 
    F;
parse_data(List) when is_list(List) -> 
    try list_to_integer(List) of
	I -> I
    catch _:_ ->
	    try list_to_float(List) of
		F -> F
	    catch _:_ ->
		    List
	    end
    end.


%--------------------------------------------------------------------
%% @doc
%% Subscribes to events and sends them on using http
%% @end
%%--------------------------------------------------------------------
event_channel(Access, Socket, Request, Filter, Version)
  when Access =:= local;
       Access =:= secure;
       Access =:= network ->
    ?log_debug("version ~p.",[Version]),
    ?log_debug("options ~p.",[Filter]),
    {ok, Id} = seaz_db_srv:subscribe(Filter),
    rester_http_server:response_r(Socket,Request,200,"OK","",
			       [{content_type,"application/json"},
				{transfer_encoding, "chunked"}]),
    rester_socket:setopts(Socket, [{active,once}]),
    SO = socket_options(),
    TimeOut = proplists:get_value(idle_timeout, SO, ?IDLE_TIMEOUT),
    Timer = inactivity_check(TimeOut),
    transfer_id(Id, Version),
    event_loop(Socket, Version, Timer, TimeOut, 0);
event_channel(_Access, Socket, Request, _Filter, _Version) ->
    response(Socket, Request, {error, no_access}).

event_loop(Socket, Version, Timer, TimeOut, SyncCounter) ->
    receive
	{Tag, _Port} when 
	      (Tag =:= tcp_closed orelse Tag =:= ssl_closed) ->
	    ?log_debug("got tcp/ssl close"),
	    stop;
	close -> %% From close_event_channel request
	    ?log_debug("got close"),
	    rester_http:send_chunk_end(Socket,""), %% Send trailer ??
	    stop;
	sync ->
	    event_loop(Socket, Version, Timer, TimeOut,
		       SyncCounter + 1);
	{timeout, Timer, inactivity_check} when SyncCounter =:= 0 ->
	    ?log_info("closing due to inactivity"),
	    close_event_channel(Socket, Version);
	{timeout, Timer, inactivity_check} when SyncCounter =/= 0 ->
	    NewTimer = inactivity_check(TimeOut),
	    event_loop(Socket, Version, NewTimer, TimeOut, 0);
	{timeout, _OtherTimer, inactivity_check} ->
	    ?log_warning("unknown timer ~p", [_OtherTimer]),
	    event_loop(Socket, Version, Timer, TimeOut,SyncCounter);
	{Tag, _Socket, Reason}
	  when Tag =:= tcp_error;
	       Tag =:= ssl_error ->
	    ?log_error("error = ~p, terminating", [Reason]),
	    stop;
	Event when is_list(Event) ->
	    ?log_debug("event ~p received", [Event]),
	    case rester_channel:transfer_event(Socket, Event, Version) of
		stop ->
		    stop;
		_ ->
		    event_loop(Socket, Version, Timer, TimeOut,
			       SyncCounter)
	    end;

	%% FIXME: maybe exit here if data is sent from client?
	_Other ->
	    ?log_warning("received unknown event ~p", [_Other]),
	    event_loop(Socket, Version, Timer, TimeOut, SyncCounter)
    end.

close_event_channel(Socket, Version) ->
    Event = [{'event-type', 'system-event'}, {group, system},
	     {'system-event', 'closed'}, {data, true}],
    rester_channel:transfer_event(Socket, Event, Version),
    rester_http:send_chunk_end(Socket,""), %% Send trailer ??
    stop.

inactivity_check(infinity) ->
    ?log_debug("no inactivity check"),
    undefined;
inactivity_check(TimeOut) when is_integer(TimeOut) ->
    erlang:start_timer(TimeOut, self(), inactivity_check);
inactivity_check(_Other) ->
    ?log_error("faulty timeout ~p, using default ~p", [?IDLE_TIMEOUT]),
    inactivity_check(?IDLE_TIMEOUT).

transfer_id(_Id, v1) ->
    ok;
transfer_id(Id, _Version) ->
    %% keep this order, szevt expect this. For now.
    %% AND do not reverse the list in transfer_event :-)
    Event = [{'event-type', 'system-event'},
	     {'system-event','channel-id'},
	     {group, system},
	     {data, Id}],
    self() ! Event. 

%%%-------------------------------------------------------------------
%% Check conditional headers
%%%-------------------------------------------------------------------
-spec header_match(H::#http_chdr{}, ETag::string(), Lmt::calendar:date_time())
		  -> true | precondition_failed | not_modified.

header_match(H, ETag, Lmt) ->
    case if_match(H#http_chdr.if_match,ETag) of
	true ->
	    case if_unmodified_since(H#http_chdr.if_unmodified_since, Lmt) of
		true ->
		    case if_none_match(H#http_chdr.if_none_match, ETag) of
			true ->
			    IfModifiedSince = H#http_chdr.if_modified_since,
			    case if_modified_since(IfModifiedSince, Lmt) of
				true -> true;
				Status -> Status
			    end;
			Status -> Status
		    end;
		Status -> Status
	    end;
	Status -> Status
    end.

if_match(undefined, _ETag) ->
    true;
if_match(IfMatch, ETag) ->
    case rester_http:scan_tokens(IfMatch) of
	["*"] -> true;
	Ts ->
	    case lists:member(ETag, Ts) of
		true ->  true;
		false -> precondition_failed
	    end
    end.

if_unmodified_since(undefined, _Lmt) ->
    true;
if_unmodified_since(IfUnModifiedSince, Lmt) ->
    try rester_http:parse_date(IfUnModifiedSince) of
	{DateTime,[]} ->
	    if Lmt > DateTime -> true;
	       true -> precondition_failed
	    end
    catch
	error:_ -> true
    end.

if_none_match(undefined, _ETag) ->
    true;
if_none_match(IfNoneMatch, ETag) ->
    case rester_http:scan_tokens(IfNoneMatch) of
	["*"] -> not_modified; %% GET/HEAD only!
	Ts ->
	    case lists:member(ETag, Ts) of
		false -> true;
		true -> not_modified
	    end
    end.

if_modified_since(undefined, _Lmt) ->
    true;
if_modified_since(IfModifiedSince, Lmt) ->
    try rester_http:parse_date(IfModifiedSince) of
	{DateTime,[]} ->
	    Now = calendar:universal_time(),
	    if DateTime > Now -> true;
	       Lmt > DateTime -> true;
	       true -> not_modified
	    end
    catch
	error:_ -> true
    end.


%%%-------------------------------------------------------------------
%%% General response function
%%%-------------------------------------------------------------------
response(Socket,Request,ok)  ->
    rester_http_server:response_r(Socket,Request,200,"OK","",[]);
response(Socket,Request,{ok, String}) 
  when is_list(String) ->
    rester_http_server:response_r(Socket,Request,200,"OK",String,[]);
response(Socket,Request,{ok, Atom}) 
  when is_atom(Atom) ->
    rester_http_server:response_r(Socket,Request,200,"OK",
			       atom_to_list(Atom),[]);
response(Socket,Request,{ok, Bin}) 
  when is_binary(Bin) ->
    rester_http_server:response_r(Socket,Request,200,"OK",
			       Bin,[]);
response(Socket,Request,{ok, String, json}) 
  when is_list(String) ->
    rester_http_server:response_r(Socket,Request,200,"OK",String,
			       [{content_type,"application/json"}]);
response(Socket,Request,{ok, String, html}) 
  when is_list(String) ->
    rester_http_server:response_r(Socket,Request,200,"OK",String,
			       [{content_type,"text/html"}]);
response(Socket,Request,{ok, {format, Args}}) 
  when is_list(Args) ->
    {ContentType,Reply} = format_reply(Args, Request),
    rester_http_server:response_r(Socket, Request, 200, "OK", Reply,
			       [{content_type,ContentType}]);

response(Socket,Request,{error, not_modified, ErrorMsg})  
  when is_list(ErrorMsg) ->
    rester_http_server:response_r(Socket,Request,304,"Not Modified", 
			       ErrorMsg,[]);
response(Socket,Request,{error, not_modified}) ->
    rester_http_server:response_r(Socket,Request,304,"Not Modified",
			       "Object not modified.",[]);
%% Client errors
response(Socket,Request,{error, bad_request, ErrorMsg}) 
  when is_list(ErrorMsg) ->
    rester_http_server:response_r(Socket,Request,400,"Bad Request",
			       ErrorMsg,[]);
response(Socket,Request,{error, badarg}) ->
    rester_http_server:response_r(Socket,Request,400,"Bad Request",
			       "Bad argument",[]);
response(Socket,Request,{error, badarg, ErrMsg}) ->
    rester_http_server:response_r(Socket,Request,400,"Bad Request",
			       ErrMsg,[]);
response(Socket,Request,{error, not_implemented}) ->
    rester_http_server:response_r(Socket,Request,400,"Bad Request",
			       "Not implemented",[]);
response(Socket,Request,{error, not_applicable}) ->
    rester_http_server:response_r(Socket,Request,400,"Bad Request",
			       "Not applicable",[]);
response(Socket,Request,{error, no_access}) ->
    rester_http_server:response_r(Socket,Request,403,"Access Not Allowed",
			       "Access Not Allowed.", []);
response(Socket,Request,{error, not_found}) ->
   rester_http_server:response_r(Socket,Request,404,"Not Found",
			      "Object not found.",[]);
response(Socket,Request,{error, enoent}) ->
   rester_http_server:response_r(Socket,Request,404,"Not Found",
			      "Object not found.",[]);
response(Socket,Request,{error, unknown_event}) ->
   rester_http_server:response_r(Socket,Request,404,"Not Found",
			      "Event not found.",[]);
response(Socket,Request,{error, not_allowed}) ->
    rester_http_server:response_r(Socket,Request,405,"Method Not Allowed",
			       "Method Not Allowed.",
			       [{<<"Allow">>, <<"GET,PUT,POST">>}]);
response(Socket,Request,{error, precondition_failed}) ->
    rester_http_server:response_r(Socket,Request,412,"Precondition Failed",
			       "Precondition Failed.",[]);

%% Application specific error codes
response(Socket,Request,{error, unknown})  ->
    rester_http_server:response_r(Socket,Request,534,"Data Missing","",[]);
response(Socket,Request,{error, sleep_not_allowed})  ->
    rester_http_server:response_r(Socket,Request,535,"Sleep not allowed","",[]);
%% Internal errors
response(Socket,Request,{error, internal_error, ErrorMsg}) 
  when is_list(ErrorMsg)->
    rester_http_server:response_r(Socket,Request,500,"Internal Server Error",
			       ErrorMsg,[]);
response(Socket,Request,{error, Reason, ErrorMsg})  
  when is_list(ErrorMsg) ->
    ?log_debug("can not handle error ~p:~p", [Reason, ErrorMsg]),
    rester_http_server:response_r(Socket,Request,500,"Internal Server Error",
			       ErrorMsg,[]);
response(Socket,Request,{error, Reason}) 
  when is_list(Reason)->
    rester_http_server:response_r(Socket,Request,500,"Internal Server Error",
			       Reason,[]);
response(Socket,Request,{error, Reason}) 
  when is_atom(Reason)->
    rester_http_server:response_r(Socket,Request,500,"Internal Server Error",
			       atom_to_list(Reason),[]);
response(Socket,Request,{error, Reason}) ->
    ?log_warning("can not handle error ~p", [Reason]),
    rester_http_server:response_r(Socket,Request,500,"Internal Server Error",
			       "",[]);
response(Socket,Request,{error, Reason, Format, Args}) 
  when is_list(Format), is_list(Args) ->
    ErrorMsg = io_lib:format(Format, Args),
    response(Socket,Request,{error, Reason, ErrorMsg});
response(Socket,Request,Other) ->
    ?log_warning("can not handle result ~p", [Other]),
    rester_http_server:response_r(Socket,Request,500,"Internal Server Error",
			       "",[]).

%%%-------------------------------------------------------------------

format_reply(Data,Request) ->
    case (Request#http_request.headers)#http_chdr.accept of
	"application/json" ->
	    {"application/json", format_reply_json(Data)};
	"text/plain" ->
	    {"text/plain", format_reply_text(Data)};
	"*/*" ->
	    {"application/json", format_reply_json(Data)}
    end.

%%%-------------------------------------------------------------------
-spec format_reply_json(Term::term()) ->
	  JsonReply::string().

format_reply_json(Term) ->
    jsone:encode(Term).

-spec format_reply_text(Term::term()) ->
	  TextReply::string().

format_reply_text(Data) when is_list(Data) ->
    Data1 = [{Key,lists:flatten(Value)} || {Key,Value} <- Data],
    io_lib:format("~p", [Data1]);
format_reply_text(Data) ->
    io_lib:format("~p", [Data]).

-spec access(Socket::#rester_socket{}) -> Access::access().

access(Socket) ->
    case rester_socket:is_ssl(Socket) of
	true ->
	    secure;
	false ->
	    %% xylan_port undefined -> no security
	    XylanPort = case application:get_env(rester, xylan_port) of
			    {ok,Xp} -> Xp;
			    undefined -> undefined
			end,
	    SockName = rester_socket:sockname(Socket),
	    ?log_debug("SockName ~p, xylan port ~p",[SockName, XylanPort]),
	    case SockName of
		{ok, XylanPort} -> remote;
		{ok, {{127,0,0,1}, _Port}} -> local;
		{ok, {_IP, _Port}} -> network; %% Allowed ??
		_O ->
		    ?log_warning("sockname ~p",[_O]),
		    unknown %% ???
	    end
    end.

index(Accept) ->
    index(Accept, ?LATEST_VSN).

-spec index(Accept::[string()],Vsn::atom()) ->
		   {ok, JsonString::string(), json} |
		   {ok, Html::string(), html} |
		   {error, Reason::atom(), ErrorMsg::string()} .

index(["text/html"|_Rest],Vsn) ->
    index_html(Vsn);
index(_Other,_Vsn) ->
    {error, bad_request, "Not implemented."}.

index_html(Vsn) ->
    html_doc(index_body(Vsn)).

index_body(Vsn) ->
    V = atom_to_list(Vsn),
    ["<body>",
     "<ul>",
     "<li><a href=\"/",V,"/settings\">Settings</a></li>",
     "<li><a href=\"/",V,"/status\">Status</a></li>",
     "<li><a href=\"/",V,"/public\">Public Keys</a></li>",
     "<li><a href=\"/",V,"/secret\">Secret Key</a></li>",
     "</ul>",
     "</body>"].

html_doc(Body) ->
    Html = ["<!DOCTYPE html>",
	    "<html>",
	    html_head(),
	    Body,
	    "</html>"],
    {ok, Html, html}.

html_head() ->
    ["<style>",
     "table, th, td {",
     "border: 1px solid black;",
     "border-collapse: collapse;"
     "}",
     "th, td {",
     "padding: 5px;",
     "}",
     "</style>"].

html_table(Table) ->
    ["<table border=\"1\", style=\"width:100%\"",
     html_th(),
     [html_tr(Row) || Row <- Table],
     "</table>"].

html_th() ->
    ["<th>",
     "<td>Key</td>",
     "<td>Value</td>",
     "</th>"].

html_tr({Key,Value}) ->
    ["<tr>",
     "<td>", value_to_string(Key), "</td>",
     "<td>", value_to_string(Value), "</td>",
     "</tr>"].

value_to_string(I) when is_integer(I) ->
    integer_to_list(I);
value_to_string(F) when is_float(F) ->
    io_lib_format:fwrite_g(F);
value_to_string(A) when is_atom(A) ->
    atom_to_list(A);
value_to_string([A]) when is_atom(A) ->
    atom_to_list(A);
value_to_string(P) when is_pid(P) ->
    pid_to_list(P);
value_to_string(P) when is_port(P) ->
    erlang:port_to_list(P);
value_to_string([Tuple]) when is_tuple(Tuple) ->
    %% last element in list
    value_to_string(Tuple);
value_to_string([Tuple | Rest]) when is_tuple(Tuple) ->
    value_to_string(Tuple) ++ ", " ++ value_to_string(Rest);
value_to_string({Condition, ConditionList} = _Filter)
  when (Condition =:= all orelse Condition =:= any) andalso
       is_list(ConditionList) ->
    ?log_debug("filter ~p",[_Filter]),
    atom_to_list(Condition) ++ ": " ++ value_to_string(ConditionList);
value_to_string({Key, Value}) ->
    value_to_string(Key) ++ ":" ++ value_to_string(Value);
value_to_string({Operator,Key,Value} = _Condition)
  when Operator =:= '=' ;
       Operator =:= '<=';
       Operator =:= '>=';
       Operator =:= '>' ;
       Operator =:= '<' ;
       Operator =:= '<>'->
    ?log_debug("condition ~p",[_Condition]),
    S = value_to_string(Key) ++ atom_to_list(Operator) ++
	value_to_string(Value),
    ?log_debug("to string ~p",[S]),
    S;
value_to_string({offset, _A, V}) ->
    value_to_string(V);
value_to_string({M,F,A}) when is_atom(M), is_atom(F), is_list(A) ->
    value_to_string({M,F}) ++ "(" ++ value_to_string(A) ++ ")";
value_to_string(T) when is_tuple(T) ->
    L = tuple_to_list(T),
    ?log_debug("tuple ~p to list ~p",[T,L]),
    lists:foldl(
      fun(X, []) -> value_to_string(X);
	 (X, Acc) -> Acc ++ ", " ++ value_to_string(X)
      end, [], L);
value_to_string([]) ->
    "";
value_to_string([S]) when is_list(S) ->
    S;
value_to_string(S) when is_list(S) ->
    S;
value_to_string(B) when is_binary(B) ->
    try binary:bin_to_list(B) of
	S -> S
    catch
       _:_ -> [B]
    end.
