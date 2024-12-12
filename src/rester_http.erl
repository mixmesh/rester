%%% @author Tony Rogvall <tony@rogvall.se>
%%% @copyright (C) 2020, Tony Rogvall
%%% @doc
%%%    http
%%% @end
%%% Created : 15 Oct 2020 by Tony Rogvall <tony@rogvall.se>

-module(rester_http).

-include("../include/rester.hrl").
-include("../include/rester_http.hrl").

%% simple client interface
-export([wget/1, wget/2, wget/3, wget/4]).
-export([wput/2, wput/3, wput/4, wput/5]).
-export([wpost/2, wpost/3, wpost/4, wpost/5, wpost_body/2]).
-export([wxget/3, wxget/4, wxget/5, wxget/6]).
-export([woptions/1, woptions/2, woptions/3, woptions/4]).

-export([wtrace/1, wtrace/2, wtrace/3, wtrace/4]).
-export([open/1, open/2, close/3]).
-export([request/2, request/3, request/4, request/5]).
-export([send/2, send/3, send/4, send/7,
	 send_body/2, send_chunk/2, send_chunk_end/2]).

%% message interface
-export([recv_response/1, recv_response/2,
	 recv_request/1, recv_request/2,
	 recv_body/2, recv_body/3, recv_body/5,
	 recv_body_eof/1,recv_body_eof/2,recv_body_eof/4,
	 recv_body_data/2,recv_body_data/3,recv_body_data/5,
	 recv_body_chunks/1,recv_body_chunks/2,recv_body_chunks/4,
	 recv_headers/2,
	 recv_headers/3
	]).

%% parse interface
-export([convert_uri/1]).
-export([tokens/1]).
-export([get_authenticate/1]).
-export([scan_tokens/1]).
-export([parse_date/1]).
-export([parse_accept/1]).
-export([accept_media/1]).

-export([set_chdr/3,
	 set_shdr/3]).

%% format interface
-export([format_response/1, format_response/3,
	 format_request/1, format_request/2, format_request/4,
	 format_query/1,
	 format_current_date/0,
	 format_timestamp/1,
	 format_date/1,
	 format_headers/1,
	 format_hdr/1,
	 fmt_chdr/1,
	 fmt_shdr/1,
	 make_request/4,
	 make_response/4,
	 auth_basic_encode/2,
	 url_encode/1,
	 make_headers/2,
	 make_basic_request/2,
	 make_digest_request/2
	]).

-export([url_decode/1,
	 parse_query/1]).
-export([parse_alt_query/1, parse_alt_seq/1, parse_alt_seq/2, parse_kv/1]).
-export([make_digest_response/3]).

-define(Q, $\").

-define(MAX_RAW_CHUNK_SIZE, 4096).

%%
%% Perform a HTTP/1.1 GET
%%
wget(Url) ->
    wget(Url,{1,1}, [], infinity).

wget(Url, Hs) ->
    wget(Url, {1,1}, Hs, infinity).

wget(Url, Version, Hs) ->
    wget(Url, Version, Hs, infinity).

wget(Url, Version, Hs, Timeout) ->
    Req = make_request('GET',Url,Version,Hs),
    request(Req,[],Timeout).

%% Proxy version
wxget(Proxy,Port,Url) ->
    wxget(Proxy,Port,Url,{1,1},[],infinity).

wxget(Proxy,Port,Url, Hs) ->
    wxget(Proxy,Port,Url, {1,1}, Hs,infinity).

wxget(Proxy,Port,Url, Version, Hs) ->
    wxget(Proxy,Port,Url, Version, Hs,infinity).

wxget(Proxy,Port,Url, Version, Hs,Timeout) ->
    Req = make_request('GET',Url,Version,Hs),
    xrequest(Proxy,Port,Req,[],Timeout).

%%
%% HTTP/1.1 OPTIONS
%%
woptions(Url) ->
    woptions(Url,{1,1},[],infinity).
woptions(Url, Hs) ->
    woptions(Url,{1,1},Hs,infinity).

woptions(Url, Version, Hs) ->
    woptions(Url, Version, Hs,infinity).

woptions(Url, Version, Hs, Timeout) ->
    Req = make_request('OPTIONS',Url,Version,Hs),
    request(Req,[],Timeout).

%%
%% HTTP/1.1 TRACE
%%
wtrace(Url) ->
    wtrace(Url,{1,1},[],infinity).

wtrace(Url, Hs) ->
    wtrace(Url,{1,1},Hs,infinity).

wtrace(Url, Version, Hs) ->
    wtrace(Url, Version, Hs, infinity).

wtrace(Url, Version, Hs,Timeout) ->
    Req = make_request('TRACE',Url,Version,Hs),
    request(Req,[],Timeout).

%%
%% HTTP/1.1 PUT
%% 1.  Content-type: application/x-www-form-urlencoded
%%       - Data = [{key,value}] => key=valye&...
%%       - Data = [{file,Name,FileName} | {binary,Name,<<bin>>} | <<bin>>
%%
%% 2.
%%     Content-type: multipart/form-data; boundary=XYZ
%%
%%     Content-type: multipart/<form>
%%
%%        - Data = [{file,ContentType,DispositionName,FileName}  |
%%                  {data,ContentType,DispositionName,<<bin>>} |
%%                  <<bin>>]
%%
%%
wput(Url,Data) ->
    wput(Url,{1,1},[],Data).

wput(Url,Hs,Data) ->
    wput(Url,{1,1},Hs,Data,infinity).

wput(Url,Version,Hs,Data) ->
    wput(Url,Version,Hs,Data,infinity).

wput(Url,Version,Hs,Data,Timeout) ->
    Req = make_request('PUT',Url,Version,Hs),
    {ok,Req1,Body} = wpost_body(Req, Data),
    request(Req1, Body, Timeout).


%%
%% HTTP/1.1 POST
%% 1.  Content-type: application/x-www-form-urlencoded
%%       - Data = [{key,value}] => key=valye&...
%%       - Data = [{file,Name,FileName} | {binary,Name,<<bin>>} | <<bin>>
%%
%% 2.
%%     Content-type: multipart/form-data; boundary=XYZ
%%
%%     Content-type: multipart/<form>
%%
%%        - Data = [{file,ContentType,DispositionName,FileName}  |
%%                  {data,ContentType,DispositionName,<<bin>>} |
%%                  <<bin>>]
%%
%%
wpost(Url,Data) ->
    wpost(Url,{1,1},[],Data).

wpost(Url,Hs,Data) ->
    wpost(Url,{1,1},Hs,Data,infinity).

wpost(Url,Version,Hs,Data) ->
    wpost(Url,Version,Hs,Data,infinity).

wpost(Url,Version,Hs,Data,Timeout) ->
    Req = make_request('POST',Url,Version,Hs),
    {ok,Req1,Body} = wpost_body(Req, Data),
    request(Req1, Body, Timeout).

wpost_body(Req, Data) ->
    Headers = Req#http_request.headers,
    case Headers#http_chdr.content_type of
	undefined ->
	    wpost_form_body(Req, Data);
	"application/json" ->
	    wpost_json_body(Req, Data);
	"application/x-www-form-urlencoded" ->
	    wpost_form_body(Req, Data);
	"multipart/"++_ ->
	    wpost_multi_body(Req, Data);
	_ ->
	    wpost_plain_body(Req, Data)
    end.

wpost_json_body(Req, Data) ->
    {ok,Req,json:encode(Data)}.

wpost_form_body(Req, Data) ->
    {ok,Req,format_query(Data)}.

wpost_multi_body(Req, Data) ->
    H = Req#http_request.headers,
    Ct0 = H#http_chdr.content_type,
    {Boundary,Req1} =
	case string:str(Ct0, "boundary=") of
	    0 ->
		<<Rnd64:64>> = crypto:strong_rand_bytes(8),
		Bnd = "------------------------"++
		    integer_to_list(Rnd64, 16),
		Ct1 = H#http_chdr.content_type ++
		    "; boundary=\""++Bnd ++"\"",
		H1 = set_chdr('Content-Type', Ct1, H),
		{Bnd, Req#http_request { headers = H1 }};
	    I ->
		Str = string:sub_string(Ct0, I, length(Ct0)),
		["boundary", QBnd | _] = string:tokens(Str, " ;="),
		{unquote(QBnd), Req}
	end,
    {ok,Req1,multi_data(Data, Boundary)}.


unquote([$" | Str]) ->
    case lists:reverse(Str) of
	[$" | RStr] -> lists:reverse(RStr);
	_ -> Str
    end;
unquote(Str) -> Str.


wpost_plain_body(Req, Data) ->
    Body = case Data of
	       Bin when is_binary(Bin) ->
		   Bin;
	       [{file,_,FileName}] ->
		   {ok,Bin} = file:read_file(FileName),
		   Bin;
	       [{file,_,_,FileName}] ->
		   {ok,Bin} = file:read_file(FileName),
		   Bin;
	       [{data,_,Bin}] ->
		   Bin;
	       [{data,_,_,Bin}] ->
		   Bin;
	       List when is_list(List) ->
		   list_to_binary(List)
	   end,
    {ok,Req,Body}.


multi_data(Data, Boundary) ->
    list_to_binary(
      [
     lists:map(
       fun(Bin) when is_binary(Bin) ->
	       [
		"--",Boundary,?CRNL,
		"Content-Type: text/plain",?CRNL,
		%% "Content-Transfer-Encoding: 8bit",?CRNL,
		?CRNL,
		Bin,
		?CRNL
	       ];
	  ({file,Name,ContentType,FileName}) ->
	       {ok,Bin} = file:read_file(FileName),
	       [
		"--",Boundary,?CRNL,
		"Content-Disposition: form-data",
		"; name=","\"", Name, "\"",
		"; filename=\"",filename:basename(FileName),"\"",?CRNL,
		"Content-Type: ",ContentType,?CRNL,
		%% "Content-Transfer-Encoding: 8bit",?CRNL,
		?CRNL,
		Bin,
		?CRNL
	       ];
	  ({data,Name,Value}) ->
	       [
		"--",Boundary,?CRNL,
		"Content-Disposition: form-data",
		"; name=\"",Name,"\"",?CRNL,
		?CRNL,
		Value,
		?CRNL
	       ];
	  ({data,Name,ContentType,Bin}) ->
	       [
		"--",Boundary,?CRNL,
		"Content-Disposition: form-data",
		"; name=\"",Name,"\"",?CRNL,
		"Content-Type: ",ContentType,?CRNL,
		%% "Content-Transfer-Encoding: 8bit",?CRNL,
		?CRNL,
		Bin,
		?CRNL
	       ]
       end, Data),
       "--",Boundary,"--",?CRNL]).

request(Req, Body) ->
    request(Req, Body,infinity).

request(Req, Body,Timeout) ->
    case open(Req,Timeout) of
	{ok, S} ->
	    case request(S, Req, Body, false, Timeout) of
		{ok,Resp,RespBody} ->
		    close(S,Req,Resp),
		    {ok,Resp,RespBody};
		Error ->
		    rester_socket:close(S),
		    Error
	    end;
	Error ->
	    Error
    end.


xrequest(Proxy,Port,Req,Body,Timeout) ->
    Proto = case Req#http_request.uri of
		#url { scheme = http } -> [tcp,http];
		#url { scheme = https } -> [tcp,ssl,http];
		_ -> [tcp,http]
	    end,
    case rester_socket_cache:open(Proto,Req#http_request.version,
			       Proxy,Port,Timeout) of
	{ok,S} ->
	    %% {nodelay,true}?
	    rester_socket:setopts(S, [{mode,binary},{packet,http}]),
	    case request(S, Req, Body, true, Timeout) of
		{ok,Resp,RespBody} ->
		    close(S,Req,Resp),
		    {ok,Resp,RespBody};
		_Error ->
		    rester_socket:close(S)
	    end;
	Error ->
	    Error
    end.

request(S, Req, Body, Proxy) ->
    request(S, Req, Body, Proxy, infinity).

request(S, Req, Body, Proxy, Timeout) ->
    case send(S, Req, Body, Proxy) of
	ok ->
	    %% FIXME: take care of POST 100-continue
	    case recv_response(S, Timeout) of
		{ok, Resp} ->
		    ?debug("response: ~p", [Resp]),
		    case recv_body(S, Resp, Timeout) of
			{ok,RespBody} ->
			    {ok,Resp,RespBody};
			Error ->
			    ?debug("body: ~p", [Error]),
			    Error
		    end;
		Error ->
		    ?debug("response: ~p", [Error]),
		    Error
	    end;
	Error -> Error
    end.

open(Request) ->
    open(Request,infinity).

open(Request,Timeout) ->
    URI = Request#http_request.uri,
    Url = if is_record(URI, url) -> URI;
	     is_list(URI) -> rester_url:parse(URI, sloppy)
	  end,
    Scheme = if Url#url.scheme =:= undefined -> http;
		true -> Url#url.scheme
	     end,
    Port = if Url#url.port =:= undefined ->
		   case Scheme of
		       http      -> 80;
		       https     -> 443;
		       ftp       -> 21
		   end;
	      true ->
		   Url#url.port
	   end,
    Proto = case Scheme of
		https -> [tcp,ssl,http];
		_ -> [tcp,http]
	    end,
    case rester_socket_cache:open(Proto,Request#http_request.version,
			       Url#url.host,Port,Timeout) of
	{ok,S} ->
	    rester_socket:setopts(S, [{mode,binary},{packet,http}]),
	    {ok,S};
	Error ->
	    ?debug("open failed, reason ~p",[Error]),
	    Error
    end.

close(S, Req, Resp) ->
    case do_close(Req,Resp) of
	true ->
	    ?debug("real close",[]),
	    rester_socket:close(S);
	false ->
	    ?debug("session close",[]),
	    rester_socket_cache:close(S)
    end.

do_close(Req, Res) ->
    _ReqH = Req#http_request.headers,
    ResH = Res#http_response.headers,
    case tokens(ResH#http_shdr.connection) of
	["close"] -> true;
	["keep-alive"] ->
	    %% Check {1,0} and keep-alive requested
	    false;
	_ ->
	    case Req#http_request.version of
		{1,1} -> false;
		_ -> true
	    end
    end.

%%
%% Send the HTTP request on a open connection
%%
send(Socket, Request) ->
    send(Socket, Request, false).

send(Socket, Request, Proxy) ->
    send(Socket, Request, [], Proxy).

send(Socket, Request, Body, Proxy) ->
    send(Socket,
	 Request#http_request.method,
	 Request#http_request.uri,
	 Request#http_request.version,
	 Request#http_request.headers,
	 Body, Proxy).

send(Socket, Method, URI, Version, H, Body, Proxy) ->
    Url = if is_record(URI, url) -> URI;
	     is_list(URI) -> rester_url:parse(URI, sloppy)
	  end,
    H1 =
	if H#http_chdr.host =:= undefined ->
		H#http_chdr { host = Url#url.host };
	   true ->
		H
	end,
    H2 = if is_binary(Body), size(Body) > 0,
	    H1#http_chdr.content_length =:= undefined ->
		 H1#http_chdr { content_length = size(Body) };
	    is_list(Body), Body =/= [],
	    H1#http_chdr.content_length =:= undefined ->
		 H1#http_chdr { content_length = lists:flatlength(Body) };
	    true ->
		 H1
	 end,
    H3 = if Version =:= {1,0},
	    H1#http_chdr.connection =:= undefined ->
		 H2#http_chdr { connection = "keep-alive" };
	    true ->
		 H2
	 end,
    Request = [format_request(Method,Url,Version,Proxy),?CRNL,
	       format_hdr(H3),?CRNL, Body],
    ?debug("> ~s", [Request]),
    %% io:format(">>> ~s", [Request]),
    rester_socket:send(Socket, Request).

%%
%% Send "extra" body data not sent in the original send
%%
send_body(Socket, Body) ->
    rester_socket:send(Socket, Body).

%%
%% Send chunks
%%
send_chunk(Socket, Chunk) when is_binary(Chunk) ->
    Sz = size(Chunk),
    if Sz > 0 ->
	    ChunkSize = erlang:integer_to_list(Sz,16),
	    ChunkExt = "",
	    rester_socket:send(Socket, [ChunkSize,ChunkExt,?CRNL,Chunk,?CRNL]);
       Sz =:= 0 ->
	    ok
    end.

send_chunk_end(Socket, _Trailer) ->
    ChunkSize = "0",
    ChunkExt = "",
    rester_socket:send(Socket, [ChunkSize, ChunkExt, ?CRNL,
			     %% Trailer is put here
			     ?CRNL]).

%%
%% Receive a http/https request
%%
recv_request(S) ->
    recv_request(S, infinity).

recv_request(S, Timeout) ->
    case rester_socket:recv(S, 0, Timeout) of
	{ok, {http_request, Method, Uri, Version}} ->
	    CUri = convert_uri(Uri),
	    recv_headers(S, #http_request { method = Method,
					    uri    = CUri,
					    version = Version });
	{ok, Data} ->
	    io:format("Request data: ~p", [Data]),
	    {error, sync_error };
	{error, {http_error, ?CRNL}} -> recv_request(S);
	{error, {http_error, ?NL}} -> recv_request(S);
	Error ->
	    Error
    end.

%%
%% Receive a http/https response
%%
recv_response(S) ->
    recv_response(S, infinity).

recv_response(S,Timeout) ->
    case rester_socket:recv(S, 0, Timeout) of
	{ok, {http_response, Version, Status, Phrase}} ->
	    recv_headers(S, #http_response { version = Version,
					      status = Status,
					      phrase = Phrase },Timeout);
	{ok, _} ->
	    {error, sync_error };
	{error, {http_error, ?CRNL}} -> recv_response(S,Timeout);
	{error, {http_error, ?NL}} -> recv_response(S,Timeout);
	Error ->
	    Error
    end.

%%
%% Receive a body for a request or a response
%%
recv_body(S, R) ->
    recv_body(S, R, infinity).

recv_body(S, R, Timeout) ->
    case recv_body(S, R,
		   fun (Data, Acc) -> [Data|Acc] end,
		   [], Timeout) of
	{ok, Chunks} ->
	    {ok, reversed_chunks_to_binary(Chunks)};
	Error ->
	    Error
    end.

recv_body(S, Request, Fun, Acc, Timeout)
  when is_record(Request, http_request) ->
    Method = Request#http_request.method,
    if Method =:= 'POST';
       Method =:= 'PUT' ->
	    H = Request#http_request.headers,
	    case Request#http_request.version of
		{0,9} ->
		    recv_body_eof(S, Fun, Acc, Timeout);
		{1,0} ->
		    case H#http_chdr.content_length of
			undefined -> recv_body_eof(S,Fun,Acc,Timeout);
			Len -> recv_body_data(S,list_to_integer(Len),Fun,Acc,
					      Timeout)
		    end;
		{1,1} ->
                    case H#http_chdr.content_type of
                        "multipart/form-data; boundary=" ++ Boundary ->
                            recv_multipart_form_data(
                              S, Timeout, list_to_binary(Boundary));
                        _ ->
                            case H#http_chdr.content_length of
                                undefined ->
                                    case H#http_chdr.transfer_encoding of
                                        undefined ->
                                            recv_body_eof(S, Fun, Acc, Timeout);
                                        "chunked" ->
                                            recv_body_chunks(
                                              S, Fun, Acc, Timeout)
                                    end;
                                Len ->
                                    recv_body_data(
                                      S, list_to_integer(Len), Fun, Acc,
                                      Timeout)
                            end
                    end
	    end;
       %% FIXME: handle GET/XXX with body
       true ->
	    {ok, <<>>}
    end;
recv_body(S, Response, Fun, Acc, Timeout)
  when is_record(Response, http_response) ->
    %% version 0.9  => read until eof
    %% version 1.0  => read either Content-Length or until eof
    %% version 1.1  => read Content-Length or Chunked or eof
    H = Response#http_response.headers,
    case Response#http_response.version of
	{0,9} ->
	    recv_body_eof(S,Fun,Acc,Timeout);
	{1,0} ->
	    case H#http_shdr.content_length of
		undefined -> recv_body_eof(S,Fun,Acc,Timeout);
		Len -> recv_body_data(S,list_to_integer(Len),Fun,Acc,Timeout)
	    end;
	{1,1} ->
	    case H#http_shdr.content_length of
		undefined ->
		    case H#http_shdr.transfer_encoding of
			undefined ->
			    recv_body_eof(S,Fun,Acc,Timeout);
			"chunked" ->
			    recv_body_chunks(S,Fun,Acc,Timeout)
		    end;
		Len ->
		    recv_body_data(S,list_to_integer(Len),Fun,Acc,Timeout)
	    end
    end.

recv_body_eof(Socket) ->
    recv_body_eof(Socket,infinity).

recv_body_eof(Socket,Timeout) ->
    case recv_body_eof(Socket,
		       fun(Data,Acc) -> [Data|Acc] end,
		       [], Timeout) of
	{ok, Chunks} ->
	    {ok,reversed_chunks_to_binary(Chunks)};
	Error ->
	    Error
    end.

recv_body_eof(Socket,Fun,Acc,Timeout) ->
    ?debug("RECV_BODY_EOF: tmo=~w", [Timeout]),
    rester_socket:setopts(Socket, [{packet,raw},{mode,binary}]),
    recv_body_eof_(Socket,Fun,Acc,Timeout).

recv_body_eof_(Socket,Fun,Acc,Timeout) ->
    case rester_socket:recv(Socket, 0, Timeout) of
	{ok, Bin} ->
	    Acc1 = Fun(Bin, Acc),
	    recv_body_eof_(Socket,Fun,Acc1,Timeout);
	{error, closed} ->
	    {ok, Acc};
	Error ->
	    Error
    end.

recv_body_data(Socket, Len) ->
    recv_body_data(Socket, Len, infinity).

recv_body_data(Socket, Len, Timeout) ->
    case recv_body_data(Socket, Len,
			fun(Data,Acc) -> [Data|Acc] end,
			[], Timeout) of
	{ok, Chunks} ->
	    {ok,reversed_chunks_to_binary(Chunks)};
	Error ->
	    Error
    end.

%% read determined Content-Length content in chunks of ?MAX_RAW_CHUNK_SIZE
recv_body_data(_Socket, 0, _Fun, Acc, _Timeout) ->
    ?debug("RECV_BODY_DATA: len=0, tmo=~w", [_Timeout]),
    {ok, Acc};
recv_body_data(Socket, Len, Fun, Acc, Timeout) ->
    ?debug("RECV_BODY_DATA: len=~p, tmo=~w", [Len,Timeout]),
    rester_socket:setopts(Socket, [{packet,raw},{mode,binary}]),
    recv_body_data_(Socket, Len, Fun, Acc, Timeout).

recv_body_data_(Socket, 0, _Fun, Acc, _Timeout) ->
    rester_socket:setopts(Socket, [{packet,http}]),
    {ok, Acc};
recv_body_data_(Socket, Len, Fun, Acc, Timeout) ->
    Len1 = min(Len, ?MAX_RAW_CHUNK_SIZE),
    case rester_socket:recv(Socket, Len1, Timeout) of
	{ok, Bin} ->
	    Acc1 = Fun(Bin, Acc),
	    recv_body_data_(Socket, Len-Len1, Fun, Acc1, Timeout);
	Error ->
	    Error
    end.


recv_body_chunks(Socket) ->
    recv_body_chunks(Socket, infinity).

recv_body_chunks(Socket, Timeout) ->
    case recv_body_chunks(Socket,
			  fun(Chunk,Acc) -> [Chunk|Acc] end,
			  [], Timeout) of
	{ok, Chunks} ->
	    {ok, reversed_chunks_to_binary(Chunks)};
	Error ->
	    Error
    end.

recv_body_chunks(Socket, Fun, Acc, Timeout) ->
    rester_socket:setopts(Socket, [{packet,line},{mode,list}]),
    ?debug("RECV_BODY_CHUNKS: tmo=~w", [Timeout]),
    recv_body_chunk(Socket, Fun, Acc, Timeout).

recv_body_chunk(S, Fun, Acc, Timeout) ->
    case rester_socket:recv(S, 0, Timeout) of
	{ok,Line} ->
	    ?debug("CHUNK-Line: ~p", [Line]),
	    {ChunkSize,_Ext} = chunk_size(Line),
	    ?debug("CHUNK: ~w", [ChunkSize]),
	    if ChunkSize =:= 0 ->
		    rester_socket:setopts(S, [{packet,httph}]),
		    case recv_chunk_trailer(S, [], Timeout) of
			{ok,_TR} ->
			    ?debug("CHUNK TRAILER: ~p", [_TR]),
			    rester_socket:setopts(S, [{packet,http},
						   {mode,binary}]),
			    {ok,Acc};
			Error ->
			    Error
		    end;
	       ChunkSize > 0 ->
		    rester_socket:setopts(S, [{packet,raw},{mode,binary}]),
		    case rester_socket:recv(S, ChunkSize, Timeout) of
			{ok,Bin} ->
			    rester_socket:setopts(S, [{packet,line},{mode,list}]),
			    case rester_socket:recv(S, 0, Timeout) of
				{ok, ?NL} ->
				    Acc1 = Fun(Bin,Acc),
				    recv_body_chunk(S,Fun,Acc1,Timeout);
				{ok, ?CRNL} ->
				    Acc1 = Fun(Bin,Acc),
				    recv_body_chunk(S,Fun,Acc1,Timeout);
				{ok, _Data} ->
				    ?debug("out of sync ~p", [_Data]),
				    {error, sync_error};
				Error ->
				    Error
			    end;
			Error ->
			    Error
		    end
	    end;
	Error ->
	    Error
    end.

recv_chunk_trailer(S, Acc, Timeout) ->
    case rester_socket:recv(S, 0, Timeout) of
	{ok,{http_header,_,K,_,V}} ->
	    recv_chunk_trailer(S,[{K,V}|Acc],Timeout);
	{ok,http_eoh} ->
	    {ok, lists:reverse(Acc)};
	Error ->
	    Error
    end.

reversed_chunks_to_binary(Bin) when is_binary(Bin) -> Bin;
reversed_chunks_to_binary([Bin]) when is_binary(Bin) -> Bin;
reversed_chunks_to_binary(Chunks) ->
    iolist_to_binary(lists:reverse(Chunks)).


%% See: https://tools.ietf.org/html/rfc7578

%% "-----------------------------153796634513348781802793578094\r\nContent-Disposition: form-data; name=\"files[]\"; filename=\"FOO.txt\"\r\nContent-Type: text/plain\r\n\r\nBAR\n\r\n-----------------------------153796634513348781802793578094--\r\n"

recv_multipart_form_data(Socket, Timeout, Boundary)->
    rester_socket:setopts(Socket, [{packet, raw}, {mode, binary}]),
    Separator = list_to_binary([<<"--">>, Boundary, <<"\r\n">>]),
    EndSeparator = list_to_binary([<<"--">>, Boundary, <<"--\r\n">>]),
    recv_multipart_form_data(Socket, Timeout, Separator, EndSeparator, <<>>, []).

recv_multipart_form_data(
  Socket, Timeout, Separator, EndSeparator, Buffer, Acc) ->
    SeparatorSize = size(Separator),
    BufferSize = size(Buffer),
    case binary:split(Buffer, Separator) of
        [<<>>, RemainingBuffer] ->
            case recv_multipart_headers(Socket, Timeout, RemainingBuffer, []) of
                {ok, Headers, StillRemainingBuffer} ->
                    case lists:keysearch(<<"Content-Type">>, 1, Headers) of
                        {value, {_, <<"application/octet-stream">>}} ->
                            Filename =
                                filename:join(
                                  ["/tmp", "form-data-" ++
                                       integer_to_list(
                                         erlang:unique_integer([positive]))]),
                            {ok, File} = file:open(Filename, [write, binary]),
                            case recv_multipart_body(
                                   Socket, Timeout, Separator, EndSeparator,
                                   StillRemainingBuffer, File) of
                                {separator, TrailingBuffer} ->
                                    file:close(File),
                                    recv_multipart_form_data(
                                      Socket, Timeout, Separator, EndSeparator,
                                      TrailingBuffer, [{file, Headers, Filename}|Acc]);
                                end_separator ->
                                    file:close(File),
                                    rester_socket:setopts(
                                      Socket, [{packet, http}, {mode, binary}]),
                                    {ok, {multipart_form_data,
                                          [{file, Headers, Filename}|Acc]}};
                                {error, Reason} ->
                                    file:close(File),
                                    rester_socket:close(Socket),
                                    {error, {bad_body, Reason}}
                            end;
                        false ->
                            case recv_multipart_body_data(
                                   Socket, Timeout, Separator, EndSeparator,
                                   StillRemainingBuffer) of
                                {separator, Data, TrailingBuffer} ->
                                    recv_multipart_form_data(
                                      Socket, Timeout, Separator, EndSeparator,
                                      TrailingBuffer, [{data, Headers, Data}|Acc]);
                                {end_separator, Data} ->
                                    rester_socket:setopts(
                                      Socket, [{packet, http}, {mode, binary}]),
                                    {ok, {multipart_form_data,
                                          [{data, Headers, Data}|Acc]}};
                                {error, Reason} ->
                                    rester_socket:close(Socket),
                                    {error, {bad_body, Reason}}
                            end
                    end;
                {error, Reason} ->
                    {error, {bad_header, Reason}}
            end;
        [_] when BufferSize < SeparatorSize ->
            case rester_socket:recv(Socket, 0, Timeout) of
                {ok, Data} ->
                    NewBuffer = list_to_binary([Buffer, Data]),
                    recv_multipart_form_data(
                      Socket, Timeout, Separator, EndSeparator, NewBuffer, Acc);
                {error, Reason} ->
                    {error, Reason}
            end;
        [_] ->
            {error, bad_format}
    end.

%% "-----------------------------153796634513348781802793578094\r\nContent-Disposition: form-data; name=\"files[]\"; filename=\"FOO.txt\"\r\nContent-Type: text/plain\r\n\r\nBAR\n\r\n-----------------------------153796634513348781802793578094--\r\n"

recv_multipart_headers(
  _Socket, _Timeout, <<"\r\n", RemainingBuffer/binary>>, Headers) ->
    {ok, Headers, RemainingBuffer};
recv_multipart_headers(Socket, Timeout, Buffer, Headers) ->
    case binary:split(Buffer, <<"\r\n">>) of
        [Header, RemainingBuffer] ->
            case binary:split(Header, <<": ">>) of
                [Name, Value] ->
                    recv_multipart_headers(
                      Socket, Timeout, RemainingBuffer, [{Name, Value}|Headers]);
                _ ->
                    {error, invalid_name_value}
            end;
        _ ->
            case rester_socket:recv(Socket, 0, Timeout) of
                {ok, Data} ->
                    NewBuffer = list_to_binary([Buffer, Data]),
                    recv_multipart_headers(Socket, Timeout, NewBuffer, Headers);
                {error, Reason} ->
                    {error, Reason}
            end
    end.

%% "-----------------------------153796634513348781802793578094\r\nContent-Disposition: form-data; name=\"files[]\"; filename=\"FOO.txt\"\r\nContent-Type: text/plain\r\n\r\nBAR\n\r\n-----------------------------153796634513348781802793578094--\r\n"

recv_multipart_body(Socket, Timeout, Separator, EndSeparator, Buffer, File) ->
    case binary:split(Buffer, Separator) of
        [Data, RemainingBuffer] ->
            file:write(File, Data),
            {separator, list_to_binary([Separator, RemainingBuffer])};
        [_] ->
            case binary:split(Buffer, EndSeparator) of
                [Data, <<>>] ->
                    file:write(File, Data),
                    end_separator;
                [_] ->
                    case rester_socket:recv(Socket, 0, Timeout) of
                        {ok, Data} ->
                            NewBuffer = list_to_binary([Buffer, Data]),
                            recv_multipart_body(
                              Socket, Timeout, Separator, EndSeparator,
                              NewBuffer, File);
                        {error, Reason} ->
                            {error, Reason}
                    end
            end
    end.

recv_multipart_body_data(Socket, Timeout, Separator, EndSeparator, Buffer) ->
    case binary:split(Buffer, Separator) of
        [Data, RemainingBuffer] ->
            {separator, Data, list_to_binary([Separator, RemainingBuffer])};
        [_] ->
            case binary:split(Buffer, EndSeparator) of
                [Data, <<>>] ->
                    {end_separator, Data};
                [_] ->
                    case rester_socket:recv(Socket, 0, Timeout) of
                        {ok, Data} ->
                            NewBuffer = list_to_binary([Buffer, Data]),
                            recv_multipart_body_data(
                              Socket, Timeout, Separator, EndSeparator,
                              NewBuffer);
                        {error, Reason} ->
                            {error, Reason}
                    end
            end
    end.

recv_headers(S, R) ->
    recv_headers(S, R, infinity).

recv_headers(S, R, Timeout) ->
    if is_record(R, http_request) ->
	    recv_hc(S, R, #http_chdr { },Timeout);
       is_record(R, http_response) ->
	    recv_hs(S, R, #http_shdr { },Timeout)
    end.

recv_hc(S, R, H, Timeout) ->
    case rester_socket:recv(S, 0, Timeout) of
	{ok, Hdr} ->
	    case Hdr of
		http_eoh ->
		    ?debug("EOH <", []),
		    Other = lists:reverse(H#http_chdr.other),
		    H1 = H#http_chdr { other = Other },
		    R1 = R#http_request { headers = H1 },
		    ?debug("< ~s~s", [format_request(R1,true),
				      format_headers(fmt_chdr(H1))]),
		    {ok, R1};
		{http_header,_,K,_,V} ->
		    ?debug("HEADER < ~p ~p", [K, V]),
		    recv_hc(S,R,set_chdr(K,V,H), Timeout);
		Got ->
		    ?debug("HEADER ERROR ~p", [Got]),
		    {error, Got}
	    end;
	{error, {http_error, ?CRNL}} ->
	    ?debug("ERROR CRNL <", []),
	    recv_hc(S, R, H,Timeout);
	{error, {http_error, ?NL}} ->
	    ?debug("ERROR NL <", []),
	    recv_hc(S, R, H,Timeout);
	Error ->
	    ?debug("RECV ERROR ~p <", [Error]),
	    Error
    end.

recv_hs(S, R, H, Timeout) ->
    case rester_socket:recv(S, 0, Timeout) of
	{ok, Hdr} ->
	    case Hdr of
		http_eoh ->
		    ?debug("EOH <", []),
		    Other = lists:reverse(H#http_shdr.other),
		    H1 = H#http_shdr { other = Other },
		    R1 = R#http_response { headers = H1 },
		    ?debug("< ~s~s", [format_response(R1),
				      format_hdr(H1)]),
		    {ok, R1};
		{http_header,_,K,_,V} ->
		    ?debug("HEADER < ~p ~p", [K, V]),
		    recv_hs(S,R,set_shdr(K,V,H),Timeout);
		Got ->
		    {error, Got}
	    end;
	{error, {http_error, ?CRNL}} ->
	    ?debug("ERROR CRNL <", []),
	    recv_hs(S, R, H,Timeout);
	{error, {http_error, ?NL}} ->
	    ?debug("ERROR NL <", []),
	    recv_hs(S, R, H, Timeout);
	Error -> Error
    end.

make_request(Method, Url, Version, Hs) ->
    U = rester_url:parse(Url, sloppy),
    #http_request { method = Method,
		    uri = U,
		    version = Version,
		    headers = mk_chdr(Hs) }.

make_response(Version, Status, Phrase, Hs) ->
    #http_response { version = Version,
		     status = Status,
		     phrase = Phrase,
		     headers = mk_shdr(Hs)}.

%%
%% Format http_request
%%
format_request(R) ->
    format_request(R, false).

format_request(R, Proxy) ->
    format_request(R#http_request.method,
		   R#http_request.uri,
		   R#http_request.version,
		   Proxy).

format_request(Method, Url, Version, Proxy) ->
    [if is_atom(Method) -> atom_to_list(Method);
	is_list(Method) -> Method
     end,
     " ",
     if is_record(Url, url) ->
	     if Proxy =:= true ->
		     rester_url:format(Url);
		true ->
		     rester_url:format_path(Url)
	     end;
	is_list(Url) -> Url
     end,
     case Version of
	 {0,9} ->  "";
	 {1,0} ->  " HTTP/1.0";
	 {1,1}  -> " HTTP/1.1"
     end].

format_response(R) ->
    format_response(R#http_response.version,
		    R#http_response.status,
		    R#http_response.phrase).

format_response({0,9}, _Status, _Phrase) -> "";
format_response(Version, Status, Phrase) ->
    [case Version of
	{1,0} ->  "HTTP/1.0";
	{1,1}  -> "HTTP/1.1"
     end,
     " ", integer_to_list(Status),
     case Phrase of
	 "" -> "";
	 _ -> [$\s|Phrase]
     end
    ].

format_query([Item]) ->
    case Item of
	{Key,Value} ->
	    [url_encode(to_list(Key)),"=",url_encode(to_list(Value))];
	Key ->
	    url_encode(to_list(Key))
    end;
format_query([Item|Vs]) ->
    case Item of
	{Key,Value} ->
	    [url_encode(to_list(Key)),"=",url_encode(to_list(Value)),"&" |
	     format_query(Vs)];
	Key ->
	    [url_encode(to_list(Key)), "&" |
	     format_query(Vs)]
    end;
format_query([]) ->
    [].

parse_query(Cs) ->
    parse_seq(Cs).

parse_seq(Cs) ->
    [case string:tokens(Kv,"=") of
	 [Key0,Value0] ->
	     Key1 = url_decode(Key0),
	     Value1 = url_decode(Value0),
	     try list_to_integer(trim(Value1)) of
		 Value -> {Key1, Value}
	     catch
		 error:_ -> {Key1, Value1}
	     end;
	 [Key0] ->
	     {url_decode(Key0),true}
     end || Kv <- string:tokens(Cs, "&")].

%% query with alternative forms
%% k1=v1&k2=v2;k1=v3;k3=v2  == ((k1=v1) AND (k2=v2)) OR (k1=v3) OR (k3=v2)
parse_alt_query(Cs) ->
    case string:tokens(Cs,";") of  %% run disjunction
	[] ->
	    {all,[]};
	[Q] ->
	    {all,parse_alt_seq(Q)};
	Qs ->
	    {any,[{all,parse_alt_seq(Q)} || Q <- Qs]}
    end.

%% allow k<v,k<=v,k=v,k>v,k>=,k<>v (with or without url encoding)
parse_alt_seq(Cs) ->
    [parse_kv(Kv) || Kv <- string:tokens(Cs, "&")].
parse_alt_seq(Cs, Separator) ->
    [parse_kv(Kv) || Kv <- string:tokens(Cs, Separator)].

parse_kv(Cs) ->
    parse_kv(Cs,[]).

parse_kv([$<,$=|Cs], Ks)   -> {'<=', make_rkey(Ks), make_val(Cs)};
parse_kv([$<,$>|Cs], Ks)   -> {'<>', make_rkey(Ks), make_val(Cs)};
parse_kv([$<,$%,C1,C2|Cs], Ks) ->
    parse_kv([$<,list_to_integer([C1,C2], 16)|Cs],Ks);
parse_kv([$<|Cs], Ks)      -> {'<', make_rkey(Ks), make_val(Cs)};
parse_kv([$>,$=|Cs], Ks)   -> {'>=', make_rkey(Ks), make_val(Cs)};
parse_kv([$>,$%,C1,C2|Cs], Ks) ->
    parse_kv([$>,list_to_integer([C1,C2], 16)|Cs], Ks);
parse_kv([$>|Cs], Ks)      -> {'>', make_rkey(Ks), make_val(Cs)};
parse_kv([$=|Cs], Ks)      -> {'=', make_rkey(Ks), make_val(Cs)};
parse_kv([$%,C1,C2|Cs],Ks) -> parse_kv([list_to_integer([C1,C2], 16)|Cs], Ks);
parse_kv([$+|Cs],Ks) -> parse_kv([$\s|Cs], Ks);
parse_kv([C|Cs],Ks) -> parse_kv(Cs,[C|Ks]);
parse_kv([],Ks) -> {'=',make_rkey(Ks),["true"]}.

make_rkey(Ks) ->
    list_to_atom(lists:reverse(Ks)).

make_val(Cs) ->
    [trim(P) || P <- string:tokens(url_decode(Cs),",")].

%% scan (comma) separated value  "*", "abcd" [, "fghi"]*
%% FIXME , must be able to handle empty values
scan_tokens(undefined) ->
    undefined;
scan_tokens(Cs) ->
    scan_tokens(Cs,[]).

scan_tokens([$\s|Cs],Acc) -> scan_tokens(Cs,Acc);
scan_tokens([$\t|Cs],Acc) -> scan_tokens(Cs,Acc);
scan_tokens([$,|Cs],Acc) -> scan_tokens(Cs,Acc);
scan_tokens([$"|Cs],Acc) -> scan_string(Cs,[],Acc);
scan_tokens([C|Cs],Acc) -> scan_token(Cs,[C],Acc);
scan_tokens([],Acc) -> lists:reverse(Acc).

scan_string([$"|Cs],Ds,Acc) -> scan_tokens(Cs, [lists:reverse(Ds) | Acc]);
scan_string([C|Cs],Ds,Acc) -> scan_string(Cs,[C|Ds],Acc);
scan_string([],Ds,Acc) -> scan_tokens([], [lists:reverse(Ds) | Acc]).

scan_token([$\s|Cs],Ds,Acc) -> scan_tokens(Cs,[lists:reverse(Ds)|Acc]);
scan_token([$\t|Cs],Ds,Acc) -> scan_tokens(Cs,[lists:reverse(Ds)|Acc]);
scan_token([$,|Cs],Ds,Acc) -> scan_tokens(Cs,[lists:reverse(Ds)|Acc]);
scan_token([C|Cs],Ds,Acc) -> scan_token(Cs,[C|Ds],Acc);
scan_token([],Ds,Acc) -> scan_tokens([],[lists:reverse(Ds)|Acc]).

trim(Cs) ->
    lists:reverse(trim_(lists:reverse(trim_(Cs)))).

trim_([$\s|Cs]) -> trim_(Cs);
trim_([$\t|Cs]) -> trim_(Cs);
trim_(Cs) -> Cs.

%%
%% Return Accept q-sorted list given a http request
%%
-spec accept_media(#http_request{}) -> [MediaType::string()].

accept_media(Request) ->
    Accept = (Request#http_request.headers)#http_chdr.accept,
    ?debug("accept ~p", [Accept]),
    parse_accept(Accept).

%% fixme: parse and return other media paramters, do proper handling of q
parse_accept(undefined) ->
    [];
parse_accept(String) ->
    parse_accept(scan_accept(String), []).

parse_accept([ [Media] | Types ], Acc) ->
    parse_accept(Types, [{Media, 1.0} | Acc]);
parse_accept([ [Media,"q="++QVal|_] | Types], Acc) ->
    try to_number(QVal) of
	Q -> parse_accept(Types, [{Media, Q} | Acc])
    catch
	error:_ ->
	    ?error("bad q value ~p", [QVal]),
	    parse_accept(Types, [{Media, 0.0} | Acc])
    end;
parse_accept([ [Media|_] | Types], Acc) -> %% fixme
    parse_accept(Types, [{Media, 1.0} | Acc]);
parse_accept([], Acc) ->
    [M || {M,_} <- lists:reverse(lists:keysort(2, Acc))].

scan_accept(String) ->
    [[trim(Item) || Item <- string:tokens(MediaRange,";")] || MediaRange <- string:tokens(String, ",")].

to_number(String) ->
    try list_to_float(String) of
	F -> F
    catch
	error:_ ->
	    list_to_integer(String)
    end.

%%
%% Encode basic authorization
%%
auth_basic_encode(User,undefined) ->
    base64:encode_to_string(to_list(User)++":");
auth_basic_encode(User,Pass) ->
    base64:encode_to_string(to_list(User)++":"++to_list(Pass)).

make_headers(User, Pass) ->  %% bad name should go
    make_basic_request(User, Pass).

make_basic_request(undefined, _Pass) -> [];
make_basic_request(User, Pass) ->
    [{"Authorization", "Basic "++auth_basic_encode(User, Pass)}].

make_digest_request(undefined, _Params) -> [];
make_digest_request(User, Params) ->
    [{"Authorization", "Digest " ++
	  make_param(<<"username">>,User) ++
	  lookup_param(<<"realm">>, Params) ++
	  lookup_param(<<"nonce">>, Params) ++
	  lookup_param(<<"uri">>, Params) ++
	  lookup_param(<<"response">>, Params)}].

make_param(Key, Value) ->
    to_key(Key)++"="++to_value(Value).

lookup_param(Key, List) ->
    case proplists:get_value(Key, List) of
	undefined -> [];
	Value -> ", "++make_param(Key, Value)
    end.

-spec to_key(binary()) -> string().
to_key(Bin) -> binary_to_list(Bin).

to_value(Bin) when is_binary(Bin) -> [?Q]++binary_to_list(Bin)++[?Q];
to_value(List) when is_list(List) -> [?Q]++List++[?Q];
to_value(Atom) when is_atom(Atom) -> atom_to_list(Atom);
to_value(Int) when is_integer(Int) -> integer_to_list(Int).

%%
%% Url encode a string
%%
url_encode([C|T]) ->
    if C >= $a, C =< $z ->  [C|url_encode(T)];   %% unreserved
       C >= $A, C =< $Z ->  [C|url_encode(T)];   %% unreserved
       C >= $0, C =< $9 ->  [C|url_encode(T)];   %% unreserved
       C =:= $\s        ->  [$+|url_encode(T)];
       C =:= $-; C =:= $.; C =:= $_; C =:= $~ -> %% unreserved
	    [C|url_encode(T)];
       C =:= $!; C =:= $$; C =:= $&; C =:= $'; C =:= $(; C =:= $);
       C =:= $*; C =:= $+; C =:= $,; C =:= $;; C =:= $= ->  %% sub-delims
	    [C|url_encode(T)];
       C =:= $:; C =:= $@ ->  %% pchar
	    [C|url_encode(T)];
       true ->  %% pct-encoded
	    case erlang:integer_to_list(C, 16) of
		[C1]   -> [$%,$0,C1 | url_encode(T)];
		[C1,C2] ->[$%,C1,C2 | url_encode(T)]
	    end
    end;
url_encode([]) ->
    [].

url_decode([$%,C1,C2|T]) ->
    C = list_to_integer([C1,C2], 16),
    [C | url_decode(T)];
url_decode([$+|T]) -> [$\s|url_decode(T)];
url_decode([C|T]) -> [C|url_decode(T)];
url_decode([]) -> [].

to_list(X) when is_integer(X) -> integer_to_list(X);
to_list(X) when is_atom(X) -> atom_to_list(X);
to_list(X) when is_list(X) -> X.

convert_uri({abs_path, Path}) ->
    rester_url:parse_path(#url{ }, Path);
convert_uri({absoluteURI, Scheme, Host, Port, Path}) ->
    rester_url:parse_path(#url{ scheme = Scheme,host = Host, port = Port}, Path);
convert_uri({scheme, Scheme, Request}) ->
    #url{ scheme = Scheme, path = Request }.

format_field(Key,Value) ->
    K = if is_atom(Key) -> atom_to_list(Key);
	   is_list(Key) -> Key;
	   is_binary(Key) -> Key
	end,
    V = if is_integer(Value) -> integer_to_list(Value);
	   is_atom(Value) -> atom_to_list(Value);
	   is_list(Value) -> Value;
	   is_binary(Value) -> Value
	end,
    [K,": ",V,"\r\n"].

format_headers([{Key,Value}|Hs]) ->
    [format_field(Key,Value) | format_headers(Hs)];
format_headers([]) ->
    [].


mk_shdr(Hs) ->
    mk_shdr(Hs, #http_shdr { }).

mk_shdr([{K,V}|Hs], H) ->
    mk_shdr(Hs, set_shdr(K,V,H));
mk_shdr([], H) ->
    H.

set_shdr(K,V,H) ->
    case K of
	'Connection'        -> H#http_shdr { connection = V };
	'Transfer-Encoding' -> H#http_shdr { transfer_encoding = V };
	'Location'          -> H#http_shdr { location = V };
	'Set-Cookie'        -> H#http_shdr { set_cookie = V };
	'Content-Length'    -> H#http_shdr { content_length = V };
	'Content-Type'      -> H#http_shdr { content_type = V };
	_ ->
	    Hs = [{K,V} | H#http_shdr.other],
	    H#http_shdr { other = Hs }
    end.

mk_chdr(Hs) ->
    mk_chdr(Hs, #http_chdr { }).

mk_chdr([{K,V}|Hs], H) ->
    mk_chdr(Hs, set_chdr(K,V,H));
mk_chdr([], H) ->
    H.

set_chdr(K,V,H) ->
    case K of
	'Host'   -> H#http_chdr { host = V };
	'Connection' -> H#http_chdr { connection = V };
	'Transfer-Encoding' -> H#http_chdr { transfer_encoding = V };
	'Accept' -> H#http_chdr { accept = V };
	'If-Modified-Since' -> H#http_chdr { if_modified_since = V };
	'If-Match' -> H#http_chdr { if_match = V };
	'If-None-Match' -> H#http_chdr { if_none_match = V };
	'If-Range' -> H#http_chdr { if_range = V };
	'If-Unmodified-Since' -> H#http_chdr { if_unmodified_since = V };
	'Range' -> H#http_chdr { range = V };
	'Referer' -> H#http_chdr { referer = V };
	'User-Agent' -> H#http_chdr { user_agent = V };
	'Accept-Ranges' -> H#http_chdr { accept_ranges = V };
	'Cookie' ->
	    V1 = [V | H#http_chdr.cookie],
	    H#http_chdr { cookie = V1 };
	'Keep-Alive' -> H#http_chdr { keep_alive = V };
        'Content-Length' -> H#http_chdr { content_length = V };
        'Content-Type' -> H#http_chdr { content_type = V };
        'Authorization' -> H#http_chdr { authorization = V };
	_ ->
	    Hs = [{K,V} | H#http_chdr.other],
	    H#http_chdr { other = Hs }
    end.

format_hdr(H) when is_record(H, http_chdr) ->
    fcons('Host', H#http_chdr.host,
    fcons('Connection', H#http_chdr.connection,
    fcons('Transfer-Encoding', H#http_chdr.transfer_encoding,
    fcons('Accept', H#http_chdr.accept,
    fcons('If-Modified-Since', H#http_chdr.if_modified_since,
    fcons('If-Match', H#http_chdr.if_match,
    fcons('If-None-Match', H#http_chdr.if_none_match,
    fcons('If-Range', H#http_chdr.if_range,
    fcons('If-Unmodified-Since', H#http_chdr.if_unmodified_since,
    fcons('Range', H#http_chdr.range,
    fcons('Referer', H#http_chdr.referer,
    fcons('User-Agent', H#http_chdr.user_agent,
    fcons('Accept-Ranges', H#http_chdr.accept_ranges,
    fcons_list('Cookie', H#http_chdr.cookie,
    fcons('Keep-Alive', H#http_chdr.keep_alive,
    fcons('Content-Length', H#http_chdr.content_length,
    fcons('Content-Type', H#http_chdr.content_type,
    fcons('Authorization', H#http_chdr.authorization,
	  format_headers(H#http_chdr.other)))))))))))))))))));
format_hdr(H) when is_record(H, http_shdr) ->
    fcons('Connection', H#http_shdr.connection,
    fcons('Transfer-Encoding', H#http_shdr.transfer_encoding,
    fcons('Location', H#http_shdr.location,
    fcons('Set-Cookie', H#http_shdr.set_cookie,
    fcons('Content-Length', H#http_shdr.content_length,
    fcons('Content-Type', H#http_shdr.content_type,
	  format_headers(H#http_shdr.other))))))).


%%
%% Convert the http_chdr (client header) structure into a
%% key value list suitable for formatting.
%% returns [ {Key,Value} ]
%% Looks a bit strange, but is done this way to avoid creation
%% of garabge.
fmt_chdr(H) ->
    hcons('Host', H#http_chdr.host,
    hcons('Connection', H#http_chdr.connection,
    hcons('Transfer-Encoding', H#http_chdr.transfer_encoding,
    hcons('Accept', H#http_chdr.accept,
    hcons('If-Modified-Since', H#http_chdr.if_modified_since,
    hcons('If-Match', H#http_chdr.if_match,
    hcons('If-None-Match', H#http_chdr.if_none_match,
    hcons('If-Range', H#http_chdr.if_range,
    hcons('If-Unmodified-Since', H#http_chdr.if_unmodified_since,
    hcons('Range', H#http_chdr.range,
    hcons('Referer', H#http_chdr.referer,
    hcons('User-Agent', H#http_chdr.user_agent,
    hcons('Accept-Ranges', H#http_chdr.accept_ranges,
    hcons_list('Cookie', H#http_chdr.cookie,
    hcons('Keep-Alive', H#http_chdr.keep_alive,
    hcons('Content-Length', H#http_chdr.content_length,
    hcons('Content-Type', H#http_chdr.content_type,
    hcons('Authorization', H#http_chdr.authorization,
	  H#http_chdr.other)))))))))))))))))).

%% Convert the http_shdr (server header) structure into a
%% key value list suitable for formatting.
fmt_shdr(H) ->
    hcons('Connection', H#http_shdr.connection,
    hcons('Transfer-Encoding', H#http_shdr.transfer_encoding,
    hcons('Location', H#http_shdr.location,
    hcons('Set-Cookie', H#http_shdr.set_cookie,
    hcons('Content-Length', H#http_shdr.content_length,
    hcons('Content-Type', H#http_shdr.content_type,
	  H#http_shdr.other)))))).

hcons(_Key, undefined, Hs) -> Hs;
hcons(Key, Val, Hs) ->
    [{Key,Val} | Hs].

hcons_list(Key, [V|Vs], Hs) ->
    [{Key,V} | hcons_list(Key,Vs,Hs)];
hcons_list(_Key, [], Hs) ->
    Hs.

fcons(_Key, undefined, Hs) -> Hs;
fcons(Key, Val, Hs) ->
    [format_field(Key,Val) | Hs].

fcons_list(Key, [V|Vs], Hs) ->
    [format_field(Key,V) | fcons_list(Key,Vs,Hs)];
fcons_list(_Key, [], Hs) ->
    Hs.

%%
%% Parse chunk-size [ chunk-extension ] CRLF
%% return {chunk-size, chunk-extension}
%%
chunk_size(Line) ->
    chunk_size(Line, 0).

chunk_size([H|Hs], N) ->
    if
	H >= $0, H =< $9 ->
	    chunk_size(Hs, (N bsl 4)+(H-$0));
	H >= $a, H =< $f ->
	    chunk_size(Hs, (N bsl 4)+((H-$a)+10));
	H >= $A, H =< $F ->
	    chunk_size(Hs, (N bsl 4)+((H-$A)+10));
	H =:= $\r -> {N, ""};
	H =:= $\n -> {N, ""};
	H =:= $\s -> {N, Hs};
	H =:= $;  -> {N, [H|Hs]}
    end;
chunk_size([], N) ->
    {N, ""}.

tokens(undefined) ->
    [];
tokens(Line) ->
    string:tokens(string:to_lower(Line), ";").


%% Read and parse WWW-Authenticate header value
get_authenticate(undefined) ->
    {none,[]};
get_authenticate(<<>>) ->
    {none,[]};
get_authenticate(<<$\s,Cs/binary>>) ->
    get_authenticate(Cs);
get_authenticate(<<"Basic ",Cs/binary>>) ->
    {basic, get_params(Cs)};
get_authenticate(<<"Digest ",Cs/binary>>) ->
    {digest, get_params(Cs)};
get_authenticate(List) when is_list(List) ->
    get_authenticate(list_to_binary(List)).

get_params(Bin) ->
    Ps = binary:split(Bin, <<" ">>, [global]),
    [ case binary:split(P, <<"=">>) of
	  [K,V] -> {K,unq(V)};
	  [K] -> {K,true}
      end || P <- Ps, P =/= <<>> ].

%% "unquote" a string or a binary
unq(String) when is_binary(String) -> unq(binary_to_list(String));
unq([$\s|Cs]) -> unq(Cs);
unq([?Q|Cs]) -> unq_(Cs);
unq(Cs) -> Cs.

unq_([?Q|_]) -> [];
unq_([C|Cs]) -> [C|unq_(Cs)];
unq_([]) -> [].

make_digest_response(Cred, Method, AuthParams) ->
    Nonce = proplists:get_value(<<"nonce">>,AuthParams,""),
    DigestUriValue = proplists:get_value(<<"uri">>,AuthParams,""),
    %% FIXME! Verify Nonce!!!
    A1 = a1(Cred),
    HA1 = hex(crypto:hash(md5,A1)),
    A2 = a2(Method, DigestUriValue),
    HA2 = hex(crypto:hash(md5,A2)),
    hex(kd(HA1, Nonce++":"++HA2)).

a1({digest,_Path,User,Password,Realm}) ->
    iolist_to_binary([User,":",Realm,":",Password]).

a2(Method, Uri) ->
    iolist_to_binary([atom_to_list(Method),":",Uri]).

kd(Secret, Data) ->
    crypto:hash(md5,[Secret,":",Data]).

hex(Bin) ->
    [ element(X+1, {$0,$1,$2,$3,$4,$5,$6,$7,$8,$9,$a,$b,$c,$d,$e,$f}) ||
	<<X:4>> <= Bin ].

%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
%% decode http-date (RFC 2068). (MUST be send in RFC1123 date format)
%%          HTTP-date    = rfc1123-date | rfc850-date | asctime-date
%%          rfc1123-date = wkday "," SP date1 SP time SP "GMT"
%%          rfc850-date  = weekday "," SP date2 SP time SP "GMT"
%%          asctime-date = wkday SP date3 SP time SP 4DIGIT
%%
%%          date1        = 2DIGIT SP month SP 4DIGIT
%%                         ; day month year (e.g., 02 Jun 1982)
%%          date2        = 2DIGIT "-" month "-" 2DIGIT
%%                         ; day-month-year (e.g., 02-Jun-82)
%%          date3        = month SP ( 2DIGIT | ( SP 1DIGIT ))
%%                         ; month day (e.g., Jun  2)
%%
%%          time         = 2DIGIT ":" 2DIGIT ":" 2DIGIT
%%                         ; 00:00:00 - 23:59:59
%%
%%          wkday        = "Mon" | "Tue" | "Wed"
%%                       | "Thu" | "Fri" | "Sat" | "Sun"
%%
%%
%%          weekday      = "Monday" | "Tuesday" | "Wednesday"
%%                       | "Thursday" | "Friday" | "Saturday" | "Sunday"
%%
%%          month        = "Jan" | "Feb" | "Mar" | "Apr"
%%                       | "May" | "Jun" | "Jul" | "Aug"
%%                       | "Sep" | "Oct" | "Nov" | "Dec"
%%
%% decode date or crash!
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%

parse_date(Line) -> dec_http_date(string:to_lower(Line)).

dec_http_date([$m,$o,$n,$d,$a,$y,$\s | Cs]) -> dec_date2(Cs);
dec_http_date([$t,$u,$e,$s,$d,$a,$y,$\s | Cs]) -> dec_date2(Cs);
dec_http_date([$w,$e,$d,$n,$s,$d,$a,$y,$\s | Cs]) -> dec_date2(Cs);
dec_http_date([$t,$h,$u,$r,$s,$d,$a,$y,$\s | Cs]) -> dec_date2(Cs);
dec_http_date([$f,$r,$i,$d,$a,$y,$\s | Cs]) -> dec_date2(Cs);
dec_http_date([$s,$a,$t,$u,$r,$d,$a,$y,$\s  | Cs]) -> dec_date2(Cs);
dec_http_date([$s,$u,$n,$d,$a,$y,$\s | Cs]) -> dec_date2(Cs);
dec_http_date([$m,$o,$n,X | Cs]) -> dec_date13(X,Cs);
dec_http_date([$t,$u,$e,X  | Cs]) -> dec_date13(X,Cs);
dec_http_date([$w,$e,$d,X  | Cs]) -> dec_date13(X,Cs);
dec_http_date([$t,$h,$u,X  | Cs]) -> dec_date13(X,Cs);
dec_http_date([$f,$r,$i,X  | Cs]) -> dec_date13(X,Cs);
dec_http_date([$s,$a,$t,X  | Cs]) -> dec_date13(X,Cs);
dec_http_date([$s,$u,$n,X  | Cs]) -> dec_date13(X,Cs).

dec_date13($\s, Cs) -> dec_date3(Cs);
dec_date13($,, [$\s|Cs]) -> dec_date1(Cs).

%% date1
dec_date1([D1,D2,$\s,M1,M2,M3,$\s,Y1,Y2,Y3,Y4,$\s | Cs]) ->
    M = dec_month(M1,M2,M3),
    D = lti(D1,D2),
    Y = lti(Y1,Y2,Y3,Y4),
    {Time,[$\s,$g,$m,$t|Cs1]} = dec_time(Cs),
    { {{Y,M,D},Time}, Cs1}.

%% date2
dec_date2([D1,D2,$-,M1,M2,M3,$-,Y1,Y2 | Cs]) ->
    M = dec_month(M1,M2,M3),
    D = lti(D1,D2),
    Y = 1900 + lti(Y1,Y2),
    {Time, [$\s,$g,$m,$t|Cs1]} = dec_time(Cs),
    {{{Y,M,D}, Time}, Cs1}.

%% date3
dec_date3([M1,M2,M3,$\s,D1,D2,$\s| Cs]) ->
    M = dec_month(M1,M2,M3),
    D = if D1 =:= $\s -> lti(D2);
	   true -> lti(D1,D2)
	end,
    {Time,[$\s,Y1,Y2,Y3,Y4|Cs1]} = dec_time(Cs),
    Y = lti(Y1,Y2,Y3,Y4),
    { {{Y,M,D}, Time}, Cs1 }.

%% decode lowercase month
dec_month($j,$a,$n) -> 1;
dec_month($f,$e,$b) -> 2;
dec_month($m,$a,$r) -> 3;
dec_month($a,$p,$r) -> 4;
dec_month($m,$a,$y) -> 5;
dec_month($j,$u,$n) -> 6;
dec_month($j,$u,$l) -> 7;
dec_month($a,$u,$g) -> 8;
dec_month($s,$e,$p) -> 9;
dec_month($o,$c,$t) -> 10;
dec_month($n,$o,$v) -> 11;
dec_month($d,$e,$c) -> 12.

%% decode time HH:MM:SS
dec_time([H1,H2,$:,M1,M2,$:,S1,S2|Cs]) ->
    { {lti(H1,H2), lti(M1,M2), lti(S1,S2) }, Cs}.


format_current_date() ->
    format_date(calendar:universal_time()).

format_timestamp(Us) when is_integer(Us), Us >=0  ->
    SS = Us div 1000000,
    NowU = Us rem 1000000,
    NowMs = SS div 1000000,
    NowS  = SS rem 1000000,
    format_timestamp({NowMs,NowS,NowU});
format_timestamp({NowMs,NowS,NowU}) ->
    {{YYYY,MM,DD},{H,M,S}} = calendar:now_to_datetime({NowMs,NowS,NowU}),
    io_lib:format("~4..0w-~2..0w-~2..0w ~2..0w:~2..0w:~2..0w.~w",
		  [YYYY,MM,DD,H,M,S,NowU]).

%% encode date into rfc1123-date (must be a GMT time!!!)
format_date({{Y,M,D},{TH,TM,TS}}) ->
    WkDay = case calendar:day_of_the_week({Y,M,D}) of
		1 -> "Mon";
		2 -> "Tue";
		3 -> "Wed";
		4 -> "Thu";
		5 -> "Fri";
		6 -> "Sat";
		7 -> "Sun"
	    end,
    [WkDay, $,,
     $\s, itl_2_0(D),
     $\s, enc_month(M),
     $\s, itl_4_0(Y),
     $\s, itl_2_0(TH),
     $:, itl_2_0(TM),
     $:, itl_2_0(TS),
     " GMT"].

itl_2_0(I) ->  %% ~2..0w
    tl(integer_to_list(100 + I)).

itl_4_0(I) ->  %% ~4..0w
    tl(integer_to_list(10000 + I)).

lti(D1) ->
    (D1-$0).

lti(D1, D2) ->
    (D1-$0)*10 + (D2-$0).

lti(D1, D2, D3, D4) ->
    100*lti(D1,D2) + lti(D3, D4).

%% encode month
enc_month(1) -> "Jan";
enc_month(2) -> "Feb";
enc_month(3) -> "Mar";
enc_month(4) -> "Apr";
enc_month(5) -> "May";
enc_month(6) -> "Jun";
enc_month(7) -> "Jul";
enc_month(8) -> "Aug";
enc_month(9) -> "Sep";
enc_month(10) -> "Oct";
enc_month(11) -> "Nov";
enc_month(12) -> "Dec".
