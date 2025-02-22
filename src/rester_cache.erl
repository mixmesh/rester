%%% @author Tony Rogvall <tony@rogvall.se>
%%% @copyright (C) 2021, Tony Rogvall
%%% @doc
%%%    Rester client cache interface
%%% @end
%%% Created : 19 Dec 2021 by Tony Rogvall <tony@rogvall.se>

-module(rester_cache).

-include("../include/rester.hrl").
-include("../include/rester_http.hrl").

%% return content in return if less equal in size to:
%% return file reference otherwise {file, Filename}
-define(CONTENT_MAX_SIZE, 1024).

-export([get/1, get/2, get/3, get/4]).

get(Url) ->
    get(Url,{1,1},[],infinity).

get(Url, Hs) ->
    get(Url, {1,1}, Hs, infinity).

get(Url, Version, Hs) ->
    get(Url, Version, Hs, infinity).

get(Url, Version={Ma,Mi}, Hs, Timeout)
  when is_list(Hs),
       is_integer(Ma), is_integer(Mi),
       ((is_integer(Timeout) andalso (Timeout > 0))
	orelse (Timeout =:= infinity)) ->
    Req = rester_http:make_request('GET',Url,Version,Hs),
    request(Req,[],Timeout).

request(Req, Body,Timeout) ->
    case rester_http:open(Req,Timeout) of
	{ok, S} ->
	    case request_(S, Req, Body, false, Timeout) of
		{ok,Resp,BodyOrFile} ->
		    rester_http:close(S,Req,Resp),
		    {ok,Resp,BodyOrFile};
		Error ->
		    rester_socket:close(S),
		    Error
	    end;
	Error ->
	    Error
    end.

%% FIXME: add
%%   follow 301 - (Moved) and check Content-Length
%%   follow 302 - (Found) and check Content-Length
%%
request_(S, Req, Body, Proxy, Timeout) ->
    case rester_http:send(S, Req, Body, Proxy) of
	ok ->
	    %% FIXME: take care of POST 100-continue
	    case rester_http:recv_response(S, Timeout) of
		{ok, Resp} ->
		    ?debug("response: ~p", [Resp]),
		    get_body_(S, Resp, Timeout);
		Error ->

		    ?debug("response: ~p", [Error]),
		    Error
	    end;
	Error -> Error
    end.

%% return response either as binary or {file,Filename} (size > CONTENT_MAX)
get_body_(S, Resp, Timeout) ->
    Dir = filename:join([os:getenv("HOME"), ".local", "lib",
			 "mixmesh", "cache"]),
    CacheCopy = filename:join(Dir, "content.dat"),
    {ok, Fd} = file:open(CacheCopy, [write]),
    try rester_http:recv_body(S, Resp,
			      fun (Chunk, {Size,Acc}) ->
				      ok = file:write(Fd, Chunk),
				      Size1 = Size + byte_size(Chunk),
				      if Size1 >= ?CONTENT_MAX_SIZE ->
					      {Size1, filename};
					 true ->
					      {Size1, [Chunk | Acc]}
				      end
			      end,
			      {0,[]},
			      Timeout) of
	{ok,{Size,filename}} ->
	    write_meta(Dir, Resp),
	    {ok,Resp,{Size,{filename,CacheCopy}}};
	{ok,{Size,RespBody}} ->
	    write_meta(Dir, Resp),
	    {ok,Resp,{Size,RespBody}};
	Error ->
	    ?debug("body: ~p", [Error]),
	    Error
    after
	file:close(Fd)
    end.


%% write cache headers ...
%% FIXME: Filter
%%   Content-Type:
%%   Content-Length:
%%   Cache-Control:
%%   Age:
%%
write_meta(Dir, Resp) ->
    Meta = filename:join(Dir, "meta.txt"),
    {ok, Fd1} = file:open(Meta, [write]),
    io:format(Fd1, "~p.\n",
	      [rester_http:fmt_shdr(Resp#http_response.headers)]),
    file:close(Fd1).
