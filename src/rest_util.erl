-module(rest_util).
-export([parse_body/2, parse_body/3, parse_json_params/2,
         access/1,
         response/3,
         header_match/3, if_match/2, if_unmodified_since/2, if_none_match/2,
         if_modified_since/2]).

%%-include_lib("apptools/include/log.hrl").
%%-include_lib("apptools/include/shorthand.hrl").
-include_lib("rester/include/rester.hrl").
-include_lib("rester/include/rester_http.hrl").

-define(LATEST_VSN, v1).

%%
%% Exported: parse_body
%%

parse_body(Request, Body) ->
    parse_body(Request, Body, []).

parse_body(Request, Body, Options) ->
    ?debug("body ~p", [Body]),
    case try_parse_body(Request, Body, Options) of
	{ok, Data} ->
            parse_data(Data);
	Error ->
            Error
    end.

try_parse_body(Request, Body, Options) ->
    try parse_data(Request, Body, Options) of
	{error, _Reason} ->
	    ?warning("parse failed, reason ~p", [_Reason]),
	    {error, badarg};
	Result ->
            Result
    catch
        error:Reason -> {error, Reason}
    end.

parse_data(Request, Body, Options) when is_binary(Body)->
    parse_data(Request, binary_to_list(Body), Options);
parse_data(Request, Body, Options) ->
    Type = (Request#http_request.headers)#http_chdr.content_type,
    ?debug("type ~p, body ~p", [Type, Body]),
    case string:split(Type, ";") of
	["*/*"|_] -> %% Accept?
	    {ok,parse_data(Body)};
	["text/plain"|_] ->
	    {ok,parse_data(Body)};
	["application/json"|_] ->
	    parse_json_string(Body, Options);
	["application/x-www-form-urlencoded"|_] ->
	    {ok,rester_http:parse_query(Body)};
        ["multipart/form-data", "boundary="++ _, _] ->
            {ok,Body};
        _ ->
	    ?debug("type: ~p~n", [Type]),
	    {error, "Unknown content type"}
    end.


parse_json_string(Data, Options) ->
    try json:decode(iolist_to_binary(Data)) of
	JsonTerm ->
            {ok, munge_json(JsonTerm, Options)}
    catch
        error:Reason ->
	    {error, Reason}
    end.

munge_json(JsonTerm, Options) ->
    case lists:keysearch(json_options, 1, Options) of
        {value, {_, JsonOptions}} ->
            case lists:member(proplist, JsonOptions) of
                true ->
                    proplistify(JsonTerm);
                false ->
                    JsonTerm
            end;
        false ->
            JsonTerm
    end.

proplistify(JsonTerm) ->
    case maps:size(JsonTerm) of
        0 ->
            [{}];
        _ ->
            proplists:from_map(JsonTerm)
    end.

parse_data(B) when is_binary(B) ->
    B;
parse_data(I) when is_integer(I) ->
    I;
parse_data(F) when is_float(F) ->
    F;
parse_data(M) when is_map(M) ->
    M;
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

parse_json_params(JsonTerm, Params) ->
    parse_json_params(JsonTerm, Params, []).

parse_json_params([], [], Acc) ->
    lists:reverse(Acc);
parse_json_params([{Name, _Value}|_], [], _Acc) ->
    throw({error, list_to_binary(io_lib:format("~s not expected", [Name]))});
parse_json_params(_JsonTerm, [], _Acc) ->
    throw({error, <<"Invalid parameters">>});
parse_json_params(JsonTerm, [{Name, CheckType}|Rest], Acc) ->
    case lists:keytake(Name, 1, JsonTerm) of
        {value, {_, Value}, RemainingJsonTerm} ->
            case CheckType(Value) of
                true ->
                    parse_json_params(RemainingJsonTerm, Rest, [Value|Acc]);
                false ->
                    throw({error, list_to_binary(io_lib:format("~s has bad type", [Name]))})
            end;
        false ->
            throw({error, list_to_binary(io_lib:format("~s is missing", [Name]))})
    end;
parse_json_params(JsonTerm, [{Name, CheckType, DefaultValue}|Rest], Acc) ->
    case lists:keytake(Name, 1, JsonTerm) of
        {value, {_, Value}, RemainingJsonTerm} ->
            case CheckType(Value) of
                true ->
                    parse_json_params(RemainingJsonTerm, Rest, [Value|Acc]);
                false ->
                    throw({error, list_to_binary(io_lib:format("~s has bad type", [Name]))})
            end;
        false ->
            parse_json_params(JsonTerm, Rest, [DefaultValue|Acc])
    end;
parse_json_params(_JsonTerm, _Params, _Acc) ->
    throw({error, <<"Invalid parameters">>}).

%%%-------------------------------------------------------------------
%% Check conditional headers (KEEP THEM!!!)
%%%-------------------------------------------------------------------

%%
%% Exported: header_match
%%

-spec header_match(H::#http_chdr{}, ETag::string(), Lmt::calendar:datetime())
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

%%
%% Exported: if_match
%%

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

%%
%% Exported: if_unmodified_since
%%

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

%%
%% Exported: if_none_match
%%

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

%%
%% Exported: if_modified_since
%%

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

%%
%% Exported: response
%%

%%%-------------------------------------------------------------------
%%% General response function
%%%-------------------------------------------------------------------

%% 20x
response(Socket, Request, ok)  ->
    rester_http_server:response_r(Socket, Request, 200, "OK", "", []);
response(Socket, Request, {ok, String}) when is_list(String) ->
    rester_http_server:response_r(Socket, Request, 200, "OK", String, []);
response(Socket,Request,{ok, Atom}) when is_atom(Atom) ->
    rester_http_server:response_r(Socket, Request, 200, "OK",
                                  atom_to_list(Atom), []);
response(Socket,Request, {ok, Bin}) when is_binary(Bin) ->
    rester_http_server:response_r(Socket,Request, 200, "OK", Bin, []);
response(Socket,Request, {ok, String, json}) when is_list(String) ->
    rester_http_server:response_r(Socket, Request, 200, "OK", String,
                                  [{content_type, "application/json"}]);
response(Socket,Request,{ok, String, html}) when is_list(String) ->
    rester_http_server:response_r(Socket, Request, 200, "OK", String,
                                  [{content_type,"text/html"}]);
response(Socket, Request, {ok, {format, Args}}) ->
    {ContentType, Reply} = format_reply(Args, Request),
    rester_http_server:response_r(Socket, Request, 200, "OK", Reply,
                                  [{content_type, ContentType}]);
response(Socket, Request, ok_201)  ->
    rester_http_server:response_r(
      Socket, Request, 201, "Created",
      "The request was successful, and a new resource was created as a result",
      []);
response(Socket, Request, ok_204)  ->
    rester_http_server:response_r(Socket, Request, 204, "OK", "No Content", []);
%% 30x
response(Socket, Request, {error, not_modified, ErrorMsg})
  when is_list(ErrorMsg) ->
    rester_http_server:response_r(Socket, Request, 304, "Not Modified",
                                  ErrorMsg, []);
response(Socket,Request, {error, not_modified}) ->
    rester_http_server:response_r(Socket,Request, 304, "Not Modified",
                                  "Object not modified", []);
%% 40x
response(Socket, Request, {error, bad_request, ErrorMsg})
  when is_list(ErrorMsg) ->
    rester_http_server:response_r(Socket, Request, 400, "Bad Request",
                                  ErrorMsg, []);
response(Socket, Request, {error, badarg}) ->
    rester_http_server:response_r(Socket, Request, 400, "Bad Request",
                                  "Bad argument", []);
response(Socket, Request, {error, badarg, ErrMsg}) ->
    rester_http_server:response_r(Socket, Request, 400, "Bad Request",
                                  ErrMsg, []);
response(Socket, Request, {error, not_implemented}) ->
    rester_http_server:response_r(Socket, Request, 400, "Bad Request",
                                  "Not implemented", []);
response(Socket, Request, {error, not_applicable}) ->
    rester_http_server:response_r(Socket, Request, 400, "Bad Request",
                                  "Not applicable", []);
%% 401
response(Socket, Request, {error, unauthorized, ErrorMsg})
  when is_list(ErrorMsg) ->
    rester_http_server:response_r(Socket, Request, 401, "Unauthorized",
                                  ErrorMsg, []);
response(Socket, Request, {error, unauthorized}) ->
    rester_http_server:response_r(
      Socket, Request, 401, "Unauthorized",
      "Authentication is required and has failed or has not yet been provided",
      []);
response(Socket, Request, {error, {forbidden, Body}}) ->
    rester_http_server:response_r(Socket, Request, 403, "Forbidden", Body, []);
response(Socket, Request, {error, forbidden}) ->
    rester_http_server:response_r(
      Socket, Request, 403, "Forbidden",
      "The server understood the request but refuses to authorize it", []);
response(Socket, Request, {error, not_found}) ->
    rester_http_server:response_r(Socket, Request, 404, "Not Found",
                                  "The requested resource could not be found",
                                  []);
response(Socket, Request, {error, enoent}) ->
    rester_http_server:response_r(
      Socket, Request, 404, "Not Found",
      "The file or directory you're asking for doesn't exist", []);
response(Socket, Request, {error, unknown_event}) ->
    rester_http_server:response_r(Socket, Request, 404, "Not Found",
                                  "Event not found",[]);
response(Socket, Request, {error, not_allowed}) ->
    rester_http_server:response_r(
      Socket, Request, 405, "Method Not Allowed",
      "The HTTP method used is not supported for the resource",
      [{<<"Allow">>, <<"GET,PUT,POST">>}]);
response(Socket, Request, {error, timeout}) ->
    rester_http_server:response_r(
      Socket, Request, 408, "Request Timeout",
      "The server timed out waiting for the request", []);
response(Socket, Request, {error, precondition_failed}) ->
    rester_http_server:response_r(
      Socket, Request, 412, "Precondition Failed",
      "One or more preconditions in the request headers were not met", []);
%% 50x
response(Socket, Request, {error, internal_error, ErrorMsg})
  when is_list(ErrorMsg)->
    rester_http_server:response_r(Socket, Request, 500, "Internal Server Error",
                                  ErrorMsg, []);
response(Socket, Request, {error, Reason, ErrorMsg}) when is_list(ErrorMsg) ->
    ?debug("can not handle error ~p:~p", [Reason, ErrorMsg]),
    rester_http_server:response_r(Socket, Request, 500, "Internal Server Error",
                                  ErrorMsg, []);
response(Socket, Request, {error, Reason}) when is_list(Reason)->
    rester_http_server:response_r(Socket, Request, 500, "Internal Server Error",
                                  Reason, []);
response(Socket,Request, {error, Reason}) when is_atom(Reason)->
    rester_http_server:response_r(Socket, Request, 500, "Internal Server Error",
                                  atom_to_list(Reason), []);
response(Socket, Request, {error, Reason}) ->
    ?warning("can not handle error ~p", [Reason]),
    rester_http_server:response_r(Socket, Request, 500, "Internal Server Error",
                                  "", []);
response(Socket, Request, {error, Reason, Format, Args})
  when is_list(Format), is_list(Args) ->
    ErrorMsg = io_lib:format(Format, Args),
    response(Socket, Request, {error, Reason, ErrorMsg});
response(Socket, Request, Other) ->
    ?warning("can not handle result ~p", [Other]),
    rester_http_server:response_r(Socket, Request, 500," Internal Server Error",
                                  "", []).

%%%-------------------------------------------------------------------

format_reply(Data, Request) ->
    case (Request#http_request.headers)#http_chdr.accept of
	"application/json" ->
	    {"application/json", format_reply_json(Data)};
	"text/plain" ->
	    {"text/plain", format_reply_text(Data)};
	"*/*" ->
	    {"application/json", format_reply_json(Data)};
        undefined ->
	    {"application/json", format_reply_json(Data)}
    end.

%%%-------------------------------------------------------------------
-spec format_reply_json(Term::term()) -> binary().

format_reply_json(Term) ->
    json:encode(Term).

-spec format_reply_text(Term::term()) ->
	  TextReply::string().

format_reply_text(Data) when is_list(Data) ->
    Data1 = [{Key,lists:flatten(Value)} || {Key,Value} <- Data],
    io_lib:format("~p", [Data1]);
format_reply_text(Data) ->
    io_lib:format("~p", [Data]).

%%
%% Exported: access
%%

%%-spec access(Socket::#rester_socket{}) -> Access::access().

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
	    ?debug("SockName ~p, xylan port ~p",[SockName, XylanPort]),
	    case SockName of
		{ok, XylanPort} -> remote;
		{ok, {{127,0,0,1}, _Port}} -> local;
		{ok, {_IP, _Port}} -> network; %% Allowed ??
		_O ->
		    ?warning("sockname ~p",[_O]),
		    unknown %% ???
	    end
    end.
