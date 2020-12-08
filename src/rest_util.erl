-module(rest_util).
-export([parse_body/2, parse_body/3, parse_json_params/2,
         access/1,
         response/3,
         header_match/3, if_match/2, if_unmodified_since/2, if_none_match/2,
         if_modified_since/2]).

-include_lib("apptools/include/log.hrl").
-include_lib("rester/include/rester.hrl").
-include_lib("rester/include/rester_http.hrl").

-define(LATEST_VSN, v1).

%% Exported: parse_body

parse_body(Request, Body) ->
    parse_body(Request, Body, []).

parse_body(Request, Body, Options) ->
    ?dbg_log_fmt("body ~p", [Body]),
    case try_parse_body(Request, Body, Options) of
	{ok, Data} ->
            parse_data(Data);
	[{"data", Data}] ->
            parse_data(Data);
	[{Data, true}] ->
            parse_data(Data);  %% default is urlencoded
	List when is_list(List) ->
            List;
	Error ->
            Error
    end.

try_parse_body(Request, Body, Options) ->
    try parse_data(Request, Body, Options) of
	{error, _Reason} ->
	    ?log_warning("parse failed, reason ~p", [_Reason]),
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
    ?dbg_log_fmt("type ~p, body ~p", [Type, Body]),
    case Type of
	"*/*" -> %% Accept?
	    {ok,parse_data(Body)};
	"text/plain" ->
	    {ok,parse_data(Body)};
	"application/json" ->
	    parse_json_string(Body, Options);
	"application/x-www-form-urlencoded" ->
	    rester_http:parse_query(Body);
        "multipart/form-data; boundary=" ++ _ ->
            Body;
        Type ->
	    ?dbg_log_fmt("type: ~p~n", [Type]),
	    {error, "Unknown content type"}
    end.

parse_json_string(Data, Options) ->
    case lists:keysearch(jsone_options, 1, Options) of
        {value, {_, JsoneOptions}} ->
            ok;
        false ->
            JsoneOptions = []
    end,
    try jsone:decode(iolist_to_binary(Data), JsoneOptions) of
	Term ->
            {ok, Term}
    catch
	error:Reason ->
	    {error, Reason}
    end.

parse_data(B) when is_binary(B) ->
    B;
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

parse_json_params(JsonTerm, Params) ->
    parse_json_params(JsonTerm, Params, []).

parse_json_params([], [], Acc) ->
    lists:reverse(Acc);
parse_json_params([{Name, _Value}|_], [], _Acc) ->
    throw({error, io_lib:format("~s not expected", [Name])});
parse_json_params(_JsonTerm, [], _Acc) ->
    throw({error, "Invalid parameters"});
parse_json_params(JsonTerm, [{Name, CheckType}|Rest], Acc) ->
    case lists:keytake(Name, 1, JsonTerm) of
        {value, {_, Value}, RemainingJsonTerm} ->
            case CheckType(Value) of
                true ->
                    parse_json_params(RemainingJsonTerm, Rest, [Value|Acc]);
                false ->
                    throw({error, io_lib:format("~s has bad type", [Name])})
            end;
        false ->
            throw({error, io_lib:format("~s is missing", [Name])})
    end;
parse_json_params(JsonTerm, [{Name, CheckType, DefaultValue}|Rest], Acc) ->
    case lists:keytake(Name, 1, JsonTerm) of
        {value, {_, Value}, RemainingJsonTerm} ->
            case CheckType(Value) of
                true ->
                    parse_json_params(RemainingJsonTerm, Rest, [Value|Acc]);
                false ->
                    throw({error, io_lib:format("~s has bad type", [Name])})
            end;
        false ->
            parse_json_params(JsonTerm, Rest, [DefaultValue|Acc])
    end;
parse_json_params(_JsonTerm, _Params, _Acc) ->
    throw({error, "Invalid parameters"}).

%%%-------------------------------------------------------------------
%% Check conditional headers (KEEP THEM!!!)
%%%-------------------------------------------------------------------

%% Exported: header_match

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

%% Exported: if_match

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

%% Exported: if_unmodified_since

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

%% Exported: if_none_match

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

%% Exported: if_modified_since

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

%% Exported: response

%%%-------------------------------------------------------------------
%%% General response function
%%%-------------------------------------------------------------------
response(Socket,Request,ok)  ->
    rester_http_server:response_r(Socket,Request,200,"OK","",[]);
response(Socket,Request,ok_204)  ->
    rester_http_server:response_r(Socket,Request,204,"OK","",[]);
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
response(Socket,Request,{ok, {format, Args}}) ->
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
    ?dbg_log_fmt("can not handle error ~p:~p", [Reason, ErrorMsg]),
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
-spec format_reply_json(Term::term()) -> binary().

format_reply_json(Term) ->
    jsone:encode(Term, [{float_format, [{decimals, 4}, compact]},
                        {indent, 2},
                        {object_key_type, value},
                        {space, 1},
                        native_forward_slash]).

-spec format_reply_text(Term::term()) ->
	  TextReply::string().

format_reply_text(Data) when is_list(Data) ->
    Data1 = [{Key,lists:flatten(Value)} || {Key,Value} <- Data],
    io_lib:format("~p", [Data1]);
format_reply_text(Data) ->
    io_lib:format("~p", [Data]).

%% Exported: access

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
	    ?dbg_log_fmt("SockName ~p, xylan port ~p",[SockName, XylanPort]),
	    case SockName of
		{ok, XylanPort} -> remote;
		{ok, {{127,0,0,1}, _Port}} -> local;
		{ok, {_IP, _Port}} -> network; %% Allowed ??
		_O ->
		    ?log_warning("sockname ~p",[_O]),
		    unknown %% ???
	    end
    end.
