%%% @author Tony Rogvall <tony@rogvall.se>
%%% @copyright (C) 2020, Tony Rogvall
%%% @doc
%%%    flow control
%%% @end
%%% Created : 15 Oct 2020 by Tony Rogvall <tony@rogvall.se>

-module(rester_flow).

-behaviour(gen_server).

%% general api
-export([start_link/1, 
	 stop/0]).

%% functional api
-export([new/2,
	 delete/1,
	 transfer/2,
	 use/2,
	 fill/1,
	 fill_time/2,
	 wait/2,
	 fill_wait/2,
	 statistics/1]).

%% gen_server callbacks
-export([init/1, 
	 handle_call/3, 
	 handle_cast/2, 
	 handle_info/2,
	 terminate/2, 
	 code_change/3]).

%% support api
-export([buckets_exist/0]).

%% test api
-export([dump/0]).

-define(SERVER, ?MODULE). 
-define(BUCKETS, rester_token_buckets).
-define(POLICIES, rester_token_policies).

%% for dialyzer
-type start_options()::{linked, TrueOrFalse::boolean()}.

%% token bucket
-record(bucket,
	{
	  key::term(),
	  capacity::float(),    %% max number of tokens in the bucket
	  rate::float(),        %% tokens per second 
	  current::float(),     %% current number of tokens
	  action::atom(),       %% to do when overload
	  parent::atom(),       %% for group flow
	  timestamp::integer()  %% last time
	}).

%% loop data
-record(ctx,
	{
	  buckets::term(),
	  policies::term(),
	  owners::term()
	}).

-include("../include/rester.hrl").

%%%===================================================================
%%% API
%%%===================================================================
%%--------------------------------------------------------------------
%% @doc
%% Starts the server.
%% Loads configuration from File.
%% @end
%%--------------------------------------------------------------------
-spec start_link(Opts::list(start_options())) -> 
			{ok, Pid::pid()} | 
			ignore | 
			{error, Error::term()}.

start_link(Opts) ->
    ?debug("args = ~p\n", [Opts]),
    F =	case proplists:get_value(linked,Opts,true) of
	    true -> start_link;
	    false -> start
	end,
    
    gen_server:F({local, ?SERVER}, ?MODULE, Opts, []).


%%--------------------------------------------------------------------
%% @doc
%% Stops the server.
%% @end
%%--------------------------------------------------------------------
-spec stop() -> ok | {error, Error::term()}.

stop() ->
    gen_server:call(?SERVER, stop).


%%--------------------------------------------------------------------
%% @doc
%% Create a pair of new buckets, one for incoming and one for outgoing.
%%
%% @end
%%--------------------------------------------------------------------
-spec new(Key::term(), Policy::atom()) -> 
		 ok | 
		 {error, Error::atom()}.

new(Key, Policy) when is_atom(Policy) ->
    ?debug("new key = ~p, ~p", [Key, Policy]),
    case is_up() of
	true ->
	    case new_bucket({in, Key}, Policy) of
		ok ->
		    case new_bucket({out, Key}, Policy) of
			ok -> 
			    gen_server:cast(?SERVER, {add, self(), Key}),
			    ok;
			E -> 
			    delete({in, Key}), E
		    end;
		E ->
		    E
	    end;
	false ->
	    {error, not_up}
    end.

%%--------------------------------------------------------------------
%% @doc
%% Delete a bucket.
%%
%% @end
%%--------------------------------------------------------------------
-spec delete(Key::term()) -> 
		    ok | 
		    {error, Error::atom()}.

delete({Direction, _K} = Key) when Direction =:= in;
				   Direction =:= out ->
    ?debug("delete key = ~p", [Key]),
    ets:delete(?BUCKETS, Key);
delete(Key) ->
   case is_up() of
	true ->
	   delete({in, Key}),
	   delete({out, Key}),
	   gen_server:cast(?SERVER, {remove, Key});
	false ->
	    {error, not_up}
    end.

%%--------------------------------------------------------------------
%% @doc
%% Transfer a bucket.
%%
%% @end
%%--------------------------------------------------------------------
-spec transfer(Key::term(), Owner::term()) -> ok.

transfer(Key, Owner)  ->
    ?debug("transfer key = ~p, owner = ~p", [Key, Owner]),
    gen_server:cast(?SERVER, {transfer, Key, Owner}).

%%--------------------------------------------------------------------
%% @doc
%% Use a bucket.
%% If enough tokens -> ok, otherwise -> {error, Action}.
%%
%% @end
%%--------------------------------------------------------------------
-spec use(Key::term(), Tokens::number()) -> ok | 
					    {action, Action::throw | wait} |
					    {error, Error::atom()}.

use({Direction, _K} = Key, Tokens) 
  when is_number(Tokens), is_atom(Direction) ->
    ?debug("use key = ~p, tokens = ~p", [Key, Tokens]),
    case is_up() of
	true ->
	    use_tokens(Key, Tokens);
	false ->
	    {error, not_up}
    end.

%%--------------------------------------------------------------------
%% @doc
%% Fills the bucket fill rate with tokens accumulated since last use.
%% Returns number of tokens in the bucket.
%%
%% @end
%%--------------------------------------------------------------------
-spec fill(Key::term()) -> {ok, Tokens::number()} |
			   {error, Error::atom()}.

fill({Direction, _K} = Key) when is_atom(Direction) ->
    ?debug("fill key = ~p", [Key]),
    case is_up() of
	true ->
	    case ets:lookup(?BUCKETS, Key) of
		[B] when is_record(B, bucket) ->
		    fill_bucket(B);
		[] ->
		    {error, unknown_key}
	    end;
	false ->
	    {error, not_up}
    end.

%%--------------------------------------------------------------------
%% @doc
%% How long to wait for the bucket to contain Tokens in seconds.
%%
%% @end
%%--------------------------------------------------------------------
-spec fill_time(Key::term(), Tokens::number()) -> 
		       {ok, Secs::number()} |
		       {error, Error::atom()}.

fill_time({Direction, _K} = Key, Tokens) 
  when is_number(Tokens), is_atom(Direction) ->
    ?debug("fill_time key = ~p, tokens = ~p", [Key, Tokens]),
    case is_up() of
	true ->
	    case ets:lookup(?BUCKETS, Key) of
		[B] when is_record(B, bucket) ->
		    bucket_fill_time(B, Tokens);
		[] ->
		    {error, unknown_key}
	    end;
	false ->
	    {error, not_up}
    end.


%%--------------------------------------------------------------------
%% @doc
%% Wait the time needed for the bucket to have enough tokens.
%% However, does not fill the bucket !!!
%%
%% @end
%%--------------------------------------------------------------------
-spec wait(Key::term(), Tokens::number()) -> 
		       ok |
		       {error, Error::atom()}.

wait({Direction, _K} = Key, Tokens) 
  when is_number(Tokens), is_atom(Direction) ->
   ?debug("wait key = ~p, tokens = ~p", [Key, Tokens]),
    case is_up() of
	true ->
	    case ets:lookup(?BUCKETS, Key) of
		[B] when is_record(B, bucket) ->
		    bucket_wait(B, Tokens);
		[] ->
		    {error, unknown_key}
	    end;
	false ->
	    {error, not_up}
    end.
	    	    
%%--------------------------------------------------------------------
%% @doc
%% Wait the time needed for the bucket to have enough tokens and
%% fill the bucket.
%% Returns number of tokens in the bucket.
%%
%% @end
%%--------------------------------------------------------------------
-spec fill_wait(Key::term(), Tokens::number()) -> 
		       {ok, Tokens::number()} |
		       {error, Error::atom()}.

fill_wait({Direction, _K} = Key, Tokens) 
  when is_number(Tokens), is_atom(Direction) ->
   ?debug("fill_wait key = ~p, tokens = ~p", [Key, Tokens]),
    case is_up() of
	true ->
	    case ets:lookup(?BUCKETS, Key) of
		[B] when is_record(B, bucket) ->
		    bucket_wait(B, Tokens),
		    fill_bucket(B);
		[] ->
		    {error, unknown_key}
	    end;
	false ->
	    {error, not_up}
    end.

%%--------------------------------------------------------------------
%% @doc
%% Get statistics for an owner
%%
%% @end
%%--------------------------------------------------------------------
-spec statistics(Owner::pid()) ->
			list({Key::atom(), Value::term()}) |
			{error, Error::atom()}.

statistics(Owner) when is_pid(Owner)->
    gen_server:call(?SERVER,{stats, Owner}).

%%--------------------------------------------------------------------
%% @doc
%% Checks if any buckets
%%
%% @end
%%--------------------------------------------------------------------
-spec buckets_exist() -> boolean().

buckets_exist() ->
    case ets:info(?BUCKETS, size) of
	I when I > 0 -> true;
	0 -> false
    end.

%%--------------------------------------------------------------------
%% @doc
%% Dumps data to standard output.
%%
%% @end
%%--------------------------------------------------------------------
-spec dump() -> ok | {error, Error::atom()}.

dump() ->
    gen_server:call(?SERVER,dump).

%%%===================================================================
%%% gen_server callbacks
%%%===================================================================

%%--------------------------------------------------------------------
%% @private
%% @doc
%% Initializes the server
%%
%% @end
%%--------------------------------------------------------------------
-spec init(Args::list(start_options())) -> 
		  {ok, Ctx::#ctx{}} |
		  {stop, Reason::term()}.

init(Args) ->
    ?debug("args = ~p,\n pid = ~p\n", [Args, self()]),
    BTab = ets:new(?BUCKETS, [named_table, public, {keypos, #bucket.key}]),
    PTab = ets:new(?POLICIES, [named_table, public, {keypos, #bucket.key}]),
    OTab = ets:new(bucket_owners, [named_table]),
    lists:foreach(fun({PolicyName, Opts}) ->
			  add_template(PolicyName, in, Opts),
			  add_template(PolicyName, out, Opts)
		  end, opt_get_env(rester, policies, [])),
    {ok, #ctx {buckets = BTab, policies = PTab, owners = OTab}}.


%%--------------------------------------------------------------------
%% @private
%% @doc
%% Handling call messages.
%% Request can be the following:
%% <ul>
%% <li> {stats, Owner} - Get owner statistics.</li>
%% <li> dump - Writes loop data to standard out (for debugging).</li>
%% <li> stop - Stops the application.</li>
%% </ul>
%%
%% @end
%%--------------------------------------------------------------------
-type call_request()::
	{stats, Owner::pid()} |
	dump |
	stop.

-spec handle_call(Request::call_request(), From::{pid(), Tag::term()}, Ctx::#ctx{}) ->
			 {reply, Reply::term(), Ctx::#ctx{}} |
			 {noreply, Ctx::#ctx{}} |
			 {stop, Reason::atom(), Reply::term(), Ctx::#ctx{}}.

handle_call({stats, Owner} = _Req, _From, Ctx=#ctx {owners = Owners}) ->
    ?debug("~p",[_Req]),
    {reply, handle_stats(Owner, Owners), Ctx};
handle_call(dump, _From, Ctx=#ctx {buckets = T}) ->
    io:format("Ctx: Buckets = ~p.", [ets:tab2list(T)]),
    {reply, ok, Ctx};

handle_call(stop, _From, Ctx) ->
    ?debug("stop.",[]),
    {stop, normal, ok, Ctx};

handle_call(_Request, _From, Ctx) ->
    ?debug("unknown request ~p.", [_Request]),
    {reply, {error,bad_call}, Ctx}.

%%--------------------------------------------------------------------
%% @private
%% @doc
%% Handling cast messages.
%%
%% @end
%%--------------------------------------------------------------------
-type cast_msg()::
	term().

-spec handle_cast(Msg::cast_msg(), Ctx::#ctx{}) -> 
			 {noreply, Ctx::#ctx{}} |
			 {stop, Reason::term(), Ctx::#ctx{}}.

handle_cast({add, Pid, Key} = _M, Ctx=#ctx {owners = Owners}) ->
    ?debug("message ~p", [_M]),
    add_owner(Pid, Key, Owners),
    {noreply, Ctx};

handle_cast({remove, Key} = _M, Ctx=#ctx {owners = Owners}) ->
    ?debug("message ~p", [_M]),
    remove_owner(Key, Owners),
    {noreply,Ctx};

handle_cast({transfer, Key, Pid} = _M, Ctx=#ctx {owners = Owners}) ->
    ?debug("message ~p", [_M]),
    remove_owner(Key, Owners),
    add_owner(Pid, Key, Owners),
    {noreply,Ctx};

handle_cast(_Msg, Ctx) ->
    ?debug("unknown msg ~p.", [_Msg]),
    {noreply, Ctx}.

%%--------------------------------------------------------------------
%% @private
%% @doc
%% Handling all non call/cast messages.
%% 
%% @end
%%--------------------------------------------------------------------
-type info()::
	term().

-spec handle_info(Info::info(), Ctx::#ctx{}) -> 
			 {noreply, Ctx::#ctx{}} |
			 {noreply, Ctx::#ctx{}, Timeout::timeout()} |
			 {stop, Reason::term(), Ctx::#ctx{}}.

handle_info({'DOWN',Ref,process,Pid,_Reason} = _I,
	    Ctx=#ctx {owners = Owners}) ->
   ?debug("info ~p", [_I]),
    case ets_take(Owners, {Pid, Ref}) of
	[{{Pid, Ref}, Key}] ->
	    erlang:demonitor(Ref, [flush]),
	    ets:delete(?BUCKETS, {in, Key}),
	    ets:delete(?BUCKETS, {out, Key}),
	    ets:delete(Owners, Key);
	_Other ->
	    ?debug("unexpected ~p", [_Other])
    end,
    {noreply, Ctx};

handle_info(_Info, Ctx) ->
    ?debug("unknown info ~p.", [_Info]),
    {noreply, Ctx}.

%%--------------------------------------------------------------------
%% @private
%%--------------------------------------------------------------------
-spec terminate(Reason::term(), Ctx::#ctx{}) -> 
		       no_return().

terminate(_Reason, _Ctx) ->
    ?debug("terminating, reason = ~p.",[_Reason]),
    ok.
%%--------------------------------------------------------------------
%% @private
%% @doc
%% Convert process ctx when code is changed
%%
%% @end
%%--------------------------------------------------------------------
-spec code_change(OldVsn::term(), Ctx::#ctx{}, Extra::term()) -> 
			 {ok, NewCtx::#ctx{}}.

code_change(_OldVsn, Ctx, _Extra) ->
    ?debug("old version ~p.", [_OldVsn]),
    {ok, Ctx}.


%%%===================================================================
%%% Internal functions
%%%===================================================================
is_up() ->
    case ets:info(?BUCKETS) of
	Info when is_list(Info) -> true;
	undefined -> false
    end.

add_template(PolicyName, Direction, Opts) ->
    case proplists:get_value(Direction, Opts) of
	[] -> do_nothing;
	DirOpts -> add_bucket(?POLICIES, {Direction, PolicyName}, DirOpts)
    end.

add_bucket(Table, Key, Opts) ->
    Capacity = proplists:get_value(capacity, Opts),
    Rate = proplists:get_value(rate, Opts),
    Parent = proplists:get_value(parent, Opts),
    Action = proplists:get_value(action, Opts),
    Bucket = #bucket {key = Key,
		      capacity  = float(Capacity),
		      current    = float(Capacity),
		      rate = float(Rate),
		      action = Action,
		      parent = Parent,
		      timestamp = erlang_system_time_us()},
    ?debug("bucket ~p created,", [Bucket]),
    ets:insert(Table, Bucket).

new_bucket({Direction, _K} = Key, PolicyName) -> 
   case ets:lookup(?POLICIES, {Direction,PolicyName}) of
       [Policy=#bucket {capacity = C}] ->
	   ets:insert(?BUCKETS, 
		      Policy#bucket{key=Key, 
				    current = C, 
				    timestamp = erlang_system_time_us()}),
	   ?debug("bucket ~p created.", [Key]),
	   ok;
       [] -> 
	   ?warning("no policy found for ~p", [{Direction, PolicyName}]),
	   {error,no_policy}
    end.

use_tokens({in, _K} = Key, Tokens) ->
    %% Incoming data is already received so use is forced,
    %% Note that current can become negative!
    Current = ets:lookup_element(?BUCKETS, Key, #bucket.current),
    if Current - Tokens < 0 -> ?warning("bucket ~p negative.", [Key]);
       true -> ok
    end,
    ets:update_element(?BUCKETS, Key, [{#bucket.current, Current - Tokens}]),
    ok;
use_tokens({out, _K} = Key, Tokens) ->
    case ets:lookup(?BUCKETS, Key) of
	[_B=#bucket {current = Current}] when Tokens =< Current ->
	    ets:update_element(?BUCKETS, Key, 
			       [{#bucket.current, Current - Tokens}]),
	    ok;
	[_B=#bucket {action = Action}] ->
	    ?debug("not enough tokens in bucket ~p, ~p.", [Key, Action]),
	    {action, Action};
	[] ->
	    ?warning("unknown key ~p.", [Key]),
	    {error, unknown_key}
    end.

fill_bucket(B) when is_record(B, bucket) ->
    Now = erlang_system_time_us(),
    Current = B#bucket.current,
    Capacity = B#bucket.capacity,
    Tokens = if Current < Capacity ->
		     Dt = time_delta(Now, B#bucket.timestamp),
		     New = B#bucket.rate * Dt,
		     ?debug("bucket ~p tokens to fill ~p", 
				 [B#bucket.key, New]),
		erlang:min(Capacity, Current + New);
	   true ->
		Current
	end,
    ets:insert(?BUCKETS, B#bucket {current = Tokens, timestamp = Now}),
    {ok, Tokens}.
    
bucket_fill_time(B, Tokens) when is_record(B, bucket) ->
    Current = B#bucket.current,
    if Tokens < Current ->
	    {ok, 0};
       true ->
	    Ts = Tokens - Current,  %% tokens to wait for
	    Sec = Ts / B#bucket.rate, %% seconds to wait
	    ?debug("bucket ~p tokens to wait for ~p.", [B#bucket.key, Ts]),
	    ?debug("bucket ~p time to wait ~p.", [B#bucket.key, Sec]),
	    {ok, Sec}
    end.

bucket_wait(B, Tokens)  when is_record(B, bucket) ->
    {ok, Ts} = bucket_fill_time(B, Tokens),
    Tms = Ts*1000,
    Delay = trunc(Tms),
    ?debug("bucket ~p sleeping ~p ms.", [B#bucket.key, Delay]),
    if Delay < Tms ->
	    timer:sleep(Delay+1);
       Delay > 0 ->
	    timer:sleep(Delay);
       true ->
	    ok
    end.

add_owner(Pid, Key, Owners) ->
    Ref = erlang:monitor(process, Pid),
    ets:insert(Owners, {Key, {Pid, Ref}}), %% For remove, key is unique
    ets:insert(Owners, {{Pid, Ref}, Key}). %% For crash, pid is NOT unique
 
remove_owner(Key, Owners) ->
    case ets_take(Owners, Key) of
	[{Key, {_Pid, Ref} = PR}] ->
	    erlang:demonitor(Ref, [flush]),
	    ets:delete(Owners, PR);
	_Other ->
	    ?warning("unexpected owner take result ~p", [_Other])
    end.	

handle_stats(Owner, Owners) ->
    case ets:foldl(
	   fun({{Pid, _Ref}, Key}, Acc) when is_pid(Pid), Pid =:= Owner ->
		   [stats(Key) | Acc];
	      ({_Key, _PR}, Acc) ->
		   Acc
	   end, [], Owners) of
	[] -> [];
	Stats -> [{socket_stats, Stats}]
    end.

stats(Socket) ->
    case inet:getstat(Socket) of
	{ok, Stats} -> {Socket, Stats};
	_ -> [] %% Not socket??
    end.

time_delta(T1, T0) ->
    (T1 - T0) / 1000000.

opt_get_env(App, Key, Default) ->
    case application:get_env(App, Key) of
	undefined -> Default;
	{ok,Value} -> Value
    end.

erlang_system_time_us() ->
    try erlang:system_time(micro_seconds)
    catch
	error:undef ->
	    {MS,S,US} = os:timestamp(),
	    (MS*1000000+S)*1000000+US
    end.

ets_take(Tab,Key) ->
    try ets:take(Tab, Key)
    catch
	error:undef ->
	    case ets:lookup(Tab,Key) of
		[] -> [];
		Objects ->
		    ets:delete(Tab, Key),
		    Objects
	    end
    end.
