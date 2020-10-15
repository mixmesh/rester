%%% @author Tony Rogvall <tony@rogvall.se>
%%% @copyright (C) 2020, Tony Rogvall
%%% @doc
%%%    general socket server
%%% @end
%%% Created : 15 Oct 2020 by Tony Rogvall <tony@rogvall.se>

-module(rester_socket_server).

-behaviour(gen_server).

%% API
-export([start_link/5, start_link/6]).
-export([start/5, start/6]).
-export([stop/1]).
-export([reusable_sessions/1]).

%% gen_server callbacks
-export([init/1, 
	 handle_call/3, 
	 handle_cast/2, 
	 handle_info/2,
	 terminate/2, 
	 code_change/3]).

-export([behaviour_info/1]).

-include("../include/rester.hrl").
-include("../include/rester_socket.hrl").

%% -define(debug(Fmt,Args), ok).
%% -define(error(Fmt,Args), error_logger:format(Fmt, Args)).

-define(SERVER, ?MODULE). 

-record(state, {
	  listen,    %% #rester_socket{}
	  active,    %% default active mode for socket
	  socket_reuse = none,  %% 'none' | #reuse{}
	  inet_ref,  %% prim_inet internal accept ref number
	  resource,  %% rester_resource reference
	  module,    %% session module
	  args       %% session init args
	 }).

-record(reuse, {
	  mode,
	  port,
	  sessions = dict:new(),
	  session_pids = dict:new(),
	  state
	 }).

-define(RESTER_DEFAULT_ACCEPT_TIMEOUT, 5000).

%%%===================================================================
%%% API
%%%===================================================================
%%--------------------------------------------------------------------
%% @doc
%% The plugin behaviour:<br/>
%% <ul>
%% <li>init(Socket::socket(), Args::[term()] <br/>
%%   -> {ok,NewState::state()} | <br/>
%%      {stop,Reason::term(),NewState::state()}<br/></li>
%% <li>data(Socket::socket(), Data::io_list(), State::state()) <br/>
%%   -> {ok,NewState::state()}|<br/>
%%      {close,NewState::state()}|<br/>
%%      {stop,Reason::term(),NewState::state()}<br/></li>
%% <li>close(Socket::socket(), State::state())<br/>
%%   -> {ok,state()}<br/></li>
%% <li>error(Socket::socket(),Error::error(), State::state())<br/>
%%   -> {ok,NewState::state()} | <br/>
%%      {stop,Reason::term(),NewState::state()}<br/></li>
%% <li>control(Socket::socket(), Request::term(), From::term(), State::state())<br/>
%%   -> {reply, Reply::term(),NewState::state()} | <br/>
%%      {noreply, NewState::state()} |<br/>
%%      {ignore, NewState::state()} | <br/>
%%      {send, Bin::binary(), NewState::state()} |<br/>
%%      {data, Data::term(), NewState::state()} |<br/>
%%      {stop, Reason::term(),NewState::state()}<br/></li>
%% <li>info(Socket::socket(), Data::io_list(), State::state()) <br/>
%%   -> {ok,NewState::state()}|<br/>
%%      {close,NewState::state()}|<br/>
%%      {stop,Reason::term(),NewState::state()}<br/></li>
%% </ul>
%% @end
%%--------------------------------------------------------------------
-spec behaviour_info(callbacks) -> list().
behaviour_info(callbacks) ->
    [
     {init,  2},  %% init(Socket::socket(), Args::[term()] 
                  %%   -> {ok,state()} | {stop,reason(),state()}
     {data,  3},  %% data(Socket::socket(), Data::io_list(), State::state()) 
                  %%   -> {ok,state()}|{close,state()}|{stop,reason(),state()}
     {close, 2},  %% close(Socket::socket(), State::state())
                  %%   -> {ok,state()}
     {error, 3},  %% error(Socket::socket(),Error::error(), State:state())
                  %%   -> {ok,state()} | {stop,reason(),state()}
     {control, 4},%% control(Socket::socket(), Request::term(), 
                  %%         From::term(), State:state())
                  %%   -> {reply, Reply::term(),state()} | {noreply, state()} |
                  %%      {ignore, state()} | {send, Bin::binary(), state()} |
                  %%      {data, Data::trem()} |{stop,reason(),state()}
     {info,  3}   %% data(Socket::socket(), Data::io_list(), State::state()) 
                  %%   -> {ok,state()}|{close,state()}|{stop,reason(),state()}
    ];
behaviour_info(_Other) ->
    undefined.

%%--------------------------------------------------------------------
%% @doc
%% Starts the server
%% @end
%%--------------------------------------------------------------------
start_link(Port, Protos, Options, Module, SessionOptions) ->
    gen_server:start_link(?MODULE, 
			  [Port,Protos,Options,Module,SessionOptions],
			  []).

start_link(ServerName, Protos, Port, Options, Module, SessionOptions) ->
    gen_server:start_link(ServerName, 
			  ?MODULE, 
			  [Port,Protos,Options,Module,SessionOptions], 
			  []).

start(Port, Protos, Options, Module, SessionOptions) ->
    gen_server:start(?MODULE, 
		     [Port,Protos,Options,Module,SessionOptions], 
		     []).

start(ServerName, Protos, Port, Options, Module, SessionOptions) ->
    gen_server:start(ServerName, 
		     ?MODULE, 
		     [Port,Protos,Options,Module,SessionOptions], 
		     []).

%%--------------------------------------------------------------------
%% @doc
%% Stops the server identified by pid or servername.
%% @end
%%--------------------------------------------------------------------
-spec stop(Server::atom() | pid()) -> ok | {error, Error::term()}.

stop(Server) when is_atom(Server);
		  is_pid(Server) ->
    gen_server:call(Server, stop).


%%--------------------------------------------------------------------
-spec reusable_sessions(Process::pid() | atom()) ->
	   list({{IpAddress::tuple(), Port::integer}, Pid::pid}).

reusable_sessions(P) ->
    gen_server:call(P, reusable_sessions).

%%%===================================================================
%%% gen_server callbacks
%%%===================================================================

%%--------------------------------------------------------------------
%% @private
%% @doc
%% Initializes the server
%%
%% @spec init(Args) -> {ok, State} |
%%                     {ok, State, Timeout} |
%%                     ignore |
%%                     {stop, Reason}
%% @end
%%--------------------------------------------------------------------
init([Port,Protos,Options,Module,SessionOptions] = _X) ->
    ?log_debug("~p: init(~p)", [?MODULE, _X]),
    Active = proplists:get_value(active, Options, true),
    ReuseMode = proplists:get_value(reuse_mode, Options, none),
    Options1 = proplists:delete(reuse_mode, proplists:delete(active, Options)),
    Reuse = case ReuseMode of
		none -> none;
		_ when ReuseMode =:=client; ReuseMode =:= server ->
		    {ok, RUSt} = Module:reuse_init(ReuseMode, SessionOptions),
		    #reuse{mode = ReuseMode,
			   port = Port,
			   state = RUSt}
	    end,
    case rester_socket:listen(Port,Protos,Options1) of
	{ok,Listen} ->
	    %% Acquire resource for first connection
	    Resource = make_ref(),
	    rester_resource:acquire_async(Resource, infinity),
	    ?log_debug("~p: listening", [?MODULE]),
	    {ok, #state{ listen = Listen, 
			 active = Active, 
			 socket_reuse = Reuse,
			 resource = Resource,
			 module = Module, 
			 args = SessionOptions
		       }};
	{error,Reason} ->
	    {stop,Reason}
    end.

%%--------------------------------------------------------------------
%% @private
%% @doc
%% Handling call messages. <br/>
%%
%% @end
%%--------------------------------------------------------------------
-spec handle_call(Request::term(), 
		  From::{pid(), Tag::term()}, 
		  State::#state{}) ->
			 {reply, Reply::term(), State::#state{}} |
			 {noreply, State::#state{}} |
			 {stop, Reason::atom(), Reply::term(), State::#state{}}.

handle_call({get_session, Host, Port, Opts} = _Req, From,
	    #state{socket_reuse = Reuse} = State) ->
    ?log_debug("~p: ~p~n", [?MODULE, _Req]),
    Key = {Host, Port},
    case Reuse of
	none ->
	    {reply, connect, State};
	#reuse{mode = client, sessions = Sessions,
	       session_pids = Pids} = R ->
	    case dict:find(Key, Sessions) of
		error ->
		    ConnPid = start_connector(Host, Port, Opts, self(), State),
		    Sessions1 = dict:store(Key, {ConnPid, [From]}, Sessions),
		    Pids1 = dict:store(ConnPid, Key, Pids),
		    R1 = R#reuse{sessions = Sessions1,
				 session_pids = Pids1},
		    {noreply, State#state{socket_reuse = R1}};
		{ok, Pid} when is_pid(Pid) ->
		    {reply, Pid, State};
		{ok, {CPid, Pending}} ->
		    Sessions1 = dict:store(
				  Key, {CPid, [From|Pending]}, Sessions),
		    R1 = R#reuse{sessions = Sessions1},
		    {noreply, State#state{socket_reuse = R1}}
	    end;
	#reuse{mode = server, sessions = Sessions} ->
	    case dict:find(Key, Sessions) of
		error ->
		    %% server never initiates connection when in reuse mode
		    {reply, rejected, State};
		{ok, Pid} when is_pid(Pid) ->
		    {reply, Pid, State}
	    end
    end;
handle_call(reusable_sessions, _From, #state{socket_reuse = R} = State) ->
    case R of
	#reuse{sessions = Sessions} ->
	    {reply, dict:to_list(Sessions), State};
	_ ->
	    {reply, [], State}
    end;
handle_call(stop, _From, State) ->
    ?log_debug("stop", []),
    {stop, normal, ok, State};
handle_call(_Request, _From, State) ->
    ?log_debug("unknown request ~p.", [_Request]),
    {reply, {error, bad_call}, State}.

%%--------------------------------------------------------------------
%% @private
%% @doc
%% Handling cast messages
%%
%% @spec handle_cast(Msg, State) -> {noreply, State} |
%%                                  {noreply, State, Timeout} |
%%                                  {stop, Reason, State}
%% @end
%%--------------------------------------------------------------------
handle_cast(_Msg, State) ->
    ?log_debug("unknown msg ~p.", [_Msg]),
    {noreply, State}.

%%--------------------------------------------------------------------
%% @private
%% @doc
%% Handling all non call/cast messages
%%
%% @spec handle_info(Info, State) -> {noreply, State} |
%%                                   {noreply, State, Timeout} |
%%                                   {stop, Reason, State}
%% @end
%%--------------------------------------------------------------------
handle_info({resource, ok, Resource}, 
	    State=#state {resource = Resource, listen = Listen}) ->
    NewAccept = rester_socket:async_accept(Listen),
    %% Create the socket_session process
    case NewAccept of
	{ok, Ref} -> {noreply, State#state {inet_ref = Ref}};
	{error, Reason} -> {stop, Reason, State}
    end;

handle_info({resource, error, Reason}, State) ->
    ?log_error("resource acquire failed, reason ~p",[Reason]),
    {stop, Reason, State};

handle_info({inet_async, LSocket, Ref, {ok,Socket}} = _Msg, 
	    State=#state {inet_ref = Ref, resource = Resource}) 
  when (State#state.listen)#rester_socket.socket =:= LSocket ->
    ?log_debug("<-- ~p~n", [_Msg]),
    Listen = State#state.listen,
    Pid = proc_lib:spawn(fun() -> 
				 create_socket_session(Listen, Socket, State) 
			 end),
    inet:tcp_controlling_process(Socket, Pid),
    %% Turn over control to socket session
    rester_resource:transfer(Resource, Pid),
    Pid ! controlling,
    %% Acquire resource for next connection
    NewResource = make_ref(),
    rester_resource:acquire_async(NewResource, infinity),
    {noreply, State#state {resource = NewResource}};

%% handle {ok,Socket} on bad ref ?
handle_info({inet_async, _LSocket, Ref, {error,Reason}} = _Msg, 
	    State=#state {inet_ref = Ref}) ->
    ?log_debug("~p: ~p~n", [?MODULE, _Msg]),
    %% Resource already acquired
    case rester_socket:async_accept(State#state.listen) of
	{ok,Ref} ->
	    {noreply, State#state { inet_ref = Ref }};
	{error, Reason} ->
	    {stop, Reason, State}
	    %% {noreply, State#state { inet_ref = undefined }}
    end;
handle_info({Pid, ?MODULE, connected, Host, Port} = _Msg,
	    #state{socket_reuse = #reuse{sessions = Sessions} = R} = State) ->
    ?log_debug("~p: ~p~n", [?MODULE, _Msg]),
    Session = dict:fetch(Key = {Host, Port}, Sessions),
    case Session of
	{_, Pending} ->
	    [gen_server:reply(From, Pid) || From <- Pending];
	_ -> ok
    end,
    Sessions1 = dict:store(Key, Pid, Sessions),
    %% Pids = dict:store(Pid, {Host,Port}, R#reuse.session_pids),
    R1 = R#reuse{sessions = Sessions1},
    {noreply, State#state{socket_reuse = R1}};
handle_info({Pid, reuse, Config} = _Msg,
	    #state{socket_reuse = #reuse{mode = server,
					 sessions = Sessions,
					 session_pids = Pids} = R} = State) ->
    ?log_debug("~p: ~p~n", [?MODULE, _Msg]),
    {_, Port} = lists:keyfind(port, 1, Config),
    case [H || {host, H} <- Config] of
	[Host|_] ->
	    %% we could possibly handle aliases, and thus multiple host names
	    Key = {Host, Port},
	    Sessions1 = dict:store(Key, Pid, Sessions),
	    Pids1 = dict:store(Pid, Key, Pids),
	    R1 = R#reuse{sessions = Sessions1, session_pids = Pids1},
	    {noreply, State#state{socket_reuse = R1}};
	_Other ->
	    ?log_error("strange reuse config: ~p~n", [_Other]),
	    {noreply, State}
    end;
handle_info({'DOWN', _, process, Pid, _},
	    #state{socket_reuse = #reuse{sessions = Sessions,
					 session_pids = Pids} = R} = State) ->
    ?log_debug("~p got DOWN - Pid = ~p~n"
	   "Sessions = ~p~n"
	   "Pids = ~p~n", [?MODULE, Pid, dict:to_list(Sessions),
			   dict:to_list(Pids)]),
    case dict:find(Pid, Pids) of
	error ->
	    {noreply, State};
	{ok, {_Host,_Port} = Key} ->
	    Session = dict:fetch(Key, Sessions),
	    case Session of
		{_, Pending} ->
		    [gen_server:reply(From, rejected) || From <- Pending];
		_ -> ok
	    end,
	    Sessions1 = dict:erase(Key, Sessions),
	    Pids1 = dict:erase(Pid, Pids),
	    R1 = R#reuse{sessions = Sessions1, session_pids = Pids1},
	    {noreply, State#state{socket_reuse = R1}}
    end;
handle_info(_Info, State) ->
    ?log_debug("unknown info ~p.", [_Info]),
    {noreply, State}.

%%--------------------------------------------------------------------
%% @private
%% @doc
%% This function is called by a gen_server when it is about to
%% terminate. It should be the opposite of Module:init/1 and do any
%% necessary cleaning up. When it returns, the gen_server terminates
%% with Reason. The return value is ignored.
%%
%% @spec terminate(Reason, State) -> void()
%% @end
%%--------------------------------------------------------------------
terminate(_Reason, State=#state {resource = Resource}) ->
    ?log_debug("terminating, reason ~p.", [_Reason]),
    rester_resource:release(Resource), %% last acquired
    rester_resource:release(init), %% listen socket
    rester_socket:close(State#state.listen),
    ok.

%%--------------------------------------------------------------------
%% @private
%% @doc
%% Convert process state when code is changed
%%
%% @spec code_change(OldVsn, State, Extra) -> {ok, NewState}
%% @end
%%--------------------------------------------------------------------
code_change(_OldVsn, State, _Extra) ->
    ?log_debug("code change, old version ~p.", [_OldVsn]),
    {ok, State}.

%%%===================================================================
%%% Internal functions
%%%===================================================================
create_socket_session(Listen, Socket, State) ->
    receive
	controlling ->  %% control sync
	    case rester_socket:async_socket(Listen, Socket,
					    ?RESTER_DEFAULT_ACCEPT_TIMEOUT) of
		{ok, XSocket} ->
		    {ok,XState0} = 
			rester_socket_session:init([XSocket,
						 State#state.module,
						 State#state.args]),
		    activate_session(State, XState0);
		_Error ->
		    ?log_debug("no socket session, "
				"async_socket call failed, reason ~p",
				[_Error]),
		    error
	    end
    after 3000 ->
	    ?log_warning("parent did not pass over control"),
	    error
    end.

activate_session(State, XState0) ->
    case rester_socket_session:handle_cast(
	   {activate, State#state.active}, XState0) of
	{noreply, XState1, TimeOut} ->
	    gen_server:enter_loop(rester_socket_session, [], XState1, TimeOut);
	{noreply, XState1} ->
	    gen_server:enter_loop(rester_socket_session, [], XState1)
    end.

start_connector(Host, Port, ConnArgs, Parent,
		#state{module = M, args = Args, active = Active,
		       socket_reuse = #reuse{port = MyPort,
					     state = RUSt}}) ->
    F = fun() ->
		case open_reuse_connector(Host, Port, ConnArgs) of
		    {ok, XSocket} ->
			send_reuse_message(
			  Host, Port, Args, M, MyPort, XSocket, RUSt),
			case rester_socket_session:init(
			       [XSocket, M, Args]) of
			    {ok, XSt} ->
				{noreply, XSt1} =
				    rester_socket_session:handle_cast(
				      {activate, Active}, XSt),
				Parent ! {self(), ?MODULE, connected,
					  Host, Port},
				gen_server:enter_loop(
				  rester_socket_session, [], XSt1);
			    {error, InitError} ->
				exit({InitError, [{rester_socket_session,init}]})
			end;
		    {error, ConnectError} ->
			exit({ConnectError, [{rester_socket, connect}]})
		end
	end,
    Pid = proc_lib:spawn(F),
    erlang:monitor(process, Pid),
    Pid.

open_reuse_connector(Host, Port, [Protos, Opts, Timeout]) ->
    rester_socket:connect(Host, Port, Protos, Opts, Timeout);
open_reuse_connector(Host, Port, [Protos, Opts]) ->
    rester_socket:connect(Host, Port, Protos, Opts).


send_reuse_message(Host, Port, Args, M, MyPort, XSocket, RUSt) ->
    ReuseOpts = M:reuse_options(Host, Port, Args, RUSt),
    ReuseMsg = rester_socket_session:encode_reuse(
		 MyPort, ReuseOpts),
    rester_socket:send(XSocket, ReuseMsg).

