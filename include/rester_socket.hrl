-ifndef(_RESTER_SOCKET_HRL_).
-define(_RESTER_SOCKET_HRL_, true).

-record(rester_socket,
	{
	  mdata,        %% data module  (e.g gen_tcp, ssl ...)
	  mctl,         %% control module  (e.g inet, ssl ...)
	  protocol=[],  %% [tcp|ssl|http] 
	  version,      %% Http version in use (1.0/keep-alive or 1.1)
	  transport,    %% ::port()  - transport socket
	  socket,       %% ::port() || Pid/Port/SSL/ etc
	  active=false, %% ::boolean() is active
	  mode=list,    %% :: list|binary 
	  packet=0,     %% packet mode
	  opts = [],    %% extra options
	  tags = {data,close,error}   %% data tags used
	}).

-type rester_socket() :: #rester_socket{}.

-endif.
