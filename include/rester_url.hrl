-ifndef(_RESTER_URL_HRL_).
-define(_RESTER_URL_HRL_, true).

-record(url,
	{
	  scheme,
	  host,
	  port,            %% undefined means not set
	  path = "",
	  querypart = ""
	 }). 

-endif.

