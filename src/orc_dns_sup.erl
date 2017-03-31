-module(orc_dns_sup).

-behavior(supervisor).

-export([ start_link/0, init/1 ]).

start_link() ->
	supervisor:start_link({ local, ?MODULE }, ?MODULE, []).

init([]) ->
	{ ok, { { one_for_one, 5, 10 }, [
		#{ id => orc_dns_server,
		start => { orc_dns_server, start_link, []},
		restart => permanent,
		shutdown => brutal_kill,
		type => worker,
		modules => [
			orc_dns_server,
			orc_dns_parser,
			orc_dns_message
		]}
	]}}.
	
