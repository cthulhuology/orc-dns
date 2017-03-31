-module(orc_dns_server).
-author({ "David J Goehrig", "dave@dloh.org" }).
-copyright(<<"© 2017 David J Goehrig"/utf8>>).

-export([ start_link/0, stop/0 ]).
-export([ init/1, handle_call/3, handle_cast/2, handle_info/2, terminate/2, code_change/3 ]).

-include("../include/orc_dns.hrl").

%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
%% public
%%

start_link() ->
	gen_server:start_link({ local, ?MODULE }, ?MODULE, #orc_dns_server{}, []).

stop() ->
	gen_server:call(?MODULE,stop).



%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
%% gen_server
%%

init(Server = #orc_dns_server{}) ->
	{ ok, Socket } = gen_udp:open(53, [ binary, { active, true }]),
	{ ok, Server#orc_dns_server{ socket = Socket } }.

handle_call(stop,_From,Server) ->
	{ stop, stopped, Server }; 

handle_call(Message,_From,Server) ->
	error_logger:error_msg("unknown message ~p~n", [ Message ]),
	{ reply, ok, Server }.

handle_cast(Message,Server) ->
	error_logger:error_msg("unknown message ~p~n", [ Message ]),
	{ noreply, Server }.

handle_info({ udp, Socket, IP, InPortNo, Packet },Server = #orc_dns_server{ socket = Socket }) ->
	error_logger:info_msg("got packet ~p~n", [ Packet ]),
	Message = orc_dns_parser:message(Packet),
	error_logger:info_msg("~p~n", [ Message ]),
	{ #dns_header{ id = Id }, _, _, _, _, _ } = Message,
	Response = orc_dns_message:error(Id),
	gen_udp:send(Socket,IP, InPortNo, Response),
	{ noreply, Server };

handle_info(Message,Server) ->
	error_logger:error_msg("unknown message ~p~n", [ Message ]),
	{ noreply, Server }.
	
code_change(_Old,_Extra,Server) ->
	{ ok, Server }.

terminate(_Reason,#orc_dns_server{ socket = Socket })  ->
	gen_udp:close(Socket),	
	ok.
