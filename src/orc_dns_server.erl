-module(orc_dns_server).
-author({ "David J Goehrig", "dave@dloh.org" }).
-copyright(<<"© 2017 David J Goehrig"/utf8>>).

-export([ start_link/0, stop/0 ]).
-export([ init/1, handle_call/3, handle_cast/2, handle_info/2, terminate/2, code_change/3 ]).

-include("../include/orc_dns.hrl").

-record( orc_dns_server, { udpsocket, tcpsocket, acceptor, clients = [] }).

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
	{ ok, Port } = application:get_env(orcdns,port),
	{ ok, UDPSocket } = gen_udp:open(Port, [ binary, { active, true }]),
	{ ok, TCPSocket	} = gen_tcp:listen(Port, [binary, { active, true }]),
	error_logger:info_msg("Listening on ~p~n", [ Port ]),
	Pid = spawn_link(orc_dns_client,accept,[ self(), TCPSocket ]),
	{ ok, Server#orc_dns_server{ udpsocket = UDPSocket, tcpsocket = TCPSocket, acceptor = Pid } }.

handle_call(stop,_From,Server) ->
	{ stop, stopped, Server }; 

handle_call(Message,_From,Server) ->
	error_logger:error_msg("unknown message ~p~n", [ Message ]),
	{ reply, ok, Server }.

handle_cast({accept,Socket},Server = #orc_dns_server{ clients = Clients }) ->
	error_logger:info_msg("got client ~p~n", [ Socket ]),
	{ noreply, Server#orc_dns_server{ clients = [ Socket | Clients ] }};	

handle_cast(Message,Server) ->
	error_logger:error_msg("unknown message ~p~n", [ Message ]),
	{ noreply, Server }.

handle_info({ udp, Socket, IP, InPortNo, Packet },Server = #orc_dns_server{ udpsocket = Socket }) ->
	error_logger:info_msg("got packet ~p~n", [ Packet ]),
	Message = orc_dns_parser:message(Packet),
	error_logger:info_msg("~p~n", [ Message ]),
	{ #dns_header{ id = Id }, _, _, _, _, _ } = Message,
	Response = orc_dns_message:error(Id),
	gen_udp:send(Socket,IP, InPortNo, Response),
	{ noreply, Server };

handle_info({ tcp, Socket, Packet }, Server = #orc_dns_server{ }) ->
	error_logger:info_msg("got packet ~p~n", [ Packet ]),
	{ Request, Rest } = orc_dns_parser:prefix(Packet),
	error_logger:info_msg("Rest is ~p~n", [ Rest ]),
	Message = orc_dns_parser:message(Request),
	error_logger:info_msg("~p~n", [ Message ]),
	{ #dns_header{ id = Id }, _, _, _, _, _ } = Message,
	Response = orc_dns_message:error(Id),
	Length = binary:referenced_byte_size(Response),
	gen_tcp:send(Socket,<< Length:16/big-unsigned-integer, Response/binary >>),
	{ noreply, Server };

handle_info(Message,Server) ->
	error_logger:error_msg("unknown info message ~p~n", [ Message ]),
	{ noreply, Server }.
	
code_change(_Old,_Extra,Server) ->
	{ ok, Server }.

terminate(_Reason,#orc_dns_server{ udpsocket = UDPSocket, tcpsocket = TCPSocket })  ->
	gen_udp:close(UDPSocket),	
	gen_tcp:close(TCPSocket),	
	ok.
