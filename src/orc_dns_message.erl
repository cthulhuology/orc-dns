-module(orc_dns_message).
-author({ "David J Goehrig", "dave@dloh.org" }).
-copyright(<<"© 2017 David J Goehrig"/utf8>>).

-export([ error/1 ]).

%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
%%

error(Id) ->
	Query = 1,
	Opcode = 2,
	AA = 1,
	Truncated = 0,
	RD = 0,
	RA = 0,
	Z = 0,
	RCode = 4,
	QDCount = 0,
	ANCount = 0,
	NSCount = 0,
	ARCount = 0,
	<< Id:16/big-unsigned-integer, Query:1,
	Opcode:4, AA:1, Truncated:1,
	RD:1, RA:1, Z:3, RCode:4,
	QDCount:16/big-unsigned-integer,
	ANCount:16/big-unsigned-integer,
	NSCount:16/big-unsigned-integer,
	ARCount:16/big-unsigned-integer >>.

	
