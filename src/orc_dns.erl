-module(orc_dns).
-author({ "David J Goehrig", "dave@dloh.org" }).
-copyright(<<"© 2017 David J Goehrig"/utf8>>).


resource_record(<< 	
	Name:16/big-unsigned-integer, 
	Type:16/big-unsigned-integer, 
	Class:16/big-unsigned-integer,
	TTL:32/big-signed-integer,
	RDLength:16/big-unsigned-integer,
	RDData:RDLength/binary >>) ->
	{ Name, Type, Class, TTL, RDLength, RDData }.

record_type(1) -> a;		%% a host address
record_type(2) -> ns;		%% name server 
record_type(3) -> md;		%% mail destination	(deprecated)
record_type(4) -> mf;		%% mail forwarder 	(deprecated)
record_type(5) -> cname;	%% cannonical name
record_type(6) -> soa;		%% start of authority
record_type(7) -> mb;		%% mail box 		(exp)
record_type(8) -> mg;		%% mail gruop		(exp)
record_type(9) -> mr;		%% mail rename		(exp)
record_type(10) -> null;	%% null 		(exp)
record_type(11) -> wks;		%% well known service	(exp)
record_type(12) -> ptr;		%% domain name pointer
record_type(13) -> hinfo;	%% host information
record_type(14) -> minfo;	%% mailbox infor
record_type(15) -> mx;		%% mail exchange
record_type(16) -> txt;		%% text string

%% query types
record_type(252) -> axfr;	%% request for full zone transfer
record_type(253) -> mailb;	%% request for mail records mb,mg,mr
record_type(254) -> maila;	%% request for mail agent (deprecated)
record_type(255) -> '*';	%% request for all records
record_type(_) -> unknown.


class(1) -> in;			%% internet
class(2) -> cs;			%% csnet (deprecated)
class(3) -> ch;			%% chaos
class(4) -> hs;			%% hesiod [Dyer 87]

%%
class(255) -> '*';		%% any class
class(_) -> unknown.


rdata(<< Len:8/unsigned-integer, Data:Len/binary, Rest/binary >>) ->
	io:format("Data: ~p, Rest: ~p~n", [ Data, Rest ]),
	{ Data, Rest }.
	
cname_rdata(Bin) ->
	{ Name, _ } = rdata(Bin),
	Name.

hinfo_rdata(Bin) ->
	{ CPU, Rest } = rdata(Bin),
	{ OS, _ } = rdata(Rest),
	{ CPU, OS }.

mx_rdata(<< Preference:16/big-unsigned-integer, Len:8/unsigned-integer, Exchange:Len/binary >>) ->
	{ Preference, Exchange }.

ns_rdata(Bin) ->
	{ NSDNAME, _ } = rdata(Bin),
	NSDNAME.

ptr_rdata(Bin) ->
	{ PTRDNAME, _ } = rdata(Bin),
	PTRDNAME.

soa_rdata(Bin) ->
	{ MName, MRest } = rdata(Bin),
	{ RName, RRest } = rdata(MRest),
	<< Serial:32/big-unsigned-integer, Refresh:32/big-unsigned-integer, Retry:32/big-unsigned-integer,
	Expire:32/big-unsigned-integer, Minimum:32/big-unsigned-integer >> = RRest,
	{ MName, RName, Serial, Refresh, Retry, Expire, Minimum }.

txt_rdata(Bin) ->
	


	

