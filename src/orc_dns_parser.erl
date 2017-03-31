-module(orc_dns_parser).
-author({ "David J Goehrig", "dave@dloh.org" }).
-copyright(<<"© 2017 David J Goehrig"/utf8>>).

-export([ message/1, cname/1, a/1, aaaa/1, mx/1, soa/1, txt/1, ns/1, wks/1, hinfo/1, ptr/1, test/0 ]).

-include("../include/orc_dns.hrl").

%% for reference https://www.iana.org/assignments/dns-parameters/dns-parameters.xhtml
%%
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
record_type(17) -> rp;		%% responsible person
record_type(18) -> afsdb;	%% andrew file system database
record_type(19) -> x25;		%% x.25 psdn addr
record_type(20) -> isdn;	%% isdn addr
record_type(21) -> rt;		%% route through 
record_type(22) -> nsap;	%% nsap addr http://www.iana.org/go/rfc1706
record_type(23) -> nasptr;	%% nsap ptr
record_type(24) -> sig;		%% security signature http://www.iana.org/go/rfc3008
record_type(25) -> key;		%% security key http://www.iana.org/go/rfc3110
record_type(26) -> x400;	%% X.400 mail mapping information
record_type(27) -> gpos;	%% geo pos https://tools.ietf.org/html/rfc1712 
record_type(28) -> aaaa;	%% ipv6 addr http://www.iana.org/go/rfc3596
record_type(29) -> loc;		%% http://www.iana.org/go/rfc1876
record_type(30) -> nxt;		%% next domain 		(deprecated)
record_type(31) -> eid;		%% endpoint locator http://ana-3.lcs.mit.edu/~jnc/nimrod/dns.txt
record_type(32) -> nimloc;	%% nimrod locator http://ana-3.lcs.mit.edu/~jnc/nimrod/dns.txt
record_type(33) -> srv;		%% service selector http://www.iana.org/go/rfc2782
record_type(34) -> atma;	%% ATM addres
record_type(35) -> naptr;	%% naming authority pointer http://www.iana.org/go/rfc3403
record_type(36) -> kx;		%% key exchanger http://www.iana.org/go/rfc2230
record_type(37) -> cert;	%% cert http://www.iana.org/go/rfc4398
record_type(38) -> a6;		%% obsolete see aaaa
record_type(39) -> dname;	%% dns subtree redirect http://www.iana.org/go/rfc6672
record_type(40) -> sink;	%% sink http://tools.ietf.org/html/draft-eastlake-kitchen-sink
record_type(41) -> opt;		%% http://www.iana.org/go/rfc4398
record_type(42) -> apl;		%% address prefix list https://tools.ietf.org/html/rfc3123
record_type(43) -> ds;		%% delegation signer http://www.iana.org/go/rfc4034
record_type(44) -> sshfp;	%% ssh key fingerprint http://www.iana.org/go/rfc4255
record_type(45) -> ipseckey;	%% ipsec key http://www.iana.org/go/rfc4025
record_type(46) -> rrsig;	%% http://www.iana.org/go/rfc4034
record_type(47) -> nsec;	%% "
record_type(48) -> dnskey;	%% "
record_type(49) -> dhcid;	%% http://www.iana.org/go/rfc4701
record_type(50) -> nsec3;	%% http://www.iana.org/go/rfc5155
record_type(51) -> nsec3param;  %% "
record_type(52) -> tlsa;	%% http://www.iana.org/go/rfc6698 dane tlsa 
record_type(53) -> smimea;	%% S/MIME association cert
% 54 unassigned
record_type(55) -> hip;		%% host identity protocol
record_type(56) -> ninfo;	%% 
record_type(57) -> rkey;
record_type(58) -> talink;	%% trust anchor link 
record_type(59) -> cds;		%% child ds http://www.iana.org/go/rfc7344
record_type(60) -> cdnskey;	%% "
record_type(61) -> openpgpkey;	%% http://www.iana.org/go/rfc7929
record_type(62) -> csync;	%% http://www.iana.org/go/rfc7477
%% 64-98 unassigned
record_type(99) ->  spf;	%% http://www.iana.org/go/rfc7208
record_type(100) -> uinfo;
record_type(101) -> uid;
record_type(102) -> gid;
record_type(103) -> unspec;
record_type(104) -> nid;	%% http://www.iana.org/go/rfc6742 ILNP
record_type(105) -> l32;	%% "
record_type(106) -> l64;	%% "
record_type(107) -> lp; 	%% "
record_type(108) -> eui48;	%% http://www.iana.org/go/rfc7043 mac address !!!
record_type(109) -> eui64;	%% "
%% 110 - 248 unassigned
%%
%% query types
record_type(249) -> tkey;	%% transaction key http://www.iana.org/go/rfc2930
record_type(250) -> tsig;	%% transaction sig http://www.iana.org/go/rfc2845
record_type(251) -> ixfr;	%% incremental transfer http://www.iana.org/go/rfc1995
record_type(252) -> axfr;	%% request for full zone transfer http://www.iana.org/go/rfc5936
record_type(253) -> mailb;	%% request for mail records mb,mg,mr
record_type(254) -> maila;	%% request for mail agent (deprecated)
record_type(255) -> '*';	%% request for all records
record_type(256) -> uri;	%% uri http://www.iana.org/go/rfc7553
record_type(257) -> caa;	%% ca restriction http://www.iana.org/go/rfc6844
record_type(258) -> avc;	%% application visibility control  https://www.iana.org/assignments/dns-parameters/AVC/avc-completed-template
record_type(32768) -> ta;	%% trust authority http://www.watson.org/~weiler/INI1999-19.pdf
record_type(32769) -> dlv;	%% dnssec lookaside http://www.iana.org/go/rfc4431
record_type(_) -> unassigned.

%%  
class(1) -> in;			%% internet
class(2) -> cs;			%% csnet (deprecated)
class(3) -> ch;			%% chaos
class(4) -> hs;			%% hesiod [Dyer 87]

%%
class(255) -> '*';		%% any class
class(_) -> unassigned.

%% https://www.iana.org/assignments/protocol-numbers/protocol-numbers.xhtml
ip_protocol(0) -> hopopt;	%% ipv6 hop-by-hop option
ip_protocol(1) -> icmp;		%% internet control message
ip_protocol(2) -> igmp;		%% internet group management
ip_protocol(3) -> ggp;		%% gateway-gateway protocol
ip_protocol(4) -> ipv4;		%% ipv4 encapsulation http://www.iana.org/go/rfc2003
ip_protocol(5) -> st;		%% stream http://www.iana.org/go/rfc1819
ip_protocol(6) -> tcp;
ip_protocol(8) -> egp;		%% exterior gateway protocol
ip_protocol(9) -> igp;		%% interior gateway protocol (any non-standard)
ip_protocol(10) -> bbnrccmon;	%% 
ip_protocol(11) -> nvp2;	%% network voice protocl http://www.iana.org/go/rfc741
ip_protocol(12) -> pup;		%% PARC universal packet protocol
ip_protocol(13) -> argus;	%% deprecated
ip_protocol(14) -> emcon;	%% wtf? mystery contact? emission control protocol 
%% 				https://tools.ietf.org/html/draft-riechmann-multicast-emcon-00
ip_protocol(15) -> xnet;	%% cross net debugger
ip_protocol(16) -> chaos;	%% chaos
ip_protocol(17) -> udp;
ip_protocol(18) -> mux;		%% multiplexing
ip_protocol(19) -> dcnmeas;	%% dcn measurement 
ip_protocol(20) -> hmp;		%% host monitoring protocl
ip_protocol(21) -> prm;		%% packet radio measurement
ip_protocol(22) -> xnsidp;	%% xerox ns idp
ip_protocol(23) -> trunk1;
ip_protocol(24) -> trunk2;
ip_protocol(25) -> leaf1;
ip_protocol(26) -> leaf2;
ip_protocol(27) -> rdp;		%% "reliable" datagram protocol http://www.iana.org/go/rfc908
ip_protocol(28) -> irtp;	%% internet "reliable" transaction http://www.iana.org/go/rfc938
ip_protocol(29) -> isotp4;	%% iso transport protocol class 4
ip_protocol(30) -> netblt;	%% bulk data transfer protocl http://www.iana.org/go/rfc969
ip_protocol(31) -> mfensp;	%% 
ip_protocol(32) -> meritinp;	%% 
ip_protocol(33) -> dccp;	%% datagram congrestion control protocol http://www.iana.org/go/rfc4340
ip_protocol(34) -> '3pc';	%% third party connection protocol
ip_protocol(35) -> idpr;	%% inter-domain policy routing 
ip_protocol(36) -> xtp;		%% 
ip_protocol(37) -> ddp;		%% datagram delivery protocol
ip_protocol(38) -> idprcmtp;	%% idpr control message transport protocol
ip_protocol(39) -> 'tp++';	%% tp++ transport protocol
ip_protocol(40) -> il;		%% il transport protocol
ip_protocol(41) -> ipv6;	%% ipv6 encapsulation
ip_protocol(42) -> sdrp;	%% source demand routing protocl
ip_protocol(43) -> ipv6route;	%% ipv6 routing header
ip_protocol(44) -> ipv6frag;	%% ipv6 fragment header
ip_protocol(45) -> idrp;	%% inter-domain routing protocol
ip_protocol(46) -> rsvp;	%% reservation protocol QoS
ip_protocol(47) -> gre;		%% pptp over gre
ip_protocol(48) -> dsr;		%% dynamic source routing protocl
ip_protocol(49) -> bna;		%% 
ip_protocol(50) -> esp;		%% encapsulation security payload over ip sec
ip_protocol(51) -> ah; 		%% authentication header over ip sec
ip_protocol(52) -> inlsp;	%% 
ip_protocol(53) -> swipe;	%% deprecated
ip_protocol(66) -> rvd;		%% MIT virtual disk
ip_protocol(88) -> igmp;	%% internet group management protocol
ip_protocol(89) -> ospf;	%% open shortest path first
ip_protocol(90) -> spriterpc;
ip_protocol(91) -> larp;
ip_protocol(92) -> mtp;		%% multicast transport protocol 
ip_protocol(93) -> ax25;
ip_protocol(94) -> ipip;
ip_protocol(95) -> micp;
ip_protocol(96) -> sccsp;
ip_protocol(97) -> etherip;	%% http://www.iana.org/go/rfc3378
ip_protocol(98) -> encap;
ip_protocol(99) -> private_encryption;	%% private encryption scheme
ip_protocol(100) -> gmtp;	
ip_protocol(101) -> ifmp;
ip_protocol(102) -> pnni;
ip_protocol(103) -> pim;	%% protocol independent multicast http://www.iana.org/go/rfc7761
ip_protocol(104) -> aris;
ip_protocol(105) -> scps;
ip_protocol(106) -> qnx;
ip_protocol(107) -> an;
ip_protocol(108) -> ipcomp;	%% ip compresion protocol http://www.iana.org/go/rfc2393
ip_protocol(109) -> snp;
ip_protocol(110) -> compaqpeer;
ip_protocol(111) -> ipxinip;
ip_protocol(112) -> vrrp;	%% virtual router redundancy protocol http://www.iana.org/go/rfc5798
ip_protocol(113) -> pgm;
ip_protocol(114) -> zerohop;	%% any 0 hop protocol 
ip_protocol(115) -> l2tp;	%% layer 2 tunneling http://www.iana.org/go/rfc3931
ip_protocol(116) -> ddx;
ip_protocol(117) -> iatp;
ip_protocol(118) -> stp;	%% schedule transfer protocol
ip_protocol(119) -> srp;	%% spectralink radio protocol
ip_protocol(120) -> uti;
ip_protocol(121) -> smp;	%% simple message protocol http://rdos.net/smp/
ip_protocol(122) -> sm;		%% simple multicast deprecated
ip_protocol(123) -> ptp;
ip_protocol(124) -> isis;
ip_protocol(125) -> fire;
ip_protocol(126) -> crtp;	%% combat radio protocol
ip_protocol(127) -> crudp;	%% combat radio user datagram
ip_protocol(128) -> sscopmce;	
ip_protocol(129) -> iplt;
ip_protocol(130) -> sps;
ip_protocol(131) -> pipe;
ip_protocol(132) -> sctp;	%% stream control transmission protocol
ip_protocol(133) -> fc;		%% fibre channel
ip_protocol(134) -> rsvpe2eignore;	%% http://www.iana.org/go/rfc3175
ip_protocol(135) -> mobility;	%% mobility header http://www.iana.org/go/rfc6275
ip_protocol(136) -> udplite;	%% http://www.iana.org/go/rfc3828
ip_protocol(137) -> mplsinip;	%% 
ip_protocol(138) -> manet;
ip_protocol(139) -> hip; 	%% host identity protocol http://www.iana.org/go/rfc7401
ip_protocol(140) -> shim6;	%% http://www.iana.org/go/rfc5533
ip_protocol(141) -> wesp;	%% http://www.iana.org/go/rfc5840
ip_protocol(142) -> rohc;	%% "robust" header compression ip sec http://www.iana.org/go/rfc5858
ip_protocol(253) -> experiment; %% experimental & testing
ip_protocol(254) -> experiment;	%% experimental & testing
ip_protocol(255) -> reserved;	%% reserved
ip_protocol(_) -> unassigned.	%% if we missed it :)

%% RData parsers
rdata(<< Len:8/unsigned-integer, Data:Len/binary, Rest/binary >>) ->
	io:format("Data: ~p, Rest: ~p~n", [ Data, Rest ]),
	{ Data, Rest }.
	
cname(Bin) ->
	{ Name, _ } = rdata(Bin),
	Name.

hinfo(Bin) ->
	{ CPU, Rest } = rdata(Bin),
	{ OS, _ } = rdata(Rest),
	{ CPU, OS }.

mx(<< Preference:16/big-unsigned-integer, Len:8/unsigned-integer, Exchange:Len/binary >>) ->
	{ Preference, Exchange }.

ns(Bin) ->
	{ NSDNAME, _ } = rdata(Bin),
	NSDNAME.

ptr(Bin) ->
	{ PTRDNAME, _ } = rdata(Bin),
	PTRDNAME.

soa(Bin) ->
	{ MName, MRest } = rdata(Bin),
	{ RName, RRest } = rdata(MRest),
	<< Serial:32/big-unsigned-integer, Refresh:32/big-unsigned-integer, Retry:32/big-unsigned-integer,
	Expire:32/big-unsigned-integer, Minimum:32/big-unsigned-integer >> = RRest,
	{ MName, RName, Serial, Refresh, Retry, Expire, Minimum }.

txt(Bin) ->
	txt([],Bin).

txt(Acc,<<>>) ->
	Acc;
txt(Acc,Bin) ->
	{ String, Rest } = rdata(Bin),
	txt([ String | Acc ], Rest).		

a(<<Address:32/big-unsigned-integer>>) ->
	Address.

aaaa(<<Address:128/big-unsigned-integer>>) ->
	Address.

wks(<<Address:32/big-unsigned-integer,Protocol:8/unsigned-integer,Bitmap/binary>>) ->
	{ Address, ip_protocol(Protocol), Bitmap }.


%% empty 0 byte terminates a list
label(<<0:8, Rest/binary>>,Acc,_Message) ->
	{ Acc, Rest };
%% a label index refers to an offset in the message
label(<<1,1, Offset:14/big-unsigned-integer, Rest/binary>>, Acc, Message ) ->
	{ Label, _ } = label(binary:part(Message,Offset, binary:referenced_byte_size(Message) - Offset), Acc, Message ),
	{ Label, Rest };
%% literal string
label(<<0:2,Count:6/big-unsigned-integer, String:Count/binary, Rest/binary>>,Acc,Message) ->
	label(Rest,[ String | Acc ],Message).

label(Bin,Message) ->
	label(Bin,[],Message).
	
qr(0) -> query;
qr(1) -> response.

opcode(0) -> standard;
opcode(1) -> inverse;
opcode(2) -> status;
opcode(_) -> reserved.

rcode(0) -> no_error;
rcode(1) -> format_error;
rcode(2) -> server_error;
rcode(3) -> name_error;
rcode(4) -> not_implemented;
rcode(5) -> refused;
rcode(_) -> reserved.

header(<<Id:16/big-unsigned-integer, 
	Query:1, Opcode:4/integer, AA:1, Truncated:1, RecursionDesired:1, 
	RecursionAvailable:1, _Z:3, RCode:4/integer,  
	QDCount:16/big-unsigned-integer,	%% # questions
	ANCount:16/big-unsigned-integer,	%% # answers
	NSCount:16/big-unsigned-integer,	%% # authority
	ARCount:16/big-unsigned-integer,	%% # additional
	Rest/binary>>) ->
	{ #dns_header{
		id = Id,
		type = qr(Query),
		opcode = opcode(Opcode),
		authoritative = AA,
		truncated = Truncated,
		desired = RecursionDesired,
		available = RecursionAvailable,
		error = rcode(RCode),
		questions = QDCount,
		answers = ANCount,
		authorities = NSCount,
		additional = ARCount
	}, Rest }.

question(Bin,0,Acc,_Message) ->
	{ Acc, Bin };
question(Bin,Count,Acc,Message) -> 
	{ QName, Rest } = label(Bin,Message),
	<< QType:16/big-unsigned-integer, QClass:16/big-unsigned-integer, Next/binary >> = Rest,
	question(Next,Count-1,[ #dns_question{ 
		name = QName,
		type = record_type(QType),
		class = class(QClass) } | Acc ], Message).

answer(Bin,0,Acc,_Message) ->
	{ Acc, Bin };
answer(Bin,Count,Acc,Message) ->
	{ Name, Rest } = label(Bin,Message),
	<< Type:16/big-unsigned-integer, Class:16/big-unsigned-integer, TTL:32/big-unsigned-integer,
	RDLength:16/big-unsigned-integer, RData:RDLength/binary, Next/binary>> = Rest,
	answer( Next, Count - 1, [ #dns_answer{
		name = Name,
		type = record_type(Type),
		class = class(Class),
		ttl = TTL,
		data = RData } | Acc ],Message).

message(Message) ->
	{ Header, R1} = header(Message),
	{ Question, R2} = question(R1,Header#dns_header.questions,[],Message),
	{ Answer, R3} = answer(R2,Header#dns_header.answers,[],Message),
	{ Authority, R4} = answer(R3,Header#dns_header.authorities,[],Message),
	{ Additional, Rest} = answer(R4,Header#dns_header.additional,[],Message),
	{ Header, Question, Answer, Authority, Additional, Rest }.


test() ->
	message(<<58,103,1,32,0,1,0,0,0,0,0,1,3,102,111,111,5,108,111,99,97,108,0,0,
             1,0,1,0,0,41,16,0,0,0,0,0,0,0>>).
