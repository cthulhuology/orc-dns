-module(orcdns).
-author({ "David J Goehrig", "dave@dloh.org" }).
-copyright(<<"© 2017 David J Goehrig"/utf8>>).
-export([ start/0, stop/0 ]).

start() ->
	application:ensure_all_started(orc_dns).

stop() ->
	application:stop(orc_dns).

