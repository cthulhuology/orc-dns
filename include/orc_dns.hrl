
-record( orc_dns_server, { socket }).
-record(dns_header, { id, type, opcode, 
	authoritative, truncated, desired, available, error, 
	questions, answers, authorities, additional }).
-record(dns_question, { name, type, class }).
-record(dns_answer, { name, type, class, ttl, data }).


