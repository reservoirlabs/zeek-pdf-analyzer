# @TEST-EXEC: bro -Cr $TRACES/notify.pcap %INPUT
# @TEST-EXEC: bro-cut src p note msg sub < notice.log > notice.tmp && mv notice.tmp notice.log || touch notice.log
# @TEST-EXEC: btest-diff notice.log
@load Analyzer/PDF/notify.bro

redef PDF::MAX_SIZE: count = 1048576;
