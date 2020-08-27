# @TEST-EXEC: bro -Cr $TRACES/badversion.pcap %INPUT >output
# @TEST-EXEC: btest-diff output
event pdf_info(f: fa_file, info: PDF::Info) {
	print info$version;
}
