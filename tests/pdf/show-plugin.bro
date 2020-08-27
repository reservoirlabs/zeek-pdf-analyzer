# @TEST-EXEC: bro -NN Analyzer::PDF | sed -e 's/(dynamic, version [0-9]\+\.[0-9]\+\(\.[0-9]\+\)\?)/(dynamic, version @VERSION@)/g' >output
# @TEST-EXEC: btest-diff output
