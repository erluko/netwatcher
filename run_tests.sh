#!/bin/sh
#exercise options for netwatcher
killall netwatcher-test 2>/dev/null;

O=`mktemp -t netwatcher_test_o`;
E=`mktemp -t netwatcher_test_e`;

trap 'killall netwatcher-test 2>/dev/null; rm -f -- "$O" "$E"' EXIT;

printf "REDIRECTING >'%s' 2>'%s'\n" "$O" "$E";
function QKILL() {
  { kill $1; wait $1; } >/dev/null 2>/dev/null
}

function CHECK() {
  err=$1;
  if [ "$err" == 0 ];then
    printf "Passed: %s\n" "$2";
  else
    printf "Failed: %s\n" "$2";
    exit "$err";
  fi
}

alias NETWATCHER=">'$O' 2>'$E' ./netwatcher-test"

NETWATCHER -h
grep -q 'Usage' "$O";
CHECK $? "USAGE";

NETWATCHER -d -f ./test_util.sh&
PID=$!;
sleep 2;
grep -q Listening "$E";
CHECK $? "Listening message"
QKILL $PID
grep -q Done "$E"
CHECK $? "Done message"

NETWATCHER -d -f ./test_util.sh&
PID=$!;
sleep 1;
kill -HUP $PID
sleep 1;
grep -q force-execute "$E"
CHECK $? "HUP support"
QKILL $PID;



NETWATCHER -de -f ./test_util.sh&
PID=$!;
sleep 1;
kill -HUP $PID
sleep 1;
grep -q 'out:' "$E"
CHECK $? "out > err"
QKILL $PID;

NETWATCHER -do -f ./test_util.sh&
PID=$!;
sleep 1;
kill -HUP $PID
sleep 1;
grep -q 'out:' "$O"
CHECK $? "err > out"
QKILL $PID;

NETWATCHER -dE -f ./test_util.sh&
PID=$!;
sleep 1;
kill -HUP $PID
sleep 1;
QKILL $PID;
echo >> "$E"
grep -qv 'err: ' "$E"
CHECK $? "Closed ERR"


NETWATCHER -dO -f ./test_util.sh&
PID=$!;
sleep 1;
kill -HUP $PID
sleep 1;
QKILL $PID;
echo >> "$O"
grep -qv 'out: ' "$O"
CHECK $? "Closed OUT"

