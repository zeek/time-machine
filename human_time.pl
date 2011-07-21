#!/usr/bin/perl -w

# autoflush
$|=1;

while (<>) {
    /^([\d\.]+) (.+)$/;
    print scalar localtime $1, " ", $1, " ", $2, "\n";
}
