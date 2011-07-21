#!/usr/bin/perl

use strict;
use warnings;

my @index_intervals;

while (<>) {
    if (/^([\d\.]+)\ -\ ([\d\.]+)/) {
	push @index_intervals, $1, $2;
    }
}


opendir(DIR, ".") || die "can't opendir .: $!";
my @class_files = grep { /^class_/ } readdir(DIR);
closedir DIR;

my $t0;
my $file0;

my @class_files_intervals;

foreach my $file (sort @class_files) {
    ` tcpdump -nr $file -tt -c1 ` =~ /^([\d\.]+)/;
    my $t = $1;

    if (defined $file0) {
	$file=~/class_(.+?)_/; my $class=$1;
	$file0=~/class_(.+?)_/; my $class0=$1;
	if ($class eq $class0) {
	    push @class_files_intervals, $file0, $t0, $t;
	} else {
	    push @class_files_intervals, $file0, $t0, 0;
	}
    }
    $file0=$file;
    $t0=$t;
}

push @class_files_intervals, $file0, $t0, 0;


my @result_files;

my @t=@index_intervals;
while (defined(my $is=shift @t) && defined (my $ie=shift @t)) {


#    print "[${is} , ${ie}]\n";

    my @t=@class_files_intervals;
    while (defined (my $fn=shift @t) &&
	   defined (my $fs=shift @t) &&
	   defined (my $fe=shift @t)) {
#	print " ${fn}\t[${fs} , ${fe}[\n";

	if ($is<=$fs && $ie>=$fs || $is>=$fs && ($is<=$fe || $fe==0)) {
#	    print "  [${is} , ${ie}] and [${fs} , ${fe}[ ".
#		"(file ${fn}) intersect!\n";
	    if (!grep {$_ eq $fn} @result_files) { push @result_files, $fn; }
	}
    }

}


foreach my $f (@result_files) {
    print "$f\n";
}
