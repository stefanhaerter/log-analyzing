#!/usr/bin/perl

use strict;
use warnings qw( all );

use Data::Dumper;
use DateTime;
use Getopt::Long;
use Mail::Sendmail;

# Parse command line options
my %cli_opts = ();
GetOptions(
	'--output:s' => \$cli_opts{output},
	'--log-path=s' => \$cli_opts{logpath},
	'--mail-address:s' => \$cli_opts{mailaddress},
);

# Check options
print STDERR "CLI Options: " . Dumper(%cli_opts) . "\n";

# Configuration
my $frequency_limit = 15;
my $time_limit = 60;
my @suspicious_requests = (
    '.*\.\..*',
    '.*root.*',
);

open(ACCESS_LOG, $cli_opts{logpath});

# Parsing log entries
my %processed_items = ();

my $i = 0;
while(my $line =<ACCESS_LOG>) {
	chomp($line);

	# Parse Log Entry
	$line =~ /(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}) - (\S+?) \[(.*)\] "(.*)" (\d{3}) (\d+)/;
	my $ip = $1;
	my $user = $2;
	my $timestamp = $3;
	my $request = $4;
	my $response_status = $5;
	my $size = $6;

	# Parse Date
	my %month_lookup = (
		'Jan' => '01',
		'Feb' => '02',
		'Mar' => '03',
		'Apr' => '04',
		'May' => '05',
		'Jun' => '06',
		'Jul' => '07',
		'Aug' => '08',
		'Sep' => '09',
		'Oct' => '10',
		'Nov' => '11',
		'Dez' => '12',
	);
	$timestamp =~ /(\d+)\/(\w{3})\/(\d{4}):(\d{2}):(\d{2}):(\d{2}) +|-\d{4}/;
	my $date = DateTime->new(
		year => $3,
		month => $month_lookup{$2},
		day => $1,
		hour => $4,
		minute => $5,
		second => $6
	);

	$processed_items{$i} = {
		'ip' => $ip,
		'user' => $user,
		'timestamp' => $date,
		'request' => $request,
		'response_state' => $response_status,
		'size' => $size
	};
	$i++;
}

close(ACCESS_LOG);

# Analyzing entries
my @reporting_items;

# Ideas: Many requests from same ip, many requests in short time, path traversal attacks, request state 400
my %ip_count = ();
my %time_count = ();
for my $id (sort keys %processed_items ) {
    my %item = %{$processed_items{$id}};
    # Check request forgery
    for my $regex (@suspicious_requests) {
        if ($item{'request'} =~ $regex) {
            push @reporting_items, "Suspicious request detected.\n\tRegex: $regex\n\tHit:\n\t\tIP: $item{'ip'}\n\t\tUser: $item{'user'}\n\t\tDate and Time: $item{'timestamp'}\n\t\tRequest: $item{'request'}\n\t\tResponse State: $item{'response_state'}\n"
        }
    }

    # Collect ip
    $ip_count{$item{'ip'}}++;
}

for my $ip (keys %ip_count) {
    if ($ip_count{$ip} > $frequency_limit) {
        push @reporting_items, "Many Requests from same IP detected\n\tIP: $ip\n\tRequest Count: $ip_count{$ip}\n"
    }
}

my $content = join('', @reporting_items);

my %mail = (
	To => $cli_opts{mailaddress},
	From => 'test@test.de',
	Subject => 'Log Notification',
	Message => $content,
);

if ($cli_opts{output} eq 'mail') {
    sendmail(%mail) or die $Mail::Sendmail::error;
    print STDERR "OK. Log says:\n" . $Mail::Sendmail::log;
} else {
    print STDOUT $content . "\n"; 
}
