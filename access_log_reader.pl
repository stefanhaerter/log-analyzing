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

# Check log path
if (!defined $cli_opts{logpath} || !$cli_opts{logpath}) {
	die "No path to log file given!\n";
} elsif (!-e $cli_opts{logpath}) {
	die "Given log file does not exist!\n";
}

# Check output and potential mail
if ($cli_opts{output} eq 'mail' && (!defined $cli_opts{mailaddress} || !$cli_opts{mailaddress})) {
	die "Mail as output chosen but no mail address provided!\n";
}

# Configuration
my $frequency_limit = 15;
my $time_limit = 60;
my @suspicious_requests = (
    '.*\.\..*',
    '.*root.*',
);

open(my $log_fh, '<', $cli_opts{logpath}) or die $!;

# Parsing log entries
my %processed_items = ();

my $i = 0;
while(my $line =<$log_fh>) {
	chomp($line);

	# Parse Log Entry
	my ($ip, $user, $timestamp, $request, $response_status, $size);
	if($line =~ /(?<ip>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}) - (?<user>\S+?) \[?<timestamp>(.*)\] "(?<request>.*)" (?<response_status>\d{3}) (?<size>\d+) ("(?<referer>).?")? ("(?<user_agent>).?")?/) {
		$ip = $+{ip};
		$user = $+{user};
		$timestamp = $+{timestamp};
		$request = $+{request};
		$response_status = $+{response_status};
		$size = $+{size};
	} else {
		next;
	}

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
		'date' => $date,
		'request' => $request,
		'response_state' => $response_status,
		'size' => $size
	};
	$i++;
}

close($log_fh);

# Analyzing entries
my @reporting_items;

# Ideas: Many requests from same ip, many requests in short time, path traversal attacks, request state 400
# Count requests per IP
my %ip_count = ();
# Count requests per hour and minute (day is irrelevant since log rotates daily)
my %time_count = ();

print STDERR "Items: " . Dumper(\%processed_items) . "\n";

for my $id (sort keys %processed_items ) {
    my %item = %{$processed_items{$id}};
    # Check request forgery
    for my $regex (@suspicious_requests) {
        if ($item{'request'} =~ $regex) {
            push @reporting_items, "Suspicious request detected.\n\tRegex: $regex\n\tHit:\n\t\tIP: $item{'ip'}\n\t\tUser: $item{'user'}\n\t\tDate and Time: $item{'date'}\n\t\tRequest: $item{'request'}\n\t\tResponse State: $item{'response_state'}\n"
        }
    }

    # Collect ip
    $ip_count{$item{'ip'}}++;

    # Collect time count
    print STDOUT $id . "\n";
    print STDOUT $item{'date'}->hour() . ", " . $item{'date'}->minute() . "\n";
    $time_count{$item{'date'}->hour() . '-' . $item{'date'}->minute()}++;
}

print STDOUT "Time Count: " . Dumper(\%time_count) . "\n";

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

if (defined $cli_opts{output} && $cli_opts{output} eq 'mail') {
    sendmail(%mail) or die $Mail::Sendmail::error;
    print STDERR "OK. Log says:\n" . $Mail::Sendmail::log;
} else {
    print STDOUT $content . "\n"; 
}
