#!/usr/bin/perl -w
#   Copyright 2010-2011 Institute for System Programming
#                       of Russian Academy of Sciences
#   Copyright 2012      Pavel Shved <pavel.shved@gmail.com>
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

# Resource monitoring script for limiting black-boxed processes.
# It runs an arbitrary process and watches for memory and time consumption.
# The main feature is that it watches not only the process spawned, but also
# its children--as long as a process doesn't detach ownership from parent (or
# doesn't change process group; use -w).

sub usage{ print STDERR <<usage_ends;
Usage:
	timeout [-t timelimit] [-m memlimit] [-x hertz] command [arguments ...]

usage_ends
	die;
}
# We use require_order because we don't want to process options of the command we run
use Getopt::Long qw(:config require_order);
use Time::HiRes qw( gettimeofday ); 

my $timelimit = undef;
my $hanguplimit = undef;
my $kill_stale = '';
my $ticklimit = undef;
my $memlimit = undef;
my $memlimit_rss = undef;
my $strpat = undef;
# Output for statistic buckets (STDERR if unspecified)
my $output = undef;
my $reference = undef;
my $watchfor = 'tree';
# Requests per seccond
my $frequency = 10;
# if we debug
my $debug = '';
# Whether we do not do this term-kill stuff, and just kill processes at once
my $just_kill = '';
# Suppress printing stats when there was no resource violation
my $info_on_success = 1;
# Do not conceal the exit code of the controlled process if timeout kills it.
my $confess = '';

GetOptions(
	'timelimit|t=f'=>\$timelimit,
	'hanguplimit|h=i'=>\$hanguplimit,
	'detect-hangup!'=>\$kill_stale,
	'detect-hangups!'=>\$kill_stale,
	# allow-hangups is kept for backward compatibility.
	'allow-hangups!'=>\$kill_stale,
	'memlimit|m=i'=>\$memlimit,
	'memlimit-rss|s=i'=>\$memlimit_rss,
	'frequency|x=i'=>\$frequency,
	'pattern|p=s'=>\$strpat,
	'output|o=s'=>\$output,
	'reference|r=s'=>\$reference,
	'watchfor|w=s'=>\$watchfor,
	'debug!'=>\$debug,
	'just-kill'=>\$just_kill,
	'info-on-success!'=>\$info_on_success,
	'confess|c!'=>\$confess,
) or usage;

@ARGV or usage;

my $uinfo = get_patterns($strpat);

my $uwait = int (1_000_000 / $frequency);
my $uflush_time = 100_000;

# String to identify thes script's prints in the output
my $id_str = $ENV{'TIMEOUT_IDSTR'} || '';

use strict;

# Fork process and set its process group
my $blackbox_pid = fork;
defined $blackbox_pid or die "Couldn't fork: $!";

unless ($blackbox_pid){
	# Set the process group of the blackbox process
	# We do not need to change a process group if we aren't using it to control our jobs
	unless ($watchfor eq 'tree') {
		setpgrp 0,0;
	}
	local $" = " ";
	exec @ARGV or die "Couldn't exec @ARGV: $!";
}
# Make sure we kill forked child on exit
sub when_die{
	print_uinfo('SIGNAL',$uinfo);
	kill_process_group_safely($blackbox_pid);
	exit -1;
};
$SIG{'INT'} = \&when_die;
$SIG{'TERM'} = \&when_die;
$SIG{'QUIT'} = \&when_die;
# We sleep between sending TERM and KILL to kids, so we might end up in a regular tick instead of the kill procedure!
# Here's a block for that
my $dying = 0;

use Data::Dumper;

# Now we'll just keep polling status of the process until we notice that resources are exhausted or until the child finishes
use Time::HiRes qw( ualarm usleep );

# see sub update_time for explanations of this structure
my $timeinfo = { total => 0, finished => 0, current => {} };
# For this -- update_memory
my $meminfo = 0;
my $meminfo_rss = 0;
my $fulltime = 0;
# We store the "maximum" used memory (the process may free it and we won't get the proper timestamp at the end).
my $maxmem = -1;
my $maxmem_rss = -1;

# Default ticklimit - limit of number of timeout script wakeups (ticks) before we decide that the controlling processes are hang up (if they haven't done any useful work).  We use ticks instead of real time seconds because the whole stack may be paused with SIGSTOP, and should not die in this case.
#
if(!$hanguplimit && $timelimit) {
	# If unspecified, then wait for the same time the timelimit is set up
	$ticklimit = $timelimit*$frequency;
} elsif($hanguplimit) {
	$ticklimit = $hanguplimit*$frequency;
}

my $status = 'wait';
my $box_status = 0;
while ($status eq 'wait'){
	my $child_errno;
	my $child_retv;
	# Usually we would just do alarm-waitpid, but in Perl we should do weird evals.
	# Refer to `perldoc alarm` if surprised.
	eval {
		local $SIG{'ALRM'} = sub {
			# If we're dying don't return to the embracing eval, return somewhere else!
			return if $dying;
			# Note that this signal can only interrupt "wait" function (unless we're currently in some internals of Perl implementation of waitpid wrapper, but most of the time we spend inside the wait() call).
			# According to signal(7), wait is a safe function, so we can call anything we want here.
			$timeinfo = update_time($blackbox_pid,$timeinfo);
			$meminfo = update_memory($blackbox_pid,$meminfo);
			$meminfo_rss = update_memory_rss($blackbox_pid,$meminfo_rss);
			$maxmem = $meminfo if $meminfo > $maxmem;
			$maxmem_rss = $meminfo_rss if $meminfo_rss > $maxmem_rss;
			update_info_by_ucmd($blackbox_pid,$uinfo);
			die "Assume waitpid return 0\n";
		};
		ualarm $uwait;
		my $arrived = waitpid $blackbox_pid,0;
		ualarm 0;
		die "Assume waitpid return $arrived\n";
	};
	print STDERR Dumper($uinfo) if $debug;
	print STDERR Dumper($timeinfo) if $debug;
	$child_errno = $!;
	$child_retv = $?;
	my $arrived = -1;
	if ($@ =~ /Assume waitpid return (.*)/){
		$arrived = $1;
	}else{
		print_uinfo('INTERNAL',$uinfo,$fulltime);
		die "Fail: $@";
	}
	if ($arrived == $blackbox_pid){
		# Child process terminated.
		# "Simulate" shell behavior, when signal code is returned as exit code.  See http://www.gnu.org/software/bash/manual/html_node/Exit-Status.html for more info.
		$box_status = child_status_to_exit_code($child_retv);
		$status = 'exit'
	}elsif ($arrived == -1){
		# Something happened!
		print_uinfo('INTERNAL',$uinfo);
		print STDERR "timeout: WARNING: Wait($blackbox_pid) failed: $child_errno\n";
		exit 0;
	}else{
		# Check if limits are exhausted (they should be updated by signal handler).
		# First kill, then print the script's verdict, so that it's less likely to mingle with the output of the process being controlled.
		if (my $reason = limits_exceeded()){
			kill_process_group_safely($blackbox_pid);
			# have some sleep for output to be flushed
			usleep($uflush_time);
			print_uinfo($reason,$uinfo);
			# If we killed the child process, we may need to return its error code.
			if ($confess) {
				if (waitpid($blackbox_pid,0) != -1){
					exit(child_status_to_exit_code($?));
				}
			}else{
				exit 0;
			}
		}
	}
}

# 'FINISHED' string has a special meaning in print_uinfo!
print_uinfo('FINISHED',$uinfo) if $info_on_success;
exit $box_status;

#-----------------------------------------------
use POSIX;
my $ticksize;
BEGIN { $ticksize = POSIX::sysconf(&POSIX::_SC_CLK_TCK) or die "Couldn't get ticksize";}

# Function that traverses process tree (according to watchfor setting) and invokes the function supplied for each applicable process
sub foreach_applicable_process
{
	my ($pgrp,$watchfor,$sub) = @_;
	local $_;
	# Depending on whether we count time for process tree or for process group, we use different command.
	if ($watchfor eq 'tree') {
		# Read ps output of a process tree, and read a subtree of the pid we watch for
		# The tree will look like this:
		# 26944 26944 1234 kdeinit4
		# 26944 26948 2341  \_ klauncher
		# 26944 12501 3412  \_ kio_pop3
		# 26944  1591 1101  \_ VirtualBox
		# 26944  1598 1243  |   \_ VirtualBox
		# 26944  1644 1234  |       \_ VBoxXPCOMIPCD
		# 26944 28333 9876  \_ pidgin
		# 26944 28581 8765  \_ kio_file
		# 26944 12496 7655 kmail
		my $chars = "\t \\_|";
		my $PS_FH; open $PS_FH, "-|", qw(ps -e f -o pgrp= -o pid= -o vsz= -o rss= -o ucmd=) or die "Bad open ps: $!";
		my $state = 0;	# 0 - still haven't encounter root;	1 - reading tree; (when tree is read, we break the loop)
		my $initial_depth = undef;	# Initial depth of the root of a tree
		while (<$PS_FH>){
			/^\s*([0-9]+)\s*([0-9]+)\s*([0-9]+)\s*([0-9]+)([ |\\_]+)(.*)/ or next;
			#      PID                depth in process tree
			my ($grp,$pid,$vsz,$rss,$depth_str,$cmd) = ($1,$2,$3,$4,$5,$6);
			if ($state == 0){
				# Still haven't encounter root, check if it's now
				$pid == $pgrp or next;
				$state = 1;
				$initial_depth = length $depth_str;
			}else{
				# Reading inside process tree, check if it's not over
				length $depth_str == $initial_depth and last;
			}
			# Ok, this is a node in the tree we want to process
			$sub->($pid,$grp,$cmd,$vsz,$rss);
		}
		close $PS_FH or die "Bad close ps: $!";
	}else{
		# Read ps output to get all processes within a group. Time output is not necessary, since we calculate it directly via /proc
		my $PS_FH; open $PS_FH, "-|", qw(ps -A -o pgrp= -o pid= -o vsz= -o rss= -o ucmd=) or die "Bad open ps: $!";
		while (<$PS_FH>){
			/^\s*([0-9]+)\s*([0-9]+)\s*([0-9]+)\s*([0-9]+)\s*(.*)/ or next;
			my ($grp,$pid,$vsz,$rss,$cmd) = ($1,$2,$3,$4);
			$grp == $pgrp or next;

			$sub->($pid,$grp,$cmd,$vsz,$rss);
		}
		close $PS_FH or die "Bad close ps: $!";
	}
}

sub hires_proc_runtime
{
	my ($pid) = @_;
	my $stat = `cat /proc/$pid/stat 2>/dev/null`;
	# Since we invoke this function quite often, process may decease betweem ps invocation and attempt to access its /proc entry.  So, we return undef and handle it in the caller.  That's also the reason of error redirection to void.
	return undef unless $stat;
	# Parse proc stats--14th is utime, and it's expressed in ticks.
	my (undef,undef,undef,undef,undef,undef,undef,undef,undef,undef,undef,undef,undef,$utime_ticks,$stime_ticks,$cum_utime_ticks,$cum_stime_ticks) = split /\s+/,$stat;
	return (($utime_ticks + $stime_ticks)/$ticksize, ($cum_utime_ticks + $cum_stime_ticks)/$ticksize);
}
sub update_time
{
	# Calculate the CPU+SYS time consumed by processes in the process group.  Updates special timeinfo structure fur future calculations
	my ($pgrp, $timeinfo) = @_;

	# For one process, cumulative time is its runtime plus runtime of its dead children.  Therefore, if we sum up cumulative times for all the eligible processes, we'll get the total runtime of the black box
	my $cumulative_time = 0;

	foreach_applicable_process($pgrp,$watchfor,sub { my ($pid,$grp,$cmd) = @_;
		# If hires_proc_runtime doesn't return a value (the $pid died before it tried), we keep the old value of time.  The error is not greater than ualarm interval.
		my ($pid_time,$pid_cum_time) = hires_proc_runtime($pid);
		if (defined $pid_time){
			printf STDERR "timeout: pid $pid own $pid_time kids $pid_cum_time\n" if $debug;
			$cumulative_time += $pid_time + $pid_cum_time;
		}
	});

	my $result = {prev_total => $timeinfo->{total}, total => $cumulative_time, ticks_stale => ($timeinfo->{ticks_stale} || 0)};

	# If the time didn't change, increase number of ticks the processes controlled are in a stale state.
	if ($timeinfo->{total} == $cumulative_time) {
		$result->{ticks_stale} ++;
	}

	return $result;
}

sub update_memory
{
	# Calculate the amount of memory consumed by the process group given
	my ($pgrp) = @_;
	my $result = 0;
	foreach_applicable_process($pgrp,$watchfor,sub { my ($pid,$grp,$cmd,$vsz) = @_;
		$result += $vsz;
	});
	return $result;
}

sub update_memory_rss
{
	# Calculate the amount of rss memory consumed by the process group given
	my ($pgrp) = @_;
	my $result = 0;
	foreach_applicable_process($pgrp,$watchfor,sub { my ($pid,$grp,$cmd,$vsz,$rss) = @_;
		$result += $rss;
	});
	return $result;
}

sub signal_to_process_group_safely
{
	my ($pgrp,$signal) = @_;
	if ($watchfor eq 'tree') {
		# We can't kill the whole process group, so we do the following trick.
		# We send SIGSTOP to all applicable processes.  Since they could have spawned more kids between reading their PID from ps and sending signal, we repeat this step until all processes are stopped
		my $new_kids_spawned = 1;
		my %sent_to = ();
		while ($new_kids_spawned) {
			$new_kids_spawned = 0;
			foreach_applicable_process($pgrp,$watchfor,sub { my ($pid) = @_;
				return if $sent_to{$pid};
				$sent_to{$pid} = 1;
				$new_kids_spawned = 1;
				kill SIGSTOP, $pid;
			});
		}
		# Now all the controlled processes are stopped, we send them the signal we want
		foreach_applicable_process($pgrp,$watchfor,sub { my ($pid) = @_;
			kill $signal, $pid;
		});
		# Continue the proccesses, so that they can process the signal handler
		foreach_applicable_process($pgrp,$watchfor,sub { my ($pid) = @_;
			kill SIGCONT, $pid;
		});
	}else{
		# it's still unclear to me if there won't be a delay between catching signals in different processes when a signal is sent to a whole group.
		kill SIGSTOP, -$pgrp;
		kill $signal, -$pgrp;
		kill SIGCONT, -$pgrp;
	}
}

sub kill_process_group_safely
{
	my ($pgrp) = @_;
	# Show that we're dying, so that our timely alarm handler doesn't longjmp() control out of here
	$dying = 1;
	# Reset alarm handler (we need it for sleep to work)
	$SIG{'ALRM'} = 'DEFAULT';
	unless ($just_kill) {
		print STDERR "timeout: Sending TERM\n" if $debug;
		signal_to_process_group_safely($pgrp,SIGTERM);
		sleep(1);
	}
	print STDERR "timeout: Sending KILL\n" if $debug;
	signal_to_process_group_safely($pgrp,SIGKILL);
}

sub update_info_by_ucmd
{
	my ($pgrp, $strpat) = @_;

	local $_;

	# PIDs that are currently alive
	my %alive = ();

	# Collect times and commands of the processes that satisfy the patterns given to the $strpat
	foreach_applicable_process($pgrp,$watchfor,sub { my ($pid,$grp,$ucmd) = @_;
		# Search process by pattern
		foreach my $key(keys %{$strpat}) {
			# NOTE that one pattern may match only one of these: either children or not children.  That's used to avoid confusion
			if ($ucmd =~ m/$key/) {
				# Calculate proctime only for the matching processes
				my ($proctime,$kidstime) = hires_proc_runtime($pid);
				# If PID is dead, just don't set %alive for it making time info intact.  Its time info will be reconciled later.
				if ($proctime){
					$strpat->{$key}->{pids}->{$pid}->{ptime} = $proctime;
					$strpat->{$key}->{pids}->{$pid}->{ucmd} = $ucmd;
					$alive{$pid} = 1;
				}
			}elsif(($key =~ /^CHILD/) && ("CHILD:$ucmd" =~ m/$key/)){
				# Calculate proctime only for the matching processes
				my ($proctime,$kidstime) = hires_proc_runtime($pid);
				# If PID is dead, just don't set %alive for it making time info intact.  Its time info will be reconciled later.
				if ($kidstime){
					$strpat->{$key}->{pids}->{$pid}->{ptime} = $kidstime;
					$strpat->{$key}->{pids}->{$pid}->{ucmd} = "CHILD:$ucmd";
					$alive{$pid} = 1;
				}
			}
		}
	});

	# Calculate full time for each pattern
	for my $key(keys %{$strpat}) {
		my $sk = $strpat->{$key};
		my $oldtime = $strpat->{$key}->{ptime} || 0;

		# ptime is a sum, and term_time is a total time of terminated PIDs
		# Increase the time of dead pids, and recalculate runtime of alive pids.
		my $term_time = $sk->{term_time} || 0;
		my $ptime = 0;
		for my $pid (keys %{$sk->{pids}}) {
			unless (exists $alive{$pid}) {
				$term_time += ($sk->{pids}->{$pid}->{ptime} || 0);
				delete $sk->{pids}->{$pid};
			}else{
				$ptime += $sk->{pids}->{$pid}->{ptime};
			}
		}
		$sk->{ptime} = $ptime;
		$sk->{term_time} = $term_time;
	}
	return undef;
}


#
# TODO: If the file already exists, and it contains two or more <time>...</time>
#       blocks with equals references and name 
#       then we must be calculate summary time and write one <time>..</time> 
#       block  instead of more with equlas references.
#       It needs for rule-instrumentor, that execute aspectator two time for
#       one cc command. 
#
sub print_uinfo
{
	my $reason = shift;
	# Print generic information to STDERR
	my $ticks = $timeinfo->{ticks_stale} || 0;
	printf STDERR "${id_str}%s CPU %.2f MEM %d MAXMEM %d STALE %d MAXMEM_RSS %d\n", $reason, $timeinfo->{total}, $meminfo, $maxmem, ceil($ticks/$frequency), $maxmem_rss if ($reason ne 'FINISHED') || $info_on_success;

	if (defined $output){
		open(FIL,">>", $output) or die "Can't open output file: $!\n";
	}else{
		open(FIL, ">&STDERR");
	}
	my ($strpat) = @_;
	my $reftext="";
	defined $reference and $reftext="ref=\"$reference\" ";
	# Sum up times for equal names
	my %name_val = ();
	foreach my $key( keys %{$strpat}) {
		my $sp = $strpat->{$key};

		scalar keys %{$sp->{pids}} or $sp->{term_time} or next;
		$name_val{$sp->{name}} ||= 0;
		$name_val{$sp->{name}}  += ($sp->{ptime} + $sp->{term_time});
	}
	for my $name (keys %name_val){
		print(FIL "<time ${reftext}name=\"".$name."\">".sprintf("%.0f", 1000*$name_val{$name})."</time>\n");
	}
	defined $output and close FIL;
}

sub get_patterns
{
	my ($patterns_in_string) = @_;
	if ($patterns_in_string){
		my @splitted_patterns = split(/;/,$patterns_in_string);
		my %patterns = ();
		foreach (@splitted_patterns) {
			my ($pattern, $name) = split(/,/,$_);
			printf STDERR "timeout: pattern $pattern for bucket $name initialized\n" if $debug;
			$patterns{$pattern} = {name=>$name, ptime=>0, pids=>{}};
		}
		return {%patterns};
	}else{
		return {'.*' => {name=>'ALL', prtime=>0, pids=>{}}};
	}
}

# Check if limits are exhaused, and return the reason why, if any.  Otherwise, return undef.
sub limits_exceeded
{
	if (defined $timelimit && $timeinfo->{total} > $timelimit){
		return 'TIMEOUT';
	}elsif (defined $ticklimit && $kill_stale && $timeinfo->{ticks_stale} > $ticklimit) {
	# Sometimes the controlling process may inherently hang up.  Then we don't interrupt it.
		return 'HANGUP';
	}elsif (defined $memlimit && $meminfo > $memlimit){
		return 'MEM';
	}elsif (defined $memlimit_rss && $meminfo_rss > $memlimit_rss){
		return 'MEM_RSS';
	}
	return undef;
}

# Convert child exit status to exit code.  Follow Bash way.
sub child_status_to_exit_code
{
	my ($child_retv) = @_;
	if (($child_retv > 0) && (($child_retv >> 8) == 0)){
		# The 8th bit indicates if the core was dumped.  If it was not, we are to add 128 anyway, so just set the bit.
		return $child_retv | 128;
	}else{
		# This is also executed when there was no error, and the result is zero.
		return $child_retv >> 8;
	}
}
