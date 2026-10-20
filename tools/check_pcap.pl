#!/usr/bin/env perl
# Decode a capture with tshark and check that every frame is valid BACnet.
#
#   perl tools/check_pcap.pl capture.pcap [first_port-last_port]
#
# Prints a tally of APDU types / services and exits non-zero if any frame is
# malformed, raises a Wireshark expert error, or is not decoded as BACnet.
use strict;
use warnings;

my $pcap  = shift or die "usage: $0 capture.pcap [port-range]\n";
my $ports = shift // '47808-47900';
my $tshark = $ENV{TSHARK} // 'tshark';

my @cmd = ($tshark, '-r', $pcap, '-d', "udp.port==$ports,bvlc", '-T', 'fields',
           '-E', 'separator=|', '-e', 'frame.number', '-e', '_ws.col.Protocol',
           '-e', '_ws.col.Info', '-e', '_ws.malformed', '-e', '_ws.expert.severity');
open(my $fh, '-|', @cmd) or die "cannot run tshark: $!\n";

my ($frames, $bacnet, $malformed, $expert_err) = (0, 0, 0, 0);
my (%tally, @bad);
while (my $line = <$fh>) {
    chomp $line;
    my ($num, $proto, $info, $mal, $sev) = split /\|/, $line, 5;
    $frames++;
    if ($proto =~ /^(BACnet-APDU|BACnet-NPDU|BVLC)$/) {
        $bacnet++;
    } else {
        push @bad, "frame $num: not decoded as BACnet ($proto)";
    }
    if (($mal // '') ne '' || $info =~ /Malformed/i) {
        $malformed++;
        push @bad, "frame $num: malformed: $info";
    }
    # Wireshark expert severity: 8388608 = error (0x00800000)
    if (defined $sev && grep { $_ >= 8388608 } split /,/, $sev) {
        $expert_err++;
        push @bad, "frame $num: expert error: $info";
    }
    # "Confirmed-REQ   readProperty[  3] analog-input,1 present-value" -> "Confirmed-REQ readProperty"
    my $kind = $info;
    $kind =~ s/\[\s*\d+\].*//;
    $kind = join ' ', grep { defined } (split ' ', $kind)[0, 1];
    $tally{$kind}++;
}
close $fh;
die "tshark failed (exit $?)\n" if $? != 0;

printf "%-45s %6s\n", 'APDU', 'frames';
printf "%-45s %6d\n", $_, $tally{$_} for sort { $tally{$b} <=> $tally{$a} || $a cmp $b } keys %tally;
print "$_\n" for @bad[0 .. ($#bad < 19 ? $#bad : 19)];
printf "frames=%d bacnet=%d malformed=%d expert_errors=%d\n", $frames, $bacnet, $malformed, $expert_err;
exit(($frames > 0 && $bacnet == $frames && !$malformed && !$expert_err) ? 0 : 1);
