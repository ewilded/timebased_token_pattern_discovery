<?php
### This little script attempts to guess the pattern on which some 'random' security control string is created (like anti-CSRF token or a custom generated session id, password reset token, service authorization code etc cetera). If token seems to be a result of well known function hash, like md5/sha1 and remote systems currrent timestamp was used instead of random number generator, there is a chance for us to discover such weak pattern.
### To mention few patterns of this sort: current_timestamp:username, current_timestamp-ip, usernamecurrent_timestamp etc.

### How to use:
### Make a request resulting in new token generation, save the value (timestamp) you get back in the Date response header.
### Save the token and the date in the configuration variables below. Choose the hashing function that token appears to be result of.
### If there is a difference between your current timezone and target server timezone, set it in timezone_difference (this is the number of hours that has to be added to the target timezone in order to align it to your local system time); this is needed for date text-represented tokens, as date adjusts current timezone to the result when timestamp in seconds is specified. It has to be an integer (total number).
### The fallback_seconds parameter is the time span range that is about to be tested. It is supposed to cover the gap between the request and response (usually few seconds) in order not to miss the correct timestamp that was used to generate the token. 
### Set up other settings (all predictable prefixes custom to the application, username, user-agent used and your IP address seen by the remote server. Optionally save the conjunctors.


### TODO: three_element_ has to be put out from that custom string foreach, it is redundant now
### CONFIG

$date='Fri, 20 Mar 2015 13:51:56 GMT';
$token='e2d6593191419aed4bba4ae35ecb0b55';
$hash_func='md5';
$fallback_seconds=8;
$timezone_difference=0; # difference between current timezone and timezone of the target, this is offset to the GMT
$date_formats=array("Y-M-d h:i:s",DATE_ATOM, DATE_COOKIE, DATE_RFC822, DATE_RFC850, DATE_ISO8601, DATE_RFC1123, DATE_RSS, DATE_W3C);
$user_agent='Mozilla/5.0 (Windows NT 6.1; WOW64; rv:36.0) Gecko/20100101 Firefox/36.0';
$ip_addr='192.168.58.2';
$custom_strings=array('foouser','fooappname',$user_agent,$ip_addr); 
$conjunctions=array(':','','-','_','|');


### LOGIC
$cnt=0;
$time=strtotime($date);
$start_time=$time-$fallback_seconds;
function try_this($string)
{	
		global $cnt;
		$cnt++;
		global $token;
		global $hash_func;
		$r=$hash_func($string);
		echo "Trying $hash_func($string)=$r\n";
		if($token==$r) die("Pattern found: $string\n$cnt checks performed\n");
}

function three_element_patterns($d,$c,$ip_addr,$user_agent)
{
			try_this("$d$c$ip_addr$c$user_agent");
			// timestamp:uastring:ip
			try_this("$d$c$user_agent$c$ip_addr");
			// ip:timestamp:uastring
			try_this("$ip_addr$c$d$c$user_agent");
			// ip:uastring:timestamp
			try_this("$ip_addr$c$user_agent$c$d");
			// uastring:ip:timestamp
			try_this("$user_agent$c$ip_addr$c$d");
			// uastring:timestamp:ip
			try_this("$user_agent$c$d$c$ip_addr");
}
# Direct timestamp patterns
for($i=$start_time;$i<$start_time+$fallback_seconds+2;$i++) ## one second granularity
{
	$start_time_for_date=$i-(3600*$timezone_difference);
	foreach($custom_strings as $p)
	{	
		# PREFIX+TIMESTAMP
		try_this("$p$i");
		try_this("$i$p");
		// other date formats would be good as well
		foreach($date_formats as $date_format) 
		{
			$d=date($date_format,$start_time_for_date);
			// two-element patterns
			foreach($conjunctions as $c)
			{
				try_this("$p$c$d");
				try_this("$d$c$p");
				if($p==$custom_strings[0]) three_element_patterns($d,$c,$ip_addr,$user_agent);
			}
			// three-element patterns
			
		}
		# Check milisecond granularity
		for($j=0;$j<10;$j++)
			for($h=0;$h<10;$h++)
				for($k=0;$k<10;$k++)
				{
					foreach($conjunctions as $c)
					{
						try_this("$p$c$i$j$h$k"); // prefix
						try_this("$i$j$h$k$c$p"); // suffix
						if($p==$custom_strings[0]) three_element_patterns("$i$j$h$k",$c,$ip_addr,$user_agent);
					}
				}
	}
}
echo "Pattern not discovered.\n$cnt checks performed\n";
### 
?>
