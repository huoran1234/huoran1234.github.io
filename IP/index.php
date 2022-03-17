<?php 
/*
	Dude What's My IP? Version 2.0
	@ http://perishablepress.com/roll-your-own-whats-my-ip/
*/

// variables
$xfwd     = mm_strip($_SERVER["HTTP_X_FORWARDED_FOR"]); 
$address  = mm_strip($_SERVER["REMOTE_ADDR"]); 
$port     = mm_strip($_SERVER["REMOTE_PORT"]); 
$method   = mm_strip($_SERVER["REQUEST_METHOD"]); 
$protocol = mm_strip($_SERVER["SERVER_PROTOCOL"]); 
$agent    = mm_strip($_SERVER["HTTP_USER_AGENT"]); 

if ($xfwd !== '') {
	$IP = $xfwd;
	$proxy = $address;
	$host = @gethostbyaddr($xfwd);
} else {
	$IP = $address;
	$host = @gethostbyaddr($address);
}

// sanitizes
function mm_strip($string) {
	$string = trim($string); 
	$string = strip_tags($string);
	$string = htmlspecialchars($string, ENT_QUOTES, 'UTF-8');
	$string = str_replace("\n", "", $string);
	$string = trim($string); 
	return $string;
}
?><!DOCTYPE html>
<html><meta http-equiv="Content-Type" content="text/html; charset=utf-8">
	<title>What's my IP dude!</title>
	<style type="text/css">
		* { margin:0; padding:0; }
		body { background:#333; color:#efefef; margin-top:50px; }
		.tools { margin:25px auto; width:960px; }
		.tools p {
			margin-left:20px; color:#777; font-family: Georgia,serif;
			-webkit-text-shadow:0 0 7px #000; -moz-text-shadow:0 0 7px #000; text-shadow:0 0 7px #000;
			}
		#ip-lookup { 
			border:1px solid #aaa; 
			background-position:50% 50%; background-repeat:repeat-x; background-color:#777;
			background-image: url(data:image/gif;base64,R0lGODlhAQBWAfcAAHZ2dkVFRXJyck1NTVFRUUVEREpKSnR0dEhISEZGRklJSW1tbVNTU1ZWVnV1dW9vb2lpaUdHR2dnZ2tra0xMTFpaWlBQUFRUVF9fX1VVVFlZWWRkZGBgYEtLS2FhYU5OTl1dXVVVVW5ubnZ1dmpqakZGR2tsbGZmZmJiYnZ1dWNjY0xNTVpbWmxsbFtbW0ZFRkZFRVJSUnBwb15eXlhYWWVlZVdXV05PT09PT1JTUm5vbnNzc3Nyc3BwcHFxcXFwcGppamhoaFhYWF5fXnJxcWhpaWJiY0hISVRUU25tbXV1dmNkY25vb3Rzc1NUU0xLTG1ubnR1dUhHSHV0dGNkZEhHR19eXk5OTXd3dlxdXVdXWHR1dFFRUFxcXU9PUFxbXFdWVlxcXHFxcGFhYmNjYlxdXFhYV3Bvb21sbGNjZGVlZmZmZUxNTFlZWF5dXnBxcFxcW3V2dnR0c1tcW2BfX2JhYlBQUVZXV2hnaFBPT3BxcUhJSElISG5ubXJzc2tqanJzcmZmZ0lKSlhXV1JSUXd2dkdGR2VkZFBQT0tMS2loaGJjY2ZnZmxtbEtLTExMS0lISVtbWkVFRkdGRmRlZGdnaHFxclxbW1FSUUpLSklJSkdHSF9gX2FgYFtaW09OTmtrak9QT1lZWnN0dF5dXVJSU0RFRXN0c2VmZUtMTHNzdGtsa1VVVkRERHd3dwAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAACH5BAAAAAAALAAAAAABAFYBAAj/AF0JHEiQYCFXABJiSQhgxIg4KUakUOKgYhQHU7Yc2LhxlJxTTVTt2MGDhwA/gASoVGmJiA+Xen6I+fGmRw8ZMs482PmAiQ4dIoJC6ZNkgdEFjdC0aGGi6aoJUCeA+kOCBBCrECAU0QpBUZAgeCpJGCvhBKNAJ9ScWIOqRg1KGw5t2EAljYolKsgYWWQEBYo6KMZ4GNyJg2E6nDAoHmJlyIwZbkCQApEFRJkuYb64gHNpjotInliwqEBalAYNbTTQoCFEiJlBWmzYuAOmge0GrELozsD7gm8GSJwwYJCDeKkYMQgRIIBpOQEuFuxYQGQhj5dQOD7dwHHjg/crA8IPUFgxng2F848cpXqSqIN7AwYywTcgSIF9TfYhIdhzBAEfBFIgUAUCm0RgoCElRFBCAiVMksCDLyQQwAswBACDJAEUEEAApmRYwIethChiiAEBADs=);
	
			-webkit-border-radius:11px; -moz-border-radius:11px; border-radius:11px; 
			-webkit-box-shadow:0 0 11px #111; -moz-box-shadow:0 0 11px #111; box-shadow:0 0 11px #111;
			}
		#tools p { font-size:77px; }
		#more p  { font-size:24px; }
		#more-info p { font-size:18px; }
		#more-info ul { margin:20px 0 35px 50px; font-size:18px; color:#ccc; }
		#more-info li { margin:10px 0; line-height:25px; font-family:Helvetica, Arial; }
		h1 { 
			font: 124px/1 Helvetica, Arial; text-align:center; margin:50px 0; color:#efefef;
			-webkit-text-shadow:0 0 7px #333; -moz-text-shadow:0 0 7px #333; text-shadow:0 0 7px #333;
			}
		h1 a:link { color:#efefef; }
		a:link,a:visited { 
			color:#777; text-decoration:none; outline:0 none; 
			-webkit-text-shadow:0 0 7px #000; -moz-text-shadow:0 0 7px #000; text-shadow:0 0 7px #000;
			}
		a:hover,a:active { color:#eee; text-decoration:underline; outline:0 none; }
		li span { 
			font:16px/1 Monaco,"Panic Sans","Lucida Console","Courier New",Courier,monospace,sans-serif; color:#ccc; 
			-webkit-text-shadow:0 0 3px #777; -moz-text-shadow:0 0 3px #777; text-shadow:0 0 3px #777;
			}
	</style>
	<body>
		<div id="tools" class="tools">
			<p>Your IP:</p>
		</div>
		<div id="ip-lookup" class="tools">
			<h1><?php echo $IP; ?></h1>
		</div>
		<div id="more" class="tools">
			<p><a id="more-link" title="More information" href="javascript:toggle();">More info</a></p>
		</div>
		<div id="more-info" class="tools">
			<ul>
			<?php 
				echo '<li><strong>Remote Port:</strong> <span>'.$port.'</span></li>';
				echo '<li><strong>Request Method:</strong> <span>'.$method.'</span></li>';
				echo '<li><strong>Server Protocol:</strong> <span>'.$protocol.'</span></li>';
				echo '<li><strong>Server Host:</strong> <span>'.$host.'</span></li>';
				echo '<li><strong>User Agent:</strong> <span>'.$agent.'</span></li>'; 
				if ($proxy) echo '<li><strong>Proxy: <span>'.($proxy) ? $proxy : ''.'</span></li>';

				$time_start = microtime(true);
				usleep(100);
				$time_end = microtime(true);
				$time = $time_end - $time_start;
			?>
			</ul>
			<p><small>It took <?php echo $time; ?> seconds to share this info.</small></p>
		</div>
		<script type="text/javascript">
			function hideStuff(){
				if (document.getElementById){
					var x = document.getElementById('more-info');
					x.style.display="none";
				}
			}
			function toggle(){
				if (document.getElementById){
					var x = document.getElementById('more-info');      
					var y = document.getElementById('more-link');      
					if (x.style.display == "none"){
						x.style.display = "";
						y.innerHTML = "Less info";
					} else {
						x.style.display = "none";
						y.innerHTML = "More info";
					}
				}
			}
			window.onload = hideStuff;
		</script>
	</body>
</html>
