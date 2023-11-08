<?php
$ip = $_SERVER["REMOTE_ADDR"];      //记录访问者的ip
$filename = $_SERVER['PHP_SELF'];       //访问者要访问的文件名
$parameter = $_SERVER["QUERY_STRING"];      //访问者要请求的参数
$method = $_SERVER['REQUEST_METHOD'];       //请求方法
$uri = $_SERVER['REQUEST_URI'];             //请求URI
$time = date('Y-m-d H:i:s',time());     //访问时间
$post = file_get_contents("php://input",'r');       //接收POST数据
$logadd = 'Visit Time：'.$time.' '.'Visit IP：'.$ip."\r\n".'RequestURI：'.$uri.' '.$parameter.'RequestMethod：'.$method."\r\n";
// log记录
$fh = fopen("/tmp/log.txt", "a+");
fwrite($fh, $logadd);
fwrite($fh, print_r($_COOKIE, true)."\r\n");
fwrite($fh, $post."\r\n");
fclose($fh);
?>
