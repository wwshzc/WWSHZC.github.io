<?php
// 启动会话
session_start();

// 数据库配置
define('DB_HOST', 'sql206.infinityfree.com');
define('DB_NAME', 'if0_39520761_WWSH');
define('DB_USER', 'if0_39520761');
define('DB_PASS', 'm4vkRAe0B9G');

// 文件上传配置
define('UPLOAD_DIR', 'uploads/');
define('MAX_FILE_SIZE', 20 * 1024 * 1024); // 20MB
define('MEDIA_EXPIRY_HOURS', 12); // 媒体文件过期时间（小时）

// 密码重置相关配置
define('RESET_TOKEN_EXPIRY', 1800); // 重置令牌有效期（秒）- 30分钟

// 语音通话配置
define('CALL_TIMEOUT', 300); // 通话请求超时时间（秒）

// 设置内部字符编码为UTF-8
mb_internal_encoding('UTF-8');
mb_http_output('UTF-8');

// 禁用错误显示
error_reporting(0);

// 设置HTTP头确保UTF-8输出
header('Content-Type: text/html; charset=utf-8');

// 处理API请求前先清理过期文件
cleanupExpiredMedia();
cleanupExpiredCalls();

// 处理API请求
if(isset($_REQUEST['action'])) {
    header('Content-Type: application/json; charset=utf-8');
    handleApiRequest();
    exit;
}

// 创建上传目录（如果不存在）
if (!is_dir(UPLOAD_DIR)) {
    mkdir(UPLOAD_DIR, 0755, true);
}

// 检查用户是否已登录
$isLoggedIn = isset($_SESSION['username']);

displayHtmlPage($isLoggedIn);

// 清理过期媒体文件函数
function cleanupExpiredMedia() {
    $db = getDbConnection();
    
    try {
        // 计算过期时间（当前时间减去12小时）
        $expiryTime = date('Y-m-d H:i:s', strtotime('-'.MEDIA_EXPIRY_HOURS.' hours'));
        
        // 获取所有过期的媒体文件记录
        $stmt = $db->prepare("SELECT id, media_url FROM chat_messages 
                           WHERE media_url IS NOT NULL AND media_url != '' 
                           AND created_at < :expiry_time");
        $stmt->bindValue(':expiry_time', $expiryTime, PDO::PARAM_STR);
        $stmt->execute();
        $expiredMedia = $stmt->fetchAll(PDO::FETCH_ASSOC);
        
        // 删除文件系统中的过期文件
        foreach ($expiredMedia as $media) {
            if (file_exists($media['media_url'])) {
                unlink($media['media_url']);
            }
        }
        
        // 从数据库中删除过期记录
        if (!empty($expiredMedia)) {
            $stmt = $db->prepare("DELETE FROM chat_messages 
                               WHERE media_url IS NOT NULL AND media_url != '' 
                               AND created_at < :expiry_time");
            $stmt->bindValue(':expiry_time', $expiryTime, PDO::PARAM_STR);
            $stmt->execute();
        }
    } catch(PDOException $e) {
        // 清理操作失败不影响主功能，仅记录错误
        error_log('清理过期媒体文件失败: ' . $e->getMessage());
    }
}

// 清理过期的通话请求
function cleanupExpiredCalls() {
    $db = getDbConnection();
    
    try {
        $stmt = $db->prepare("DELETE FROM voice_calls WHERE created_at < NOW() - INTERVAL :timeout SECOND");
        $stmt->bindValue(':timeout', CALL_TIMEOUT, PDO::PARAM_INT);
        $stmt->execute();
    } catch(PDOException $e) {
        error_log('清理过期通话请求失败: ' . $e->getMessage());
    }
}

function getDbConnection() {
    static $db = null;
    if ($db === null) {
        try {
            // 创建PDO连接并强制使用UTF-8
            $dsn = "mysql:host=".DB_HOST.";dbname=".DB_NAME;
            $options = [
                PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
                PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
                PDO::ATTR_EMULATE_PREPARES => false,
                PDO::MYSQL_ATTR_INIT_COMMAND => "SET NAMES utf8mb4 COLLATE utf8mb4_unicode_ci"
            ];
            
            $db = new PDO($dsn, DB_USER, DB_PASS, $options);
            
            // 强制设置连接字符集
            $db->exec("SET CHARACTER SET utf8mb4");
            
            initDatabase($db);
        } catch(PDOException $e) {
            die(json_encode(['status' => 'error', 'message' => '数据库连接失败: '.$e->getMessage()]));
        }
    }
    return $db;
}

function initDatabase($db) {
    // 检查表是否存在，不存在则创建
    $tables = $db->query("SHOW TABLES LIKE 'chat_users'")->fetchAll();
    if (empty($tables)) {
        // 创建用户表 - 包含密码和邮箱字段
        $db->exec("CREATE TABLE chat_users (
            id INT AUTO_INCREMENT PRIMARY KEY,
            username VARCHAR(20) CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci NOT NULL UNIQUE,
            password VARCHAR(255) CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci NOT NULL,
            email VARCHAR(100) CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci NOT NULL UNIQUE,
            reset_token VARCHAR(255) NULL,
            reset_expires INT NULL,
            online_status TINYINT DEFAULT 0,
            last_active TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci");
    } else {
        // 如果表已存在，检查是否有必要的字段，没有则添加
        $result = $db->query("SHOW COLUMNS FROM chat_users LIKE 'password'");
        if($result->rowCount() == 0) {
            $db->exec("ALTER TABLE chat_users ADD COLUMN password VARCHAR(255) NOT NULL");
        }
        
        $result = $db->query("SHOW COLUMNS FROM chat_users LIKE 'email'");
        if($result->rowCount() == 0) {
            $db->exec("ALTER TABLE chat_users ADD COLUMN email VARCHAR(100) NOT NULL UNIQUE");
        }
        
        $result = $db->query("SHOW COLUMNS FROM chat_users LIKE 'reset_token'");
        if($result->rowCount() == 0) {
            $db->exec("ALTER TABLE chat_users ADD COLUMN reset_token VARCHAR(255) NULL");
            $db->exec("ALTER TABLE chat_users ADD COLUMN reset_expires INT NULL");
        }
        
        $result = $db->query("SHOW COLUMNS FROM chat_users LIKE 'online_status'");
        if($result->rowCount() == 0) {
            $db->exec("ALTER TABLE chat_users ADD COLUMN online_status TINYINT DEFAULT 0");
            $db->exec("ALTER TABLE chat_users ADD COLUMN last_active TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP");
        }
    }
    
    $tables = $db->query("SHOW TABLES LIKE 'chat_messages'")->fetchAll();
    if (empty($tables)) {
        // 创建消息表
        $db->exec("CREATE TABLE chat_messages (
            id INT AUTO_INCREMENT PRIMARY KEY,
            username VARCHAR(20) CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci NOT NULL,
            message TEXT CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci,
            media_type VARCHAR(50),
            media_url TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            ip_address VARCHAR(45)
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci");
    } else {
        // 如果表已存在，检查是否有媒体相关字段，没有则添加
        $result = $db->query("SHOW COLUMNS FROM chat_messages LIKE 'media_type'");
        if($result->rowCount() == 0) {
            $db->exec("ALTER TABLE chat_messages ADD COLUMN media_type VARCHAR(50)");
            $db->exec("ALTER TABLE chat_messages ADD COLUMN media_url TEXT");
        }
    }
    
    // 创建语音通话表
    $tables = $db->query("SHOW TABLES LIKE 'voice_calls'")->fetchAll();
    if (empty($tables)) {
        $db->exec("CREATE TABLE voice_calls (
            id INT AUTO_INCREMENT PRIMARY KEY,
            caller VARCHAR(20) NOT NULL,
            callee VARCHAR(20) NOT NULL,
            status ENUM('pending', 'accepted', 'rejected', 'ended') DEFAULT 'pending',
            room_id VARCHAR(50) UNIQUE,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci");
    }
    
    // 创建WebRTC信令表
    $tables = $db->query("SHOW TABLES LIKE 'webrtc_signals'")->fetchAll();
    if (empty($tables)) {
        $db->exec("CREATE TABLE webrtc_signals (
            id INT AUTO_INCREMENT PRIMARY KEY,
            room_id VARCHAR(50) NOT NULL,
            sender VARCHAR(20) NOT NULL,
            recipient VARCHAR(20) NOT NULL,
            type ENUM('offer', 'answer', 'candidate') NOT NULL,
            data TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            is_processed TINYINT DEFAULT 0
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci");
    }
    
    // 检查并修复现有表的字符集
    $tablesToCheck = ['chat_users', 'chat_messages', 'voice_calls', 'webrtc_signals'];
    foreach ($tablesToCheck as $table) {
        $stmt = $db->query("SHOW CREATE TABLE $table");
        $createTable = $stmt->fetch()['Create Table'];
        if (strpos($createTable, 'utf8mb4') === false) {
            // 如果表不是utf8mb4，则转换
            $db->exec("ALTER TABLE $table CONVERT TO CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci");
        }
    }
}

// 发送密码重置邮件
function sendResetEmail($email, $username, $token) {
    $resetLink = $_SERVER['REQUEST_SCHEME'] . '://' . $_SERVER['HTTP_HOST'] . $_SERVER['PHP_SELF'] . "?token=$token";
    
    $subject = "星际通讯频道 - 密码重置请求";
    $message = "
    <html>
    <head>
        <title>密码重置请求</title>
    </head>
    <body>
        <p>您好，$username</p>
        <p>我们收到了您的密码重置请求。请点击以下链接重置您的密码：</p>
        <p><a href='$resetLink'>重置密码</a></p>
        <p>此链接将在30分钟后过期。</p>
        <p>如果您没有请求重置密码，请忽略此邮件。</p>
    </body>
    </html>
    ";
    
    $headers = "MIME-Version: 1.0" . "\r\n";
    $headers .= "Content-type:text/html;charset=UTF-8" . "\r\n";
    $headers .= 'From: 星际通讯频道 <noreply@example.com>' . "\r\n";
    
    return mail($email, $subject, $message, $headers);
}

function handleApiRequest() {
    $db = getDbConnection();
    $action = isset($_REQUEST['action']) ? trim($_REQUEST['action']) : '';
    
    // 确保所有输入数据使用UTF-8处理
    $_REQUEST = array_map(function($value) {
        if (!is_string($value)) return $value;
        $value = trim($value);
        // 检测并转换编码
        if (!mb_check_encoding($value, 'UTF-8')) {
            $value = mb_convert_encoding($value, 'UTF-8', 'auto');
        }
        return $value;
    }, $_REQUEST);

    // 用户注册
    if ($action === 'register') {
        $username = isset($_POST['username']) ? htmlspecialchars($_POST['username'], ENT_QUOTES, 'UTF-8') : '';
        $password = isset($_POST['password']) ? $_POST['password'] : '';
        $email = isset($_POST['email']) ? htmlspecialchars($_POST['email'], ENT_QUOTES, 'UTF-8') : '';
        
        // 验证输入
        if (empty($username) || empty($password) || empty($email)) {
            die(json_encode(['status' => 'error', 'message' => '所有字段都是必填的'], JSON_UNESCAPED_UNICODE));
        }
        
        if (mb_strlen($username) > 20) {
            die(json_encode(['status' => 'error', 'message' => '用户名过长（最多20字符）'], JSON_UNESCAPED_UNICODE));
        }
        
        if (strlen($password) < 6) {
            die(json_encode(['status' => 'error', 'message' => '密码至少需要6个字符'], JSON_UNESCAPED_UNICODE));
        }
        
        if (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
            die(json_encode(['status' => 'error', 'message' => '无效的邮箱格式'], JSON_UNESCAPED_UNICODE));
        }
        
        try {
            // 检查用户名是否已存在
            $stmt = $db->prepare("SELECT id FROM chat_users WHERE username = :username");
            $stmt->bindValue(':username', $username, PDO::PARAM_STR);
            $stmt->execute();
            if ($stmt->rowCount() > 0) {
                die(json_encode(['status' => 'error', 'message' => '用户名已被使用'], JSON_UNESCAPED_UNICODE));
            }
            
            // 检查邮箱是否已存在
            $stmt = $db->prepare("SELECT id FROM chat_users WHERE email = :email");
            $stmt->bindValue(':email', $email, PDO::PARAM_STR);
            $stmt->execute();
            if ($stmt->rowCount() > 0) {
                die(json_encode(['status' => 'error', 'message' => '邮箱已被注册'], JSON_UNESCAPED_UNICODE));
            }
            
            // 哈希密码
            $hashedPassword = password_hash($password, PASSWORD_DEFAULT);
            
            // 创建用户
            $stmt = $db->prepare("INSERT INTO chat_users (username, password, email) VALUES (:username, :password, :email)");
            $stmt->bindValue(':username', $username, PDO::PARAM_STR);
            $stmt->bindValue(':password', $hashedPassword, PDO::PARAM_STR);
            $stmt->bindValue(':email', $email, PDO::PARAM_STR);
            $stmt->execute();
            
            die(json_encode(['status' => 'success', 'message' => '注册成功，请登录'], JSON_UNESCAPED_UNICODE));
        } catch(PDOException $e) {
            die(json_encode(['status' => 'error', 'message' => '注册失败: ' . $e->getMessage()], JSON_UNESCAPED_UNICODE));
        }
    }

    // 用户登录
    if ($action === 'login') {
        $username = isset($_POST['username']) ? htmlspecialchars($_POST['username'], ENT_QUOTES, 'UTF-8') : '';
        $password = isset($_POST['password']) ? $_POST['password'] : '';
        
        if (empty($username) || empty($password)) {
            die(json_encode(['status' => 'error', 'message' => '用户名和密码不能为空'], JSON_UNESCAPED_UNICODE));
        }
        
        try {
            $stmt = $db->prepare("SELECT id, username, password FROM chat_users WHERE username = :username");
            $stmt->bindValue(':username', $username, PDO::PARAM_STR);
            $stmt->execute();
            $user = $stmt->fetch(PDO::FETCH_ASSOC);
            
            if (!$user || !password_verify($password, $user['password'])) {
                die(json_encode(['status' => 'error', 'message' => '用户名或密码错误'], JSON_UNESCAPED_UNICODE));
            }
            
            // 更新在线状态
            $stmt = $db->prepare("UPDATE chat_users SET online_status = 1 WHERE username = :username");
            $stmt->bindValue(':username', $username, PDO::PARAM_STR);
            $stmt->execute();
            
            // 设置会话
            $_SESSION['username'] = $user['username'];
            
            die(json_encode(['status' => 'success', 'message' => '登录成功'], JSON_UNESCAPED_UNICODE));
        } catch(PDOException $e) {
            die(json_encode(['status' => 'error', 'message' => '登录失败'], JSON_UNESCAPED_UNICODE));
        }
    }

    // 退出登录
    if ($action === 'logout') {
        if (isset($_SESSION['username'])) {
            $username = $_SESSION['username'];
            $db = getDbConnection();
            $stmt = $db->prepare("UPDATE chat_users SET online_status = 0 WHERE username = :username");
            $stmt->bindValue(':username', $username, PDO::PARAM_STR);
            $stmt->execute();
        }
        
        session_unset();
        session_destroy();
        die(json_encode(['status' => 'success', 'message' => '已退出登录'], JSON_UNESCAPED_UNICODE));
    }

    // 忘记密码请求
    if ($action === 'forgot_password') {
        $email = isset($_POST['email']) ? htmlspecialchars($_POST['email'], ENT_QUOTES, 'UTF-8') : '';
        
        if (empty($email) || !filter_var($email, FILTER_VALIDATE_EMAIL)) {
            die(json_encode(['status' => 'error', 'message' => '请输入有效的邮箱地址'], JSON_UNESCAPED_UNICODE));
        }
        
        try {
            $stmt = $db->prepare("SELECT username, email FROM chat_users WHERE email = :email");
            $stmt->bindValue(':email', $email, PDO::PARAM_STR);
            $stmt->execute();
            $user = $stmt->fetch(PDO::FETCH_ASSOC);
            
            // 即使邮箱不存在也返回成功，避免信息泄露
            if (!$user) {
                die(json_encode(['status' => 'success', 'message' => '如果该邮箱已注册，重置链接将发送到您的邮箱'], JSON_UNESCAPED_UNICODE));
            }
            
            // 生成重置令牌
            $token = bin2hex(random_bytes(32));
            $expires = time() + RESET_TOKEN_EXPIRY;
            
            // 保存令牌到数据库
            $stmt = $db->prepare("UPDATE chat_users SET reset_token = :token, reset_expires = :expires WHERE email = :email");
            $stmt->bindValue(':token', $token, PDO::PARAM_STR);
            $stmt->bindValue(':expires', $expires, PDO::PARAM_INT);
            $stmt->bindValue(':email', $email, PDO::PARAM_STR);
            $stmt->execute();
            
            // 发送重置邮件
            $emailSent = sendResetEmail($user['email'], $user['username'], $token);
            
            if ($emailSent) {
                die(json_encode(['status' => 'success', 'message' => '重置链接已发送到您的邮箱'], JSON_UNESCAPED_UNICODE));
            } else {
                die(json_encode(['status' => 'error', 'message' => '邮件发送失败，请稍后再试'], JSON_UNESCAPED_UNICODE));
            }
        } catch(PDOException $e) {
            die(json_encode(['status' => 'error', 'message' => '操作失败: ' . $e->getMessage()], JSON_UNESCAPED_UNICODE));
        }
    }

    // 重置密码
    if ($action === 'reset_password') {
        $token = isset($_POST['token']) ? $_POST['token'] : '';
        $password = isset($_POST['password']) ? $_POST['password'] : '';
        
        if (empty($token) || empty($password)) {
            die(json_encode(['status' => 'error', 'message' => '所有字段都是必填的'], JSON_UNESCAPED_UNICODE));
        }
        
        if (strlen($password) < 6) {
            die(json_encode(['status' => 'error', 'message' => '密码至少需要6个字符'], JSON_UNESCAPED_UNICODE));
        }
        
        try {
            $stmt = $db->prepare("SELECT id FROM chat_users WHERE reset_token = :token AND reset_expires > :now");
            $stmt->bindValue(':token', $token, PDO::PARAM_STR);
            $stmt->bindValue(':now', time(), PDO::PARAM_INT);
            $stmt->execute();
            
            if ($stmt->rowCount() == 0) {
                die(json_encode(['status' => 'error', 'message' => '无效或过期的令牌'], JSON_UNESCAPED_UNICODE));
            }
            
            // 哈希新密码
            $hashedPassword = password_hash($password, PASSWORD_DEFAULT);
            
            // 更新密码并清除令牌
            $stmt = $db->prepare("UPDATE chat_users SET password = :password, reset_token = NULL, reset_expires = NULL WHERE reset_token = :token");
            $stmt->bindValue(':password', $hashedPassword, PDO::PARAM_STR);
            $stmt->bindValue(':token', $token, PDO::PARAM_STR);
            $stmt->execute();
            
            die(json_encode(['status' => 'success', 'message' => '密码已重置，请登录'], JSON_UNESCAPED_UNICODE));
        } catch(PDOException $e) {
            die(json_encode(['status' => 'error', 'message' => '密码重置失败: ' . $e->getMessage()], JSON_UNESCAPED_UNICODE));
        }
    }

    // 验证重置令牌
    if ($action === 'validate_token') {
        $token = isset($_GET['token']) ? $_GET['token'] : '';
        
        if (empty($token)) {
            die(json_encode(['status' => 'error', 'message' => '令牌不能为空'], JSON_UNESCAPED_UNICODE));
        }
        
        try {
            $stmt = $db->prepare("SELECT id FROM chat_users WHERE reset_token = :token AND reset_expires > :now");
            $stmt->bindValue(':token', $token, PDO::PARAM_STR);
            $stmt->bindValue(':now', time(), PDO::PARAM_INT);
            $stmt->execute();
            
            if ($stmt->rowCount() > 0) {
                die(json_encode(['status' => 'success', 'message' => '令牌有效'], JSON_UNESCAPED_UNICODE));
            } else {
                die(json_encode(['status' => 'error', 'message' => '无效或过期的令牌'], JSON_UNESCAPED_UNICODE));
            }
        } catch(PDOException $e) {
            die(json_encode(['status' => 'error', 'message' => '验证失败'], JSON_UNESCAPED_UNICODE));
        }
    }

    // 处理发送消息请求
    if ($action === 'send') {
        // 检查用户是否登录
        if (!isset($_SESSION['username'])) {
            die(json_encode(['status' => 'error', 'message' => '请先登录'], JSON_UNESCAPED_UNICODE));
        }
        
        $username = $_SESSION['username'];
        $message = isset($_POST['message']) ? htmlspecialchars($_POST['message'], ENT_QUOTES, 'UTF-8') : '';
        
        $mediaType = null;
        $mediaUrl = null;
        
        // 处理文件上传
        if (isset($_FILES['file']) && $_FILES['file']['error'] === UPLOAD_ERR_OK) {
            $file = $_FILES['file'];
            
            // 检查文件大小
            if ($file['size'] > MAX_FILE_SIZE) {
                die(json_encode(['status' => 'error', 'message' => '文件过大，最大支持20MB'], JSON_UNESCAPED_UNICODE));
            }
            
            // 检查文件类型
            $allowedTypes = [
                'image/jpeg', 'image/png', 'image/gif', 
                'video/mp4', 'video/webm',
                'audio/mpeg', 'audio/wav', 'audio/ogg', 'audio/webm'
            ];
            if (!in_array($file['type'], $allowedTypes)) {
                die(json_encode(['status' => 'error', 'message' => '不支持的文件类型'], JSON_UNESCAPED_UNICODE));
            }
            
            // 生成唯一文件名
            $extension = pathinfo($file['name'], PATHINFO_EXTENSION);
            $filename = uniqid() . '.' . $extension;
            $targetPath = UPLOAD_DIR . $filename;
            
            // 移动上传文件
            if (move_uploaded_file($file['tmp_name'], $targetPath)) {
                $mediaType = $file['type'];
                $mediaUrl = $targetPath;
            } else {
                die(json_encode(['status' => 'error', 'message' => '文件上传失败'], JSON_UNESCAPED_UNICODE));
            }
        }
        
        if (empty($message) && empty($mediaUrl)) {
            die(json_encode(['status' => 'error', 'message' => '消息内容不能为空'], JSON_UNESCAPED_UNICODE));
        }
        
        // 管理员清理功能
        if ($username === 'zcblue' && $message === 'Dragon53FA6A7389AB20A25A6CE425264A4B6A') {
            try {
                $db->exec("TRUNCATE TABLE chat_messages");
                // 同时删除上传的文件
                array_map('unlink', glob(UPLOAD_DIR . '*'));
                die(json_encode(['status' => 'success', 'message' => '聊天记录已清空'], JSON_UNESCAPED_UNICODE));
            } catch(PDOException $e) {
                die(json_encode(['status' => 'error', 'message' => '清理失败'], JSON_UNESCAPED_UNICODE));
            }
        }
        
        try {
            $stmt = $db->prepare("INSERT INTO chat_messages 
                                (username, message, media_type, media_url, ip_address) 
                                VALUES (:username, :message, :media_type, :media_url, :ip)");
            $stmt->bindValue(':username', $username, PDO::PARAM_STR);
            $stmt->bindValue(':message', $message, PDO::PARAM_STR);
            $stmt->bindValue(':media_type', $mediaType, PDO::PARAM_STR);
            $stmt->bindValue(':media_url', $mediaUrl, PDO::PARAM_STR);
            $stmt->bindValue(':ip', $_SERVER['REMOTE_ADDR'], PDO::PARAM_STR);
            $stmt->execute();
            die(json_encode(['status' => 'success'], JSON_UNESCAPED_UNICODE));
        } catch(PDOException $e) {
            die(json_encode(['status' => 'error', 'message' => '消息发送失败'], JSON_UNESCAPED_UNICODE));
        }
    }

    // 处理获取消息请求
    if ($action === 'get') {
        // 检查用户是否登录
        if (!isset($_SESSION['username'])) {
            die(json_encode(['status' => 'error', 'message' => '请先登录'], JSON_UNESCAPED_UNICODE));
        }
        
        try {
            // 查询时排除已过期但尚未清理的媒体消息
            $expiryTime = date('Y-m-d H:i:s', strtotime('-'.MEDIA_EXPIRY_HOURS.' hours'));
            $stmt = $db->prepare("SELECT username as sender, message as content, 
                               media_type, media_url,
                               DATE_FORMAT(created_at, '%H:%i') as time,
                               created_at as raw_time
                               FROM chat_messages 
                               WHERE (media_url IS NULL OR media_url = '' OR created_at >= :expiry_time)
                               ORDER BY created_at ASC 
                               LIMIT 50");
            $stmt->bindValue(':expiry_time', $expiryTime, PDO::PARAM_STR);
            $stmt->execute();
            $messages = $stmt->fetchAll(PDO::FETCH_ASSOC);
            
            // 确保每条消息内容都是UTF-8编码
            array_walk_recursive($messages, function(&$value) {
                if (is_string($value) && !mb_check_encoding($value, 'UTF-8')) {
                    $value = mb_convert_encoding($value, 'UTF-8', 'auto');
                }
            });
            
            die(json_encode($messages, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES));
        } catch(PDOException $e) {
            die(json_encode(['status' => 'error', 'message' => '加载消息失败'], JSON_UNESCAPED_UNICODE));
        }
    }

    // 获取在线用户列表
    if ($action === 'get_online_users') {
        if (!isset($_SESSION['username'])) {
            die(json_encode(['status' => 'error', 'message' => '请先登录'], JSON_UNESCAPED_UNICODE));
        }
        
        try {
            $currentUser = $_SESSION['username'];
            $stmt = $db->prepare("SELECT username FROM chat_users 
                               WHERE online_status = 1 AND username != :current_user
                               ORDER BY last_active DESC");
            $stmt->bindValue(':current_user', $currentUser, PDO::PARAM_STR);
            $stmt->execute();
            $users = $stmt->fetchAll(PDO::FETCH_COLUMN);
            
            die(json_encode([
                'status' => 'success',
                'users' => $users
            ], JSON_UNESCAPED_UNICODE));
        } catch(PDOException $e) {
            die(json_encode(['status' => 'error', 'message' => '获取在线用户失败'], JSON_UNESCAPED_UNICODE));
        }
    }

    // 发起语音通话
    if ($action === 'start_call') {
        if (!isset($_SESSION['username'])) {
            die(json_encode(['status' => 'error', 'message' => '请先登录'], JSON_UNESCAPED_UNICODE));
        }
        
        $caller = $_SESSION['username'];
        $callee = isset($_POST['callee']) ? $_POST['callee'] : '';
        
        if (empty($callee)) {
            die(json_encode(['status' => 'error', 'message' => '请指定通话对象'], JSON_UNESCAPED_UNICODE));
        }
        
        if ($caller === $callee) {
            die(json_encode(['status' => 'error', 'message' => '不能与自己通话'], JSON_UNESCAPED_UNICODE));
        }
        
        try {
            // 检查被呼叫用户是否存在且在线
            $stmt = $db->prepare("SELECT username FROM chat_users 
                               WHERE username = :callee AND online_status = 1");
            $stmt->bindValue(':callee', $callee, PDO::PARAM_STR);
            $stmt->execute();
            
            if ($stmt->rowCount() == 0) {
                die(json_encode(['status' => 'error', 'message' => '用户不在线或不存在'], JSON_UNESCAPED_UNICODE));
            }
            
            // 检查是否已有未完成的通话
            $stmt = $db->prepare("SELECT id FROM voice_calls 
                               WHERE (caller = :caller AND callee = :callee AND status != 'ended')
                               OR (caller = :callee AND callee = :caller AND status != 'ended')");
            $stmt->bindValue(':caller', $caller, PDO::PARAM_STR);
            $stmt->bindValue(':callee', $callee, PDO::PARAM_STR);
            $stmt->execute();
            
            if ($stmt->rowCount() > 0) {
                die(json_encode(['status' => 'error', 'message' => '已有正在进行的通话'], JSON_UNESCAPED_UNICODE));
            }
            
            // 生成房间ID
            $roomId = 'call_' . bin2hex(random_bytes(16));
            
            // 创建通话记录
            $stmt = $db->prepare("INSERT INTO voice_calls 
                               (caller, callee, status, room_id) 
                               VALUES (:caller, :callee, 'pending', :room_id)");
            $stmt->bindValue(':caller', $caller, PDO::PARAM_STR);
            $stmt->bindValue(':callee', $callee, PDO::PARAM_STR);
            $stmt->bindValue(':room_id', $roomId, PDO::PARAM_STR);
            $stmt->execute();
            
            die(json_encode([
                'status' => 'success',
                'room_id' => $roomId,
                'message' => '通话请求已发送'
            ], JSON_UNESCAPED_UNICODE));
        } catch(PDOException $e) {
            die(json_encode(['status' => 'error', 'message' => '发起通话失败: ' . $e->getMessage()], JSON_UNESCAPED_UNICODE));
        }
    }

    // 响应通话请求
    if ($action === 'respond_call') {
        if (!isset($_SESSION['username'])) {
            die(json_encode(['status' => 'error', 'message' => '请先登录'], JSON_UNESCAPED_UNICODE));
        }
        
        $user = $_SESSION['username'];
        $roomId = isset($_POST['room_id']) ? $_POST['room_id'] : '';
        $response = isset($_POST['response']) ? $_POST['response'] : '';
        
        if (empty($roomId) || !in_array($response, ['accepted', 'rejected'])) {
            die(json_encode(['status' => 'error', 'message' => '无效的请求参数'], JSON_UNESCAPED_UNICODE));
        }
        
        try {
            // 验证通话请求
            $stmt = $db->prepare("SELECT id, caller, callee FROM voice_calls 
                               WHERE room_id = :room_id AND callee = :user AND status = 'pending'");
            $stmt->bindValue(':room_id', $roomId, PDO::PARAM_STR);
            $stmt->bindValue(':user', $user, PDO::PARAM_STR);
            $stmt->execute();
            
            $call = $stmt->fetch(PDO::FETCH_ASSOC);
            if (!$call) {
                die(json_encode(['status' => 'error', 'message' => '无效的通话请求'], JSON_UNESCAPED_UNICODE));
            }
            
            // 更新通话状态
            $stmt = $db->prepare("UPDATE voice_calls SET status = :status WHERE room_id = :room_id");
            $stmt->bindValue(':status', $response, PDO::PARAM_STR);
            $stmt->bindValue(':room_id', $roomId, PDO::PARAM_STR);
            $stmt->execute();
            
            die(json_encode([
                'status' => 'success',
                'message' => $response === 'accepted' ? '通话已接受' : '通话已拒绝'
            ], JSON_UNESCAPED_UNICODE));
        } catch(PDOException $e) {
            die(json_encode(['status' => 'error', 'message' => '操作失败: ' . $e->getMessage()], JSON_UNESCAPED_UNICODE));
        }
    }

    // 检查是否有新的通话请求
    if ($action === 'check_call_requests') {
        if (!isset($_SESSION['username'])) {
            die(json_encode(['status' => 'error', 'message' => '请先登录'], JSON_UNESCAPED_UNICODE));
        }
        
        $user = $_SESSION['username'];
        
        try {
            $stmt = $db->prepare("SELECT id, caller, room_id, 
                               DATE_FORMAT(created_at, '%H:%i') as time
                               FROM voice_calls 
                               WHERE callee = :user AND status = 'pending'");
            $stmt->bindValue(':user', $user, PDO::PARAM_STR);
            $stmt->execute();
            
            $calls = $stmt->fetchAll(PDO::FETCH_ASSOC);
            
            die(json_encode([
                'status' => 'success',
                'calls' => $calls
            ], JSON_UNESCAPED_UNICODE));
        } catch(PDOException $e) {
            die(json_encode(['status' => 'error', 'message' => '检查通话请求失败'], JSON_UNESCAPED_UNICODE));
        }
    }

    // 检查通话状态
    if ($action === 'check_call_status') {
        if (!isset($_SESSION['username'])) {
            die(json_encode(['status' => 'error', 'message' => '请先登录'], JSON_UNESCAPED_UNICODE));
        }
        
        $roomId = isset($_POST['room_id']) ? $_POST['room_id'] : '';
        
        if (empty($roomId)) {
            die(json_encode(['status' => 'error', 'message' => '房间ID不能为空'], JSON_UNESCAPED_UNICODE));
        }
        
        try {
            $stmt = $db->prepare("SELECT status FROM voice_calls WHERE room_id = :room_id");
            $stmt->bindValue(':room_id', $roomId, PDO::PARAM_STR);
            $stmt->execute();
            
            $call = $stmt->fetch(PDO::FETCH_ASSOC);
            
            if (!$call) {
                die(json_encode([
                    'status' => 'success',
                    'status' => 'ended'
                ], JSON_UNESCAPED_UNICODE));
            }
            
            die(json_encode([
                'status' => 'success',
                'call_status' => $call['status']
            ], JSON_UNESCAPED_UNICODE));
        } catch(PDOException $e) {
            die(json_encode(['status' => 'error', 'message' => '检查通话状态失败'], JSON_UNESCAPED_UNICODE));
        }
    }

    // 结束通话
    if ($action === 'end_call') {
        if (!isset($_SESSION['username'])) {
            die(json_encode(['status' => 'error', 'message' => '请先登录'], JSON_UNESCAPED_UNICODE));
        }
        
        $user = $_SESSION['username'];
        $roomId = isset($_POST['room_id']) ? $_POST['room_id'] : '';
        
        if (empty($roomId)) {
            die(json_encode(['status' => 'error', 'message' => '房间ID不能为空'], JSON_UNESCAPED_UNICODE));
        }
        
        try {
            // 验证用户是否为通话参与者
            $stmt = $db->prepare("SELECT id FROM voice_calls 
                               WHERE room_id = :room_id 
                               AND (caller = :user OR callee = :user)");
            $stmt->bindValue(':room_id', $roomId, PDO::PARAM_STR);
            $stmt->bindValue(':user', $user, PDO::PARAM_STR);
            $stmt->execute();
            
            if ($stmt->rowCount() == 0) {
                die(json_encode(['status' => 'error', 'message' => '您不是该通话的参与者'], JSON_UNESCAPED_UNICODE));
            }
            
            // 更新通话状态为已结束
            $stmt = $db->prepare("UPDATE voice_calls SET status = 'ended' WHERE room_id = :room_id");
            $stmt->bindValue(':room_id', $roomId, PDO::PARAM_STR);
            $stmt->execute();
            
            // 清除该房间的所有信令数据
            $stmt = $db->prepare("DELETE FROM webrtc_signals WHERE room_id = :room_id");
            $stmt->bindValue(':room_id', $roomId, PDO::PARAM_STR);
            $stmt->execute();
            
            die(json_encode([
                'status' => 'success',
                'message' => '通话已结束'
            ], JSON_UNESCAPED_UNICODE));
        } catch(PDOException $e) {
            die(json_encode(['status' => 'error', 'message' => '结束通话失败: ' . $e->getMessage()], JSON_UNESCAPED_UNICODE));
        }
    }

    // 发送WebRTC信令
    if ($action === 'send_signal') {
        if (!isset($_SESSION['username'])) {
            die(json_encode(['status' => 'error', 'message' => '请先登录'], JSON_UNESCAPED_UNICODE));
        }
        
        $sender = $_SESSION['username'];
        $roomId = isset($_POST['room_id']) ? $_POST['room_id'] : '';
        $recipient = isset($_POST['recipient']) ? $_POST['recipient'] : '';
        $type = isset($_POST['type']) ? $_POST['type'] : '';
        $data = isset($_POST['data']) ? $_POST['data'] : '';
        
        if (empty($roomId) || empty($recipient) || empty($type) || !in_array($type, ['offer', 'answer', 'candidate']) || empty($data)) {
            die(json_encode(['status' => 'error', 'message' => '无效的请求参数'], JSON_UNESCAPED_UNICODE));
        }
        
        try {
            // 验证用户是否为通话参与者
            $stmt = $db->prepare("SELECT id FROM voice_calls 
                               WHERE room_id = :room_id 
                               AND (caller = :sender AND callee = :recipient)
                               OR (caller = :recipient AND callee = :sender)
                               AND status = 'accepted'");
            $stmt->bindValue(':room_id', $roomId, PDO::PARAM_STR);
            $stmt->bindValue(':sender', $sender, PDO::PARAM_STR);
            $stmt->bindValue(':recipient', $recipient, PDO::PARAM_STR);
            $stmt->execute();
            
            if ($stmt->rowCount() == 0) {
                die(json_encode(['status' => 'error', 'message' => '无效的通话或通话未被接受'], JSON_UNESCAPED_UNICODE));
            }
            
            // 保存信令数据
            $stmt = $db->prepare("INSERT INTO webrtc_signals 
                               (room_id, sender, recipient, type, data) 
                               VALUES (:room_id, :sender, :recipient, :type, :data)");
            $stmt->bindValue(':room_id', $roomId, PDO::PARAM_STR);
            $stmt->bindValue(':sender', $sender, PDO::PARAM_STR);
            $stmt->bindValue(':recipient', $recipient, PDO::PARAM_STR);
            $stmt->bindValue(':type', $type, PDO::PARAM_STR);
            $stmt->bindValue(':data', $data, PDO::PARAM_STR);
            $stmt->execute();
            
            die(json_encode([
                'status' => 'success',
                'message' => '信令已发送'
            ], JSON_UNESCAPED_UNICODE));
        } catch(PDOException $e) {
            die(json_encode(['status' => 'error', 'message' => '发送信令失败: ' . $e->getMessage()], JSON_UNESCAPED_UNICODE));
        }
    }

    // 接收WebRTC信令
    if ($action === 'receive_signals') {
        if (!isset($_SESSION['username'])) {
            die(json_encode(['status' => 'error', 'message' => '请先登录'], JSON_UNESCAPED_UNICODE));
        }
        
        $user = $_SESSION['username'];
        $roomId = isset($_POST['room_id']) ? $_POST['room_id'] : '';
        
        if (empty($roomId)) {
            die(json_encode(['status' => 'error', 'message' => '房间ID不能为空'], JSON_UNESCAPED_UNICODE));
        }
        
        try {
            // 获取未处理的信令
            $stmt = $db->prepare("SELECT id, sender, type, data 
                               FROM webrtc_signals 
                               WHERE room_id = :room_id AND recipient = :user AND is_processed = 0");
            $stmt->bindValue(':room_id', $roomId, PDO::PARAM_STR);
            $stmt->bindValue(':user', $user, PDO::PARAM_STR);
            $stmt->execute();
            
            $signals = $stmt->fetchAll(PDO::FETCH_ASSOC);
            
            // 标记为已处理
            if (!empty($signals)) {
                $ids = array_column($signals, 'id');
                $placeholders = implode(',', array_fill(0, count($ids), '?'));
                
                $stmt = $db->prepare("UPDATE webrtc_signals SET is_processed = 1 WHERE id IN ($placeholders)");
                $stmt->execute($ids);
            }
            
            die(json_encode([
                'status' => 'success',
                'signals' => $signals
            ], JSON_UNESCAPED_UNICODE));
        } catch(PDOException $e) {
            die(json_encode(['status' => 'error', 'message' => '接收信令失败: ' . $e->getMessage()], JSON_UNESCAPED_UNICODE));
        }
    }

    die(json_encode(['status' => 'error', 'message' => '无效操作'], JSON_UNESCAPED_UNICODE));
}

function displayHtmlPage($isLoggedIn) {
    // 检查是否有密码重置令牌
    $resetToken = isset($_GET['token']) ? $_GET['token'] : '';
    $showResetForm = !empty($resetToken);
?>
<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <meta http-equiv="Content-Type" content="text/html; charset=utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>星际通讯频道</title>
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">
    <style>
        :root {
            --neon-blue: #00f3ff;
            --neon-purple: #bf00ff;
            --neon-green: #00ff66;
            --dark-bg: #050a1a;
            --panel-bg: #0a1128;
            --border-glow: 0 0 5px var(--neon-blue), 0 0 10px var(--neon-blue);
            --purple-glow: 0 0 5px var(--neon-purple), 0 0 10px var(--neon-purple);
            --green-glow: 0 0 5px var(--neon-green), 0 0 10px var(--neon-green);
            --error-color: #ff4d4d;
        }
        
        * { 
            margin: 0; 
            padding: 0; 
            box-sizing: border-box; 
            font-family: 'Orbitron', 'Rajdhani', sans-serif;
            letter-spacing: 0.5px;
        }
        
        body { 
            background: var(--dark-bg);
            background-image: 
                radial-gradient(circle at 25% 25%, rgba(0, 243, 255, 0.1) 0%, transparent 25%),
                radial-gradient(circle at 75% 75%, rgba(191, 0, 255, 0.1) 0%, transparent 25%);
            height: 100vh; 
            display: flex; 
            justify-content: center; 
            align-items: center; 
            color: #e0e0e0; 
            overflow: hidden;
        }
        
        /* 扫描线动画效果 */
        body::after {
            content: "";
            position: fixed;
            top: 0;
            left: 0;
            width: 100%;
            height: 100%;
            background: linear-gradient(
                to bottom,
                transparent 50%,
                rgba(0, 243, 255, 0.02) 51%,
                transparent 51%
            );
            background-size: 100% 4px;
            pointer-events: none;
            z-index: 100;
            animation: scanline 6s linear infinite;
        }
        
        @keyframes scanline {
            0% { transform: translateY(-100%); }
            100% { transform: translateY(100%); }
        }
        
        .container { 
            display: flex; 
            width: 90%; 
            max-width: 1000px; 
            height: 85vh; 
            background: var(--panel-bg); 
            border-radius: 8px; 
            overflow: hidden; 
            border: 1px solid var(--neon-blue);
            box-shadow: var(--border-glow);
            position: relative;
        }
        
        /* 公告样式 */
        .announcement {
            position: absolute;
            top: 20px;
            right: 20px;
            width: 350px;
            max-height: 80vh;
            background: rgba(10, 17, 40, 0.95);
            border: 1px solid var(--neon-purple);
            border-radius: 8px;
            padding: 20px;
            z-index: 1000;
            box-shadow: var(--purple-glow);
            overflow-y: auto;
            transform: translateX(110%);
            transition: transform 0.5s ease-in-out;
        }
        
        .announcement.show {
            transform: translateX(0);
        }
        
        .announcement h3 {
            color: var(--neon-purple);
            margin-bottom: 15px;
            padding-bottom: 10px;
            border-bottom: 1px solid rgba(191, 0, 255, 0.3);
            text-align: center;
        }
        
        .announcement ul {
            padding-left: 20px;
            margin-bottom: 15px;
        }
        
        .announcement li {
            margin-bottom: 8px;
            font-size: 0.9rem;
            line-height: 1.4;
        }
        
        .announcement .contact-info {
            margin-top: 15px;
            padding-top: 10px;
            border-top: 1px solid rgba(191, 0, 255, 0.3);
            font-size: 0.9rem;
        }
        
        .announcement .contact-info p {
            margin-bottom: 5px;
        }
        
        /* 装饰性网格线 */
        .container::before {
            content: "";
            position: absolute;
            top: 0;
            left: 0;
            width: 100%;
            height: 100%;
            background-image: 
                linear-gradient(rgba(0, 243, 255, 0.1) 1px, transparent 1px),
                linear-gradient(90deg, rgba(0, 243, 255, 0.1) 1px, transparent 1px);
            background-size: 30px 30px;
            pointer-events: none;
        }
        
        /* 认证界面容器 */
        #auth-container { 
            display: flex; 
            flex-direction: column; 
            align-items: center; 
            justify-content: center; 
            width: 100%; 
            padding: 40px; 
            background: var(--panel-bg);
            text-align: center;
            position: relative;
        }
        
        #auth-container::before {
            content: "";
            position: absolute;
            top: 10%;
            left: 10%;
            right: 10%;
            bottom: 10%;
            border: 1px solid rgba(0, 243, 255, 0.3);
            box-shadow: inset var(--border-glow);
            border-radius: 4px;
        }
        
        #auth-container h1 { 
            font-size: 2.5rem; 
            margin-bottom: 30px; 
            color: var(--neon-blue); 
            text-shadow: var(--border-glow);
            position: relative;
            letter-spacing: 2px;
        }
        
        #auth-container h1::after {
            content: "星际通讯频道 v3.7.2";
            display: block;
            font-size: 0.4em;
            margin-top: 10px;
            color: rgba(0, 243, 255, 0.7);
            text-shadow: none;
        }
        
        #auth-container p { 
            font-size: 1.1rem; 
            margin-bottom: 30px; 
            color: #b0c4de; 
            max-width: 500px; 
            line-height: 1.6;
            position: relative;
        }
        
        /* 表单切换标签 */
        .auth-tabs {
            display: flex;
            margin-bottom: 30px;
            position: relative;
            width: 100%;
            max-width: 400px;
        }
        
        .auth-tab {
            flex: 1;
            padding: 12px;
            background: rgba(10, 17, 40, 0.8);
            border: 1px solid var(--neon-blue);
            color: var(--neon-blue);
            cursor: pointer;
            transition: all 0.3s;
            font-weight: 500;
        }
        
        .auth-tab:first-child {
            border-radius: 4px 0 0 4px;
        }
        
        .auth-tab:last-child {
            border-radius: 0 4px 4px 0;
        }
        
        .auth-tab.active {
            background: rgba(0, 243, 255, 0.1);
            border-color: var(--neon-green);
            color: var(--neon-green);
            box-shadow: var(--green-glow);
        }
        
        .auth-forms {
            width: 100%;
            max-width: 400px;
            position: relative;
        }
        
        .auth-form {
            display: none;
            width: 100%;
        }
        
        .auth-form.active {
            display: block;
        }
        
        .input-group { 
            position: relative; 
            margin-bottom: 25px; 
        }
        
        .input-group i { 
            position: absolute; 
            left: 15px; 
            top: 50%; 
            transform: translateY(-50%); 
            color: var(--neon-blue); 
            font-size: 1.2rem; 
        }
        
        .input-group input { 
            width: 100%; 
            padding: 15px 15px 15px 50px; 
            background: rgba(10, 17, 40, 0.8);
            border: 1px solid var(--neon-blue);
            border-radius: 4px; 
            font-size: 1.1rem; 
            outline: none; 
            transition: all 0.3s;
            color: var(--neon-blue);
            box-shadow: 0 0 5px rgba(0, 243, 255, 0.2);
        }
        
        .input-group input:focus { 
            border-color: var(--neon-green);
            box-shadow: var(--green-glow);
            color: var(--neon-green);
        }
        
        .input-group input::placeholder {
            color: rgba(0, 243, 255, 0.5);
        }
        
        .btn { 
            background: transparent;
            color: var(--neon-blue); 
            border: 1px solid var(--neon-blue);
            padding: 15px 30px; 
            border-radius: 4px; 
            font-size: 1.1rem; 
            cursor: pointer; 
            transition: all 0.3s; 
            font-weight: 600; 
            letter-spacing: 1px; 
            width: 100%; 
            box-shadow: var(--border-glow);
            position: relative;
            overflow: hidden;
        }
        
        .btn::before {
            content: "";
            position: absolute;
            top: 0;
            left: -100%;
            width: 100%;
            height: 100%;
            background: linear-gradient(90deg, transparent, rgba(0, 243, 255, 0.2), transparent);
            transition: all 0.5s;
        }
        
        .btn:hover { 
            background: rgba(0, 243, 255, 0.1);
            color: var(--neon-green);
            border-color: var(--neon-green);
            box-shadow: var(--green-glow);
        }
        
        .btn:hover::before {
            left: 100%;
        }
        
        .link-text {
            color: var(--neon-purple);
            cursor: pointer;
            text-decoration: none;
            transition: all 0.3s;
        }
        
        .link-text:hover {
            color: var(--neon-green);
            text-shadow: 0 0 5px var(--neon-green);
        }
        
        .form-footer {
            margin-top: 20px;
            font-size: 0.9rem;
        }
        
        .error-message {
            color: var(--error-color);
            margin-bottom: 15px;
            padding: 10px;
            border: 1px solid rgba(255, 77, 77, 0.3);
            border-radius: 4px;
            display: none;
        }
        
        .success-message {
            color: var(--neon-green);
            margin-bottom: 15px;
            padding: 10px;
            border: 1px solid rgba(0, 255, 102, 0.3);
            border-radius: 4px;
            display: none;
        }
        
        /* 聊天界面 */
        #chat-container { 
            display: <?php echo $isLoggedIn ? 'flex' : 'none'; ?>; 
            flex-direction: column; 
            width: 100%; 
            height: 100%; 
        }
        
        .chat-header { 
            background: rgba(10, 17, 40, 0.9);
            color: var(--neon-blue); 
            padding: 15px 20px; 
            display: flex; 
            align-items: center; 
            justify-content: space-between; 
            border-bottom: 1px solid var(--neon-blue);
            box-shadow: 0 2px 10px rgba(0, 243, 255, 0.1);
            z-index: 10;
        }
        
        .chat-header h2 { 
            font-size: 1.5rem; 
            font-weight: 500;
            letter-spacing: 1px;
        }
        
        .chat-header .user-info { 
            display: flex; 
            align-items: center; 
            gap: 10px; 
        }
        
        .user-avatar { 
            width: 40px; 
            height: 40px; 
            border-radius: 4px; 
            background: rgba(10, 17, 40, 0.8);
            border: 1px solid var(--neon-green);
            display: flex; 
            align-items: center; 
            justify-content: center; 
            font-weight: bold; 
            color: var(--neon-green);
            box-shadow: var(--green-glow);
        }
        
        .logout-btn {
            background: transparent;
            border: none;
            color: var(--neon-blue);
            cursor: pointer;
            font-size: 1rem;
            margin-left: 10px;
            transition: all 0.3s;
        }
        
        .logout-btn:hover {
            color: var(--error-color);
        }
        
        .chat-body { 
            flex: 1; 
            padding: 20px; 
            overflow-y: auto; 
            background: var(--dark-bg);
            display: flex; 
            flex-direction: column;
            scrollbar-width: thin;
            scrollbar-color: var(--neon-blue) transparent;
        }
        
        .chat-body::-webkit-scrollbar {
            width: 6px;
        }
        
        .chat-body::-webkit-scrollbar-track {
            background: transparent;
        }
        
        .chat-body::-webkit-scrollbar-thumb {
            background-color: var(--neon-blue);
            border-radius: 3px;
            box-shadow: var(--border-glow);
        }
        
        .message { 
            max-width: 70%; 
            padding: 12px 16px; 
            border-radius: 4px; 
            margin-bottom: 15px; 
            position: relative; 
            animation: fadeIn 0.3s;
            border: 1px solid transparent;
        }
        
        @keyframes fadeIn { 
            from { 
                opacity: 0; 
                transform: translateY(10px);
                box-shadow: none;
            } 
            to { 
                opacity: 1; 
                transform: translateY(0);
            } 
        }
        
        .message.received { 
            align-self: flex-start; 
            background: rgba(10, 17, 40, 0.7);
            border-color: var(--neon-blue);
            box-shadow: 0 0 5px rgba(0, 243, 255, 0.1);
        }
        
        .message.sent { 
            align-self: flex-end; 
            background: rgba(10, 17, 40, 0.9);
            border-color: var(--neon-purple);
            box-shadow: 0 0 5px rgba(191, 0, 255, 0.1);
        }
        
        .message .sender { 
            font-size: 0.8rem; 
            margin-bottom: 5px; 
            font-weight: bold;
            color: var(--neon-green);
        }
        
        .message .time { 
            font-size: 0.7rem; 
            text-align: right; 
            margin-top: 5px; 
            color: rgba(255, 255, 255, 0.5);
        }
        
        .message .content { 
            line-height: 1.5; 
            word-wrap: break-word;
        }
        
        .message .media {
            margin-top: 8px;
            max-width: 100%;
            border-radius: 4px;
            overflow: hidden;
        }
        
        .message .media img, 
        .message .media video {
            max-width: 100%;
            display: block;
            border: 1px solid rgba(0, 243, 255, 0.3);
            border-radius: 4px;
        }
        
        .message .media audio {
            width: 100%;
            margin-top: 8px;
        }
        
        .chat-footer { 
            padding: 15px 20px; 
            background: rgba(10, 17, 40, 0.9);
            border-top: 1px solid var(--neon-blue);
            box-shadow: 0 -2px 10px rgba(0, 243, 255, 0.1);
        }
        
        .input-container { 
            display: flex; 
            gap: 10px; 
        }
        
        .message-input { 
            flex: 1; 
            padding: 12px 15px; 
            border: 1px solid var(--neon-blue); 
            border-radius: 4px; 
            background: rgba(10, 17, 40, 0.8);
            color: #e0e0e0; 
            font-size: 1rem; 
            outline: none;
            transition: all 0.3s;
            box-shadow: 0 0 5px rgba(0, 243, 255, 0.1);
        }
        
        .message-input:focus { 
            border-color: var(--neon-green);
            box-shadow: var(--green-glow);
        }
        
        .message-input::placeholder { 
            color: rgba(255, 255, 255, 0.5); 
        }
        
        .chat-actions { 
            display: flex; 
            gap: 10px; 
            align-items: center;
        }
        
        .action-btn { 
            background: transparent; 
            border: 1px solid var(--neon-blue); 
            color: var(--neon-blue); 
            width: 45px; 
            height: 45px; 
            border-radius: 4px; 
            cursor: pointer; 
            transition: all 0.3s;
            display: flex;
            align-items: center;
            justify-content: center;
            font-size: 1.2rem;
            box-shadow: 0 0 5px rgba(0, 243, 255, 0.1);
        }
        
        .action-btn:hover { 
            background: rgba(0, 243, 255, 0.1);
            color: var(--neon-green);
            border-color: var(--neon-green);
            box-shadow: var(--green-glow);
        }
        
        .file-input { 
            display: none; 
        }
        
        /* 在线用户面板 */
        .online-users-panel {
            width: 250px;
            background: rgba(10, 17, 40, 0.8);
            border-right: 1px solid var(--neon-blue);
            padding: 15px;
            overflow-y: auto;
            scrollbar-width: thin;
            scrollbar-color: var(--neon-blue) transparent;
        }
        
        .online-users-panel::-webkit-scrollbar {
            width: 4px;
        }
        
        .online-users-panel::-webkit-scrollbar-track {
            background: transparent;
        }
        
        .online-users-panel::-webkit-scrollbar-thumb {
            background-color: var(--neon-blue);
            border-radius: 2px;
        }
        
        .panel-title {
            color: var(--neon-blue);
            margin-bottom: 15px;
            padding-bottom: 10px;
            border-bottom: 1px solid rgba(0, 243, 255, 0.3);
            font-size: 1.1rem;
        }
        
        .user-list {
            list-style: none;
        }
        
        .user-item {
            display: flex;
            align-items: center;
            padding: 10px;
            border-radius: 4px;
            margin-bottom: 8px;
            cursor: pointer;
            transition: all 0.3s;
        }
        
        .user-item:hover {
            background: rgba(0, 243, 255, 0.1);
            border: 1px solid rgba(0, 243, 255, 0.3);
        }
        
        .user-item .status-indicator {
            width: 10px;
            height: 10px;
            border-radius: 50%;
            background-color: var(--neon-green);
            margin-right: 10px;
            box-shadow: 0 0 5px var(--neon-green);
        }
        
        .user-item .username {
            flex: 1;
        }
        
        .call-btn {
            background: transparent;
            border: none;
            color: var(--neon-green);
            cursor: pointer;
            font-size: 1rem;
            transition: all 0.3s;
        }
        
        .call-btn:hover {
            color: var(--neon-blue);
            transform: scale(1.1);
        }
        
        /* 通话界面样式 */
        .call-container {
            position: fixed;
            top: 0;
            left: 0;
            width: 100%;
            height: 100%;
            background: rgba(5, 10, 26, 0.95);
            z-index: 1000;
            display: none;
            flex-direction: column;
            align-items: center;
            justify-content: center;
        }
        
        .call-container.active {
            display: flex;
        }
        
        .call-info {
            text-align: center;
            margin-bottom: 30px;
            color: var(--neon-blue);
        }
        
        .call-status {
            font-size: 1.2rem;
            margin: 15px 0;
            color: #e0e0e0;
        }
        
        .call-actions {
            display: flex;
            gap: 20px;
            margin-top: 30px;
        }
        
        .call-control-btn {
            width: 60px;
            height: 60px;
            border-radius: 50%;
            display: flex;
            align-items: center;
            justify-content: center;
            border: none;
            cursor: pointer;
            font-size: 1.5rem;
            transition: all 0.3s;
        }
        
        .accept-btn {
            background-color: var(--neon-green);
            color: #000;
            box-shadow: 0 0 10px var(--neon-green);
        }
        
        .decline-btn, .end-call-btn {
            background-color: var(--error-color);
            color: white;
            box-shadow: 0 0 10px var(--error-color);
        }
        
        .call-control-btn:hover {
            transform: scale(1.1);
        }
        
        .call-loading {
            border: 4px solid rgba(0, 243, 255, 0.3);
            border-radius: 50%;
            border-top: 4px solid var(--neon-blue);
            width: 50px;
            height: 50px;
            animation: spin 1s linear infinite;
            margin: 20px auto;
        }
        
        @keyframes spin {
            0% { transform: rotate(0deg); }
            100% { transform: rotate(360deg); }
        }
        
        /* 通话请求通知 */
        .call-notification {
            position: fixed;
            bottom: 30px;
            left: 50%;
            transform: translateX(-50%);
            background: rgba(10, 17, 40, 0.95);
            border: 1px solid var(--neon-purple);
            border-radius: 8px;
            padding: 20px;
            box-shadow: var(--purple-glow);
            z-index: 900;
            width: 350px;
            display: none;
        }
        
        .call-notification.active {
            display: block;
        }
        
        .call-notification h3 {
            color: var(--neon-purple);
            margin-bottom: 15px;
            text-align: center;
        }
        
        .caller-info {
            display: flex;
            align-items: center;
            justify-content: center;
            margin-bottom: 20px;
        }
        
        .caller-avatar {
            width: 60px;
            height: 60px;
            border-radius: 50%;
            background: rgba(10, 17, 40, 0.8);
            border: 1px solid var(--neon-green);
            display: flex;
            align-items: center;
            justify-content: center;
            font-weight: bold;
            color: var(--neon-green);
            box-shadow: var(--green-glow);
            margin-right: 15px;
            font-size: 1.5rem;
        }
        
        .caller-name {
            font-size: 1.2rem;
            color: var(--neon-blue);
        }
        
        .call-notification-actions {
            display: flex;
            gap: 15px;
            justify-content: center;
        }
        
        /* 响应式设计 */
        @media (max-width: 768px) {
            .container {
                width: 95%;
                height: 95vh;
            }
            
            .online-users-panel {
                position: absolute;
                left: -250px;
                top: 0;
                height: 100%;
                z-index: 50;
                transition: left 0.3s;
            }
            
            .online-users-panel.active {
                left: 0;
            }
            
            .toggle-users-btn {
                display: block !important;
            }
            
            .message {
                max-width: 85%;
            }
            
            #auth-container h1 {
                font-size: 2rem;
            }
            
            .call-notification {
                width: 90%;
            }
        }
        
        .toggle-users-btn {
            display: none;
            background: transparent;
            border: 1px solid var(--neon-blue);
            color: var(--neon-blue);
            width: 40px;
            height: 40px;
            border-radius: 4px;
            cursor: pointer;
            transition: all 0.3s;
            margin-right: 10px;
        }
        
        .toggle-users-btn:hover {
            color: var(--neon-green);
            border-color: var(--neon-green);
            box-shadow: var(--green-glow);
        }
    </style>
</head>
<body>
    <div class="container">
        <!-- 在线用户面板 -->
        <div class="online-users-panel">
            <h3 class="panel-title">在线联系人</h3>
            <ul class="user-list" id="user-list">
                <!-- 在线用户将通过JavaScript动态加载 -->
            </ul>
        </div>
        
        <!-- 认证界面 -->
        <div id="auth-container">
            <h1>星际通讯频道</h1>
            <p>欢迎加入星际通讯网络，请登录或注册以开始通信</p>
            
            <div class="auth-tabs">
                <div class="auth-tab active" data-tab="login">登录</div>
                <div class="auth-tab" data-tab="register">注册</div>
            </div>
            
            <div class="auth-forms">
                <!-- 登录表单 -->
                <div class="auth-form active" id="login-form">
                    <div class="error-message" id="login-error"></div>
                    <div class="input-group">
                        <i class="fas fa-user"></i>
                        <input type="text" id="login-username" placeholder="用户名" required>
                    </div>
                    <div class="input-group">
                        <i class="fas fa-lock"></i>
                        <input type="password" id="login-password" placeholder="密码" required>
                    </div>
                    <button class="btn" id="login-btn">登录</button>
                    <div class="form-footer">
                        <p>忘记密码? <span class="link-text" id="forgot-password-link">点击重置</span></p>
                    </div>
                </div>
                
                <!-- 注册表单 -->
                <div class="auth-form" id="register-form">
                    <div class="error-message" id="register-error"></div>
                    <div class="input-group">
                        <i class="fas fa-user"></i>
                        <input type="text" id="register-username" placeholder="用户名" required>
                    </div>
                    <div class="input-group">
                        <i class="fas fa-envelope"></i>
                        <input type="email" id="register-email" placeholder="电子邮箱" required>
                    </div>
                    <div class="input-group">
                        <i class="fas fa-lock"></i>
                        <input type="password" id="register-password" placeholder="密码 (至少6位)" required>
                    </div>
                    <button class="btn" id="register-btn">注册</button>
                    <div class="form-footer">
                        <p>已有账号? <span class="link-text" id="back-to-login">返回登录</span></p>
                    </div>
                </div>
                
                <!-- 忘记密码表单 -->
                <div class="auth-form" id="forgot-password-form">
                    <div class="error-message" id="forgot-error"></div>
                    <div class="success-message" id="forgot-success"></div>
                    <p>请输入您的注册邮箱，我们将发送密码重置链接</p>
                    <div class="input-group">
                        <i class="fas fa-envelope"></i>
                        <input type="email" id="forgot-email" placeholder="电子邮箱" required>
                    </div>
                    <button class="btn" id="forgot-btn">发送重置链接</button>
                    <div class="form-footer">
                        <p>返回 <span class="link-text" id="back-to-login2">登录</span></p>
                    </div>
                </div>
                
                <!-- 重置密码表单 -->
                <div class="auth-form" id="reset-password-form">
                    <div class="error-message" id="reset-error"></div>
                    <div class="success-message" id="reset-success"></div>
                    <p>请设置新密码</p>
                    <div class="input-group">
                        <i class="fas fa-lock"></i>
                        <input type="password" id="new-password" placeholder="新密码 (至少6位)" required>
                    </div>
                    <button class="btn" id="reset-btn">重置密码</button>
                </div>
            </div>
        </div>
        
        <!-- 聊天界面 -->
        <div id="chat-container">
            <div class="chat-header">
                <button class="toggle-users-btn" id="toggle-users">
                    <i class="fas fa-users"></i>
                </button>
                <h2>星际通讯频道</h2>
                <div class="user-info">
                    <div class="user-avatar" id="current-user-avatar">
                        <?php echo isset($_SESSION['username']) ? strtoupper(substr($_SESSION['username'], 0, 1)) : ''; ?>
                    </div>
                    <span id="current-username"><?php echo isset($_SESSION['username']) ? $_SESSION['username'] : ''; ?></span>
                    <button class="logout-btn" id="logout-btn">
                        <button class="logout-btn" id="logout-btn">
                        <i class="fas fa-sign-out-alt"></i>
                    </button>
                </div>
            </div>
            
            <div class="chat-body" id="chat-messages">
                <!-- 消息将通过JavaScript动态加载 -->
            </div>
            
            <div class="chat-footer">
                <div class="input-container">
                    <input type="text" class="message-input" id="message-input" placeholder="输入消息...">
                    <div class="chat-actions">
                        <label for="file-upload" class="action-btn">
                            <i class="fas fa-paperclip"></i>
                        </label>
                        <input type="file" id="file-upload" class="file-input" accept="image/*,video/*,audio/*">
                        <button class="action-btn" id="send-btn">
                            <i class="fas fa-paper-plane"></i>
                        </button>
                    </div>
                </div>
            </div>
        </div>
    </div>
    
    <!-- 通话请求通知 -->
    <div class="call-notification" id="call-notification">
        <h3>收到语音通话请求</h3>
        <div class="caller-info">
            <div class="caller-avatar" id="caller-avatar"></div>
            <div class="caller-name" id="caller-name"></div>
        </div>
        <div class="call-notification-actions">
            <button class="call-control-btn accept-btn" id="accept-call">
                <i class="fas fa-phone"></i>
            </button>
            <button class="call-control-btn decline-btn" id="decline-call">
                <i class="fas fa-phone-slash"></i>
            </button>
        </div>
    </div>
    
    <!-- 通话界面 -->
    <div class="call-container" id="call-container">
        <div class="call-info">
            <div class="user-avatar" id="call-partner-avatar"></div>
            <div id="call-partner-name"></div>
            <div class="call-status" id="call-status">正在通话中...</div>
            <div class="call-loading" id="call-loading" style="display: none;"></div>
        </div>
        <div class="call-actions">
            <button class="call-control-btn end-call-btn" id="end-call-btn">
                <i class="fas fa-phone-slash"></i>
            </button>
        </div>
    </div>
    
    <script>
        document.addEventListener('DOMContentLoaded', function() {
            // DOM元素
            const authTabs = document.querySelectorAll('.auth-tab');
            const authForms = document.querySelectorAll('.auth-form');
            const loginBtn = document.getElementById('login-btn');
            const registerBtn = document.getElementById('register-btn');
            const forgotPasswordLink = document.getElementById('forgot-password-link');
            const backToLogin = document.getElementById('back-to-login');
            const backToLogin2 = document.getElementById('back-to-login2');
            const forgotBtn = document.getElementById('forgot-btn');
            const resetBtn = document.getElementById('reset-btn');
            const logoutBtn = document.getElementById('logout-btn');
            const sendBtn = document.getElementById('send-btn');
            const messageInput = document.getElementById('message-input');
            const fileUpload = document.getElementById('file-upload');
            const chatMessages = document.getElementById('chat-messages');
            const userList = document.getElementById('user-list');
            const toggleUsersBtn = document.getElementById('toggle-users');
            const onlineUsersPanel = document.querySelector('.online-users-panel');
            const callNotification = document.getElementById('call-notification');
            const callerAvatar = document.getElementById('caller-avatar');
            const callerName = document.getElementById('caller-name');
            const acceptCallBtn = document.getElementById('accept-call');
            const declineCallBtn = document.getElementById('decline-call');
            const callContainer = document.getElementById('call-container');
            const callPartnerAvatar = document.getElementById('call-partner-avatar');
            const callPartnerName = document.getElementById('call-partner-name');
            const callStatus = document.getElementById('call-status');
            const callLoading = document.getElementById('call-loading');
            const endCallBtn = document.getElementById('end-call-btn');
            
            // 错误和成功消息元素
            const loginError = document.getElementById('login-error');
            const registerError = document.getElementById('register-error');
            const forgotError = document.getElementById('forgot-error');
            const forgotSuccess = document.getElementById('forgot-success');
            const resetError = document.getElementById('reset-error');
            const resetSuccess = document.getElementById('reset-success');
            
            // 表单切换
            authTabs.forEach(tab => {
                tab.addEventListener('click', function() {
                    const tabId = this.getAttribute('data-tab');
                    
                    // 更新标签状态
                    authTabs.forEach(t => t.classList.remove('active'));
                    this.classList.add('active');
                    
                    // 更新表单显示
                    authForms.forEach(form => form.classList.remove('active'));
                    document.getElementById(`${tabId}-form`).classList.add('active');
                    
                    // 重置错误消息
                    document.querySelectorAll('.error-message, .success-message').forEach(el => {
                        el.style.display = 'none';
                        el.textContent = '';
                    });
                });
            });
            
            // 忘记密码链接
            forgotPasswordLink.addEventListener('click', function(e) {
                e.preventDefault();
                authTabs.forEach(t => t.classList.remove('active'));
                authForms.forEach(form => form.classList.remove('active'));
                document.getElementById('forgot-password-form').classList.add('active');
            });
            
            // 返回登录链接
            backToLogin.addEventListener('click', function(e) {
                e.preventDefault();
                authTabs.forEach(t => t.classList.remove('active'));
                authForms.forEach(form => form.classList.remove('active'));
                document.querySelector('.auth-tab[data-tab="login"]').classList.add('active');
                document.getElementById('login-form').classList.add('active');
            });
            
            backToLogin2.addEventListener('click', function(e) {
                e.preventDefault();
                authTabs.forEach(t => t.classList.remove('active'));
                authForms.forEach(form => form.classList.remove('active'));
                document.querySelector('.auth-tab[data-tab="login"]').classList.add('active');
                document.getElementById('login-form').classList.add('active');
            });
            
            // 登录功能
            loginBtn.addEventListener('click', function() {
                const username = document.getElementById('login-username').value.trim();
                const password = document.getElementById('login-password').value.trim();
                
                if (!username || !password) {
                    showError(loginError, '用户名和密码不能为空');
                    return;
                }
                
                fetch('?action=login', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/x-www-form-urlencoded',
                    },
                    body: `username=${encodeURIComponent(username)}&password=${encodeURIComponent(password)}`
                })
                .then(response => response.json())
                .then(data => {
                    if (data.status === 'success') {
                        window.location.reload();
                    } else {
                        showError(loginError, data.message);
                    }
                })
                .catch(error => {
                    showError(loginError, '登录失败，请重试');
                    console.error('Error:', error);
                });
            });
            
            // 注册功能
            registerBtn.addEventListener('click', function() {
                const username = document.getElementById('register-username').value.trim();
                const email = document.getElementById('register-email').value.trim();
                const password = document.getElementById('register-password').value.trim();
                
                if (!username || !email || !password) {
                    showError(registerError, '所有字段都是必填的');
                    return;
                }
                
                if (username.length > 20) {
                    showError(registerError, '用户名过长（最多20字符）');
                    return;
                }
                
                if (password.length < 6) {
                    showError(registerError, '密码至少需要6个字符');
                    return;
                }
                
                if (!isValidEmail(email)) {
                    showError(registerError, '无效的邮箱格式');
                    return;
                }
                
                fetch('?action=register', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/x-www-form-urlencoded',
                    },
                    body: `username=${encodeURIComponent(username)}&email=${encodeURIComponent(email)}&password=${encodeURIComponent(password)}`
                })
                .then(response => response.json())
                .then(data => {
                    if (data.status === 'success') {
                        // 注册成功后切换到登录表单
                        authTabs.forEach(t => t.classList.remove('active'));
                        authForms.forEach(form => form.classList.remove('active'));
                        document.querySelector('.auth-tab[data-tab="login"]').classList.add('active');
                        document.getElementById('login-form').classList.add('active');
                        showSuccess(loginError, data.message, true);
                    } else {
                        showError(registerError, data.message);
                    }
                })
                .catch(error => {
                    showError(registerError, '注册失败，请重试');
                    console.error('Error:', error);
                });
            });
            
            // 忘记密码功能
            forgotBtn.addEventListener('click', function() {
                const email = document.getElementById('forgot-email').value.trim();
                
                if (!email || !isValidEmail(email)) {
                    showError(forgotError, '请输入有效的邮箱地址');
                    return;
                }
                
                fetch('?action=forgot_password', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/x-www-form-urlencoded',
                    },
                    body: `email=${encodeURIComponent(email)}`
                })
                .then(response => response.json())
                .then(data => {
                    if (data.status === 'success') {
                        showSuccess(forgotSuccess, data.message);
                        document.getElementById('forgot-email').value = '';
                    } else {
                        showError(forgotError, data.message);
                    }
                })
                .catch(error => {
                    showError(forgotError, '操作失败，请重试');
                    console.error('Error:', error);
                });
            });
            
            // 重置密码功能
            resetBtn.addEventListener('click', function() {
                const password = document.getElementById('new-password').value.trim();
                const urlParams = new URLSearchParams(window.location.search);
                const token = urlParams.get('token');
                
                if (!password) {
                    showError(resetError, '密码不能为空');
                    return;
                }
                
                if (password.length < 6) {
                    showError(resetError, '密码至少需要6个字符');
                    return;
                }
                
                fetch('?action=reset_password', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/x-www-form-urlencoded',
                    },
                    body: `token=${encodeURIComponent(token)}&password=${encodeURIComponent(password)}`
                })
                .then(response => response.json())
                .then(data => {
                    if (data.status === 'success') {
                        showSuccess(resetSuccess, data.message);
                        // 3秒后跳转到登录
                        setTimeout(() => {
                            window.location.href = window.location.pathname;
                        }, 3000);
                    } else {
                        showError(resetError, data.message);
                    }
                })
                .catch(error => {
                    showError(resetError, '密码重置失败，请重试');
                    console.error('Error:', error);
                });
            });
            
            // 退出登录
            logoutBtn.addEventListener('click', function() {
                fetch('?action=logout')
                .then(response => response.json())
                .then(data => {
                    if (data.status === 'success') {
                        window.location.reload();
                    }
                })
                .catch(error => {
                    console.error('Error:', error);
                });
            });
            
            // 发送消息
            sendBtn.addEventListener('click', sendMessage);
            messageInput.addEventListener('keypress', function(e) {
                if (e.key === 'Enter') {
                    sendMessage();
                }
            });
            
            // 文件上传
            fileUpload.addEventListener('change', function() {
                if (this.files.length > 0) {
                    sendMessage();
                }
            });
            
            // 切换在线用户面板
            toggleUsersBtn.addEventListener('click', function() {
                onlineUsersPanel.classList.toggle('active');
            });
            
            // 接受通话
            acceptCallBtn.addEventListener('click', function() {
                if (window.currentCall) {
                    answerCall(window.currentCall.roomId, window.currentCall.caller);
                }
            });
            
            // 拒绝通话
            declineCallBtn.addEventListener('click', function() {
                if (window.currentCall) {
                    declineCall(window.currentCall.roomId);
                }
            });
            
            // 结束通话
            endCallBtn.addEventListener('click', function() {
                endCall();
            });
            
            // 加载消息
            function loadMessages() {
                fetch('?action=get')
                .then(response => response.json())
                .then(messages => {
                    if (messages.status === 'error') {
                        console.error('Error loading messages:', messages.message);
                        return;
                    }
                    
                    chatMessages.innerHTML = '';
                    const currentUser = document.getElementById('current-username').textContent;
                    
                    messages.forEach(message => {
                        addMessageToDOM(message.sender, message.content, message.time, 
                                         message.sender === currentUser, message.media_type, message.media_url);
                    });
                    
                    // 滚动到底部
                    chatMessages.scrollTop = chatMessages.scrollHeight;
                })
                .catch(error => {
                    console.error('Error loading messages:', error);
                });
            }
            
            // 发送消息函数
            function sendMessage() {
                const message = messageInput.value.trim();
                const file = fileUpload.files[0];
                
                if (!message && !file) {
                    return;
                }
                
                const formData = new FormData();
                formData.append('action', 'send');
                formData.append('message', message);
                
                if (file) {
                    formData.append('file', file);
                }
                
                fetch('', {
                    method: 'POST',
                    body: formData
                })
                .then(response => response.json())
                .then(data => {
                    if (data.status === 'success') {
                        messageInput.value = '';
                        fileUpload.value = '';
                        loadMessages();
                    } else {
                        alert(data.message);
                    }
                })
                .catch(error => {
                    console.error('Error sending message:', error);
                });
            }
            
            // 添加消息到DOM
            function addMessageToDOM(sender, content, time, isSent, mediaType, mediaUrl) {
                const messageDiv = document.createElement('div');
                messageDiv.className = `message ${isSent ? 'sent' : 'received'}`;
                
                let mediaHtml = '';
                if (mediaUrl) {
                    if (mediaType.startsWith('image/')) {
                        mediaHtml = `<div class="media"><img src="${mediaUrl}" alt="Image"></div>`;
                    } else if (mediaType.startsWith('video/')) {
                        mediaHtml = `<div class="media"><video controls src="${mediaUrl}"></video></div>`;
                    } else if (mediaType.startsWith('audio/')) {
                        mediaHtml = `<div class="media"><audio controls src="${mediaUrl}"></audio></div>`;
                    }
                }
                
                messageDiv.innerHTML = `
                    <div class="sender">${sender}</div>
                    <div class="content">${content}</div>
                    ${mediaHtml}
                    <div class="time">${time}</div>
                `;
                
                chatMessages.appendChild(messageDiv);
            }
            
            // 加载在线用户
            function loadOnlineUsers() {
                fetch('?action=get_online_users')
                .then(response => response.json())
                .then(data => {
                    if (data.status === 'success') {
                        userList.innerHTML = '';
                        
                        data.users.forEach(username => {
                            const userItem = document.createElement('li');
                            userItem.className = 'user-item';
                            userItem.innerHTML = `
                                <div class="status-indicator"></div>
                                <div class="username">${username}</div>
                                <button class="call-btn" data-username="${username}">
                                    <i class="fas fa-phone"></i>
                                </button>
                            `;
                            userList.appendChild(userItem);
                            
                            // 添加通话按钮事件
                            userItem.querySelector('.call-btn').addEventListener('click', function(e) {
                                e.stopPropagation();
                                const callee = this.getAttribute('data-username');
                                startCall(callee);
                            });
                        });
                    }
                })
                .catch(error => {
                    console.error('Error loading online users:', error);
                });
            }
            
            // 检查通话请求
            function checkCallRequests() {
                fetch('?action=check_call_requests')
                .then(response => response.json())
                .then(data => {
                    if (data.status === 'success' && data.calls.length > 0) {
                        // 有新的通话请求
                        const call = data.calls[0];
                        window.currentCall = call;
                        
                        callerName.textContent = call.caller;
                        callerAvatar.textContent = call.caller.charAt(0).toUpperCase();
                        callNotification.classList.add('active');
                        
                        // 播放铃声
                        playRingtone();
                    }
                })
                .catch(error => {
                    console.error('Error checking call requests:', error);
                });
            }
            
            // 开始通话
            function startCall(callee) {
                fetch('?action=start_call', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/x-www-form-urlencoded',
                    },
                    body: `callee=${encodeURIComponent(callee)}`
                })
                .then(response => response.json())
                .then(data => {
                    if (data.status === 'success') {
                        // 存储通话信息
                        window.callInfo = {
                            roomId: data.roomId,
                            isCaller: true,
                            partner: callee
                        };
                        
                        // 显示通话界面
                        showCallInterface(callee, '正在等待对方接听...');
                        callLoading.style.display = 'block';
                        
                        // 等待对方响应
                        waitForCallResponse(data.roomId);
                    } else {
                        alert(data.message);
                    }
                })
                .catch(error => {
                    console.error('Error starting call:', error);
                });
            }
            
            // 等待通话响应
            function waitForCallResponse(roomId) {
                const checkStatus = setInterval(() => {
                    fetch('?action=check_call_status', {
                        method: 'POST',
                        headers: {
                            'Content-Type': 'application/x-www-form-urlencoded',
                        },
                        body: `room_id=${encodeURIComponent(roomId)}`
                    })
                    .then(response => response.json())
                    .then(data => {
                        if (data.status === 'success') {
                            if (data.call_status === 'accepted') {
                                clearInterval(checkStatus);
                                callLoading.style.display = 'none';
                                callStatus.textContent = '正在通话中...';
                                
                                // 初始化WebRTC连接
                                initWebRTC(roomId, window.callInfo.partner, true);
                            } else if (data.call_status === 'rejected' || data.call_status === 'ended') {
                                clearInterval(checkStatus);
                                callContainer.classList.remove('active');
                                alert('对方已拒绝通话');
                                window.callInfo = null;
                            }
                        }
                    })
                    .catch(error => {
                        console.error('Error checking call status:', error);
                        clearInterval(checkStatus);
                    });
                }, 1000);
                
                // 超时处理
                setTimeout(() => {
                    clearInterval(checkStatus);
                    if (window.callInfo) {
                        endCall();
                        alert('通话请求超时');
                    }
                }, 30000);
            }
            
            // 接听通话
            function answerCall(roomId, caller) {
                callNotification.classList.remove('active');
                
                // 存储通话信息
                window.callInfo = {
                    roomId: roomId,
                    isCaller: false,
                    partner: caller
                };
                
                // 显示通话界面
                showCallInterface(caller, '正在连接...');
                callLoading.style.display = 'block';
                
                // 通知服务器接受通话
                fetch('?action=respond_call', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/x-www-form-urlencoded',
                    },
                    body: `room_id=${encodeURIComponent(roomId)}&response=accepted`
                })
                .then(response => response.json())
                .then(data => {
                    if (data.status === 'success') {
                        // 初始化WebRTC连接
                        initWebRTC(roomId, caller, false);
                    } else {
                        alert(data.message);
                        callContainer.classList.remove('active');
                        window.callInfo = null;
                    }
                })
                .catch(error => {
                    console.error('Error accepting call:', error);
                    callContainer.classList.remove('active');
                    window.callInfo = null;
                });
            }
            
            // 拒绝通话
            function declineCall(roomId) {
                callNotification.classList.remove('active');
                window.currentCall = null;
                
                fetch('?action=respond_call', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/x-www-form-urlencoded',
                    },
                    body: `room_id=${encodeURIComponent(roomId)}&response=rejected`
                })
                .then(response => response.json())
                .catch(error => {
                    console.error('Error declining call:', error);
                });
            }
            
            // 结束通话
            function endCall() {
                if (window.callInfo) {
                    // 停止媒体流
                    if (window.mediaStream) {
                        window.mediaStream.getTracks().forEach(track => track.stop());
                        window.mediaStream = null;
                    }
                    
                    // 关闭RTCPeerConnection
                    if (window.peerConnection) {
                        window.peerConnection.close();
                        window.peerConnection = null;
                    }
                    
                    // 通知服务器结束通话
                    fetch('?action=end_call', {
                        method: 'POST',
                        headers: {
                            'Content-Type': 'application/x-www-form-urlencoded',
                        },
                        body: `room_id=${encodeURIComponent(window.callInfo.roomId)}`
                    })
                    .catch(error => {
                        console.error('Error ending call:', error);
                    });
                    
                    // 隐藏通话界面
                    callContainer.classList.remove('active');
                    callLoading.style.display = 'none';
                    window.callInfo = null;
                }
            }
            
            // 显示通话界面
            function showCallInterface(partnerName, statusText) {
                callPartnerName.textContent = partnerName;
                callPartnerAvatar.textContent = partnerName.charAt