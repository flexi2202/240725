<?php
//SecureDatabase.php - VERSION 2 : CACHE ULTRA-SIMPLIFIÉ


// Vérification sécurité
if (!defined('SECURE_ACCESS')) {
    if (class_exists('Logger')) {
        Logger::critical('SECURE_DATABASE', "Accès direct au fichier SecureDatabase.php détecté");
    }
    exit('Accès direct au fichier interdit');
}

class SecureDatabase {
    // ================================================================================================
    // PROPRIÉTÉS ULTRA-SIMPLIFIÉES (VERSION 2)
    // ================================================================================================
    
    /**
     * Instance unique (pattern Singleton)
     * @var SecureDatabase
     */
    private static $instance = null;
    
    /**
     * Connexion PDO principale
     * @var PDO
     */
    private $pdo;
    
    /**
     * Compteur de tentatives de reconnexion
     * @var int
     */
    private $reconnectAttempts = 0;
    private $maxReconnectAttempts = 3;
    
    /**
     * Stack des transactions pour gérer l'imbrication
     * @var array
     */
    private $transactionStack = [];
    
 
    
    /**
     * ✅ Rate limiters UNIQUEMENT (conservé pour sécurité)
     * @var array
     */
    private static $rateLimits = [];

    // ================================================================================================
    // INITIALISATION ULTRA-SIMPLIFIÉE
    // ================================================================================================
    
    /**
     * Constructeur privé (pattern Singleton)
     */
    private function __construct() {
        if (class_exists('Logger')) {
            Logger::info('SECURE_DATABASE', "Initialisation SecureDatabase V2 (ultra-simplifié)");
        }
        $this->connect();
        
        // Enregistrer le cleanup automatique
        register_shutdown_function([$this, 'cleanup']);
    }
    
    /**
     * Retourne l'instance unique
     */
    public static function getInstance() {
        if (self::$instance === null) {
            self::$instance = new self();
            if (class_exists('Logger')) {
                Logger::debug('SECURE_DATABASE', "Instance singleton SecureDatabase V2 créée");
            }
        }
        return self::$instance;
    }
    
    /**
     * Établit la connexion à la base de données
     */
    private function connect() {
        $dsn = sprintf(
            "mysql:host=%s;dbname=%s;charset=%s",
            DB_HOST,
            DB_NAME,
            DB_CHARSET
        );
        
        $options = [
            PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
            PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
            PDO::ATTR_EMULATE_PREPARES => false,
            PDO::MYSQL_ATTR_FOUND_ROWS => true,
            PDO::ATTR_TIMEOUT => 5,
            PDO::ATTR_PERSISTENT => false,
            PDO::MYSQL_ATTR_INIT_COMMAND => "SET NAMES utf8mb4 COLLATE utf8mb4_unicode_ci"
        ];
        
        try {
            $this->pdo = new PDO($dsn, DB_USER, DB_PASSWORD, $options);
            if (class_exists('Logger')) {
                Logger::info('SECURE_DATABASE', "Connexion établie", [
                    'host' => DB_HOST,
                    'database' => DB_NAME
                ]);
            }
            $this->reconnectAttempts = 0;
        } catch (PDOException $e) {
            $this->handleConnectionError($e);
        }
    }
    
    /**
     * Gère les erreurs de connexion
     */
    private function handleConnectionError(PDOException $e) {
        if (class_exists('Logger')) {
            Logger::error('SECURE_DATABASE', "Erreur de connexion: " . $e->getMessage());
        }
        
        if ($this->reconnectAttempts < $this->maxReconnectAttempts) {
            $this->reconnectAttempts++;
            sleep(1);
            try {
                $this->connect();
                return;
            } catch (PDOException $retryException) {
                if ($this->reconnectAttempts >= $this->maxReconnectAttempts) {
                    throw new Exception("Impossible de se connecter à la base de données après {$this->maxReconnectAttempts} tentatives");
                }
            }
        }
        throw new Exception("Connexion à la base de données échouée: " . $e->getMessage());
    }

    // ================================================================================================
    // CACHE SUPPRIMÉ - VERSION 2 ULTRA-SIMPLE
    // ================================================================================================
    
    // ❌ SUPPRIMÉ : Toutes les méthodes cache complexes
    // ❌ SUPPRIMÉ : getSecurityCache, setSecurityCache, cleanupSecurityCache
    // ❌ SUPPRIMÉ : Gestion TTL et limites
    
    /**
     * ✅ NETTOYAGE ULTRA-SIMPLIFIÉ (VERSION 2)
     */
 /*   public static function cleanupAllCaches() {
 // VERSION 2 : Plus de cache local à nettoyer
        if (class_exists('Logger')) {
            Logger::debug('SECURE_DATABASE', "Nettoyage V2 - Pas de cache local");
        }
        
        return 0; // Aucun cache nettoyé
    }*/

    // ================================================================================================
    // VALIDATION PRODUITS ULTRA-SIMPLIFIÉE (VERSION 2)
    // ================================================================================================
    
    /**
     * ✅ VALIDATION PRODUIT ULTRA-SIMPLE - ACCÈS DB DIRECT UNIQUEMENT
     */
    public function validateProductId($productId, $checkDatabase = true) {
        if (!is_numeric($productId) || $productId <= 0 || floor($productId) != $productId) {
            return false;
        }
        
        $productId = (int)$productId;
        
        if ($checkDatabase) {
            // ✅ VERSION 2 : ACCÈS DB DIRECT - Le plus simple possible
            try {
                $count = $this->queryValue(
                    "SELECT COUNT(*) FROM products WHERE id = ? AND active = 1", 
                    [$productId]
                );
                return $count > 0;
            } catch (Exception $e) {
                if (class_exists('Logger')) {
                    Logger::error('SECURE_DATABASE', "Erreur validation productId: " . $e->getMessage());
                }
                return false;
            }
        }
        
        return true;
    }

    // ================================================================================================
    // VALIDATION UNIFIÉE DES PARAMÈTRES (CONSERVÉE INTÉGRALEMENT)
    // ================================================================================================
    
    /**
     * ✅ VALIDATION UNIFIÉE - Conservée (nécessaire pour sécurité)
     */
    public function validateParams($params) {
        if (!is_array($params)) {
            throw new InvalidArgumentException("Les paramètres doivent être un tableau");
        }
        
        // Limitation du nombre de paramètres
        $maxParams = 100;
        if (count($params) > $maxParams) {
            throw new InvalidArgumentException("Trop de paramètres (maximum {$maxParams})");
        }
        
        $validatedParams = [];
        $totalSize = 0;
        $maxTotalSize = 1048576; // 1MB
        
        foreach ($params as $key => $value) {
            // Validation des clés
            if (!is_string($key) && !is_int($key)) {
                throw new InvalidArgumentException("Clé de paramètre invalide: " . gettype($key));
            }
            
            if (is_string($key) && !preg_match('/^:[a-zA-Z_][a-zA-Z0-9_]{0,63}$/', $key)) {
                throw new InvalidArgumentException("Format de clé invalide: " . htmlspecialchars($key));
            }
            
            // Validation selon le type de valeur
            if (is_string($value)) {
                if (strlen($value) > 65535) {
                    throw new InvalidArgumentException("Valeur trop longue pour: " . htmlspecialchars((string)$key));
                }
                
                if (!mb_check_encoding($value, 'UTF-8')) {
                    throw new InvalidArgumentException("Encodage invalide pour: " . htmlspecialchars((string)$key));
                }
                
                // Détection de patterns dangereux
                $dangerousPatterns = [
                    '/\b(union|select|insert|update|delete|drop|create|alter|exec|execute)\b/i',
                    '/\b(waitfor|delay|benchmark|sleep|load_file|into\s+outfile|dumpfile)\b/i',
                    '/<script[^>]*>|javascript:|vbscript:|onload=|onerror=/i',
                    '/@@|char\(|0x[0-9a-f]+|\/\*|\*\/|\|{2}|&{2}/i'
                ];
                
                foreach ($dangerousPatterns as $pattern) {
                    if (preg_match($pattern, $value)) {
                        $this->logSecurityEvent('injection_attempt', 'Pattern dangereux détecté', [
                            'key' => htmlspecialchars((string)$key),
                            'pattern' => $pattern,
                            'ip' => $_SERVER['REMOTE_ADDR'] ?? 'unknown'
                        ]);
                        throw new InvalidArgumentException("Pattern dangereux détecté: " . htmlspecialchars((string)$key));
                    }
                }
                
                $totalSize += strlen($value);
            } elseif (is_int($value)) {
                if ($value < PHP_INT_MIN || $value > PHP_INT_MAX) {
                    throw new InvalidArgumentException("Entier hors limites: " . htmlspecialchars((string)$key));
                }
            } elseif (is_float($value)) {
                if (!is_finite($value)) {
                    throw new InvalidArgumentException("Valeur flottante invalide: " . htmlspecialchars((string)$key));
                }
            } elseif (!is_bool($value) && !is_null($value)) {
                throw new InvalidArgumentException("Type non supporté: " . gettype($value));
            }
            
            if ($totalSize > $maxTotalSize) {
                throw new InvalidArgumentException("Taille totale des paramètres excessive");
            }
            
            $validatedParams[$key] = $value;
        }
        
        return $validatedParams;
    }
    
    /**
     * ✅ VALIDATION QUANTITÉ UNIFIÉE (conservée)
     */
    public function validateQuantity($quantity, $maxQuantity = null) {
        if ($maxQuantity === null) {
            $maxQuantity = defined('MAX_ITEM_QUANTITY') ? MAX_ITEM_QUANTITY : 100;
        }
        
        return is_numeric($quantity) && 
               $quantity > 0 && 
               floor($quantity) == $quantity && 
               $quantity <= $maxQuantity;
    }
    
    /**
     * ✅ JOURNALISATION ÉVÉNEMENT SÉCURITÉ (conservée)
     */
    public function logSecurityEvent($eventType, $message, $context = []) {
        if (class_exists('Logger')) {
            Logger::security('SECURE_DATABASE', $message, array_merge(['event_type' => $eventType], $context));
        }
    }

    // ================================================================================================
    // CHIFFREMENT ET SIGNATURES UNIFIÉES (CONSERVÉES INTÉGRALEMENT - SÉCURITÉ)
    // ================================================================================================
    
    /**
     * ✅ CHIFFREMENT UNIFIÉ (conservé - sécurité critique)
     */
    public function encrypt($data) {
        try {
            $serialized = serialize($data);
            $cipher = 'aes-256-gcm';
            $ivlen = openssl_cipher_iv_length($cipher);
            $iv = random_bytes($ivlen);
            $tagLength = 16;
            
            $tag = null;
            $ciphertext = openssl_encrypt(
                $serialized, 
                $cipher, 
                APP_ENCRYPTION_KEY, 
                OPENSSL_RAW_DATA, 
                $iv, 
                $tag, 
                '', 
                $tagLength
            );
            
            if ($ciphertext === false || $tag === null || strlen($tag) !== $tagLength) {
                throw new Exception("Échec du chiffrement GCM");
            }
            
            // Nettoyage sécurisé
            $serialized = str_repeat("\0", strlen($serialized));
            
            return base64_encode($iv . $tag . $ciphertext);
        } catch (Exception $e) {
            if (class_exists('Logger')) {
                Logger::error('SECURE_DATABASE', "Erreur chiffrement: " . $e->getMessage());
            }
            return false;
        }
    }
    
    /**
     * ✅ DÉCHIFFREMENT UNIFIÉ (conservé - sécurité critique)
     */
    public function decrypt($data) {
        try {
            $decoded = base64_decode($data);
            if ($decoded === false) {
                throw new Exception("Données base64 invalides");
            }
            
            $cipher = 'aes-256-gcm';
            $ivlen = openssl_cipher_iv_length($cipher);
            $tagLength = 16;
            
            if (strlen($decoded) <= $ivlen + $tagLength) {
                throw new Exception("Données chiffrées trop courtes");
            }
            
            $iv = substr($decoded, 0, $ivlen);
            $tag = substr($decoded, $ivlen, $tagLength);
            $ciphertext = substr($decoded, $ivlen + $tagLength);
            
            $decrypted = openssl_decrypt(
                $ciphertext, 
                $cipher, 
                APP_ENCRYPTION_KEY, 
                OPENSSL_RAW_DATA, 
                $iv, 
                $tag
            );
            
            if ($decrypted === false) {
                throw new Exception("Échec du déchiffrement ou authentification");
            }
            
            $result = unserialize($decrypted);
            $decrypted = str_repeat("\0", strlen($decrypted));
            
            return $result;
        } catch (Exception $e) {
            if (class_exists('Logger')) {
                Logger::error('SECURE_DATABASE', "Erreur déchiffrement: " . $e->getMessage());
            }
            return null;
        }
    }
    
    /**
     * ✅ HMAC UNIFIÉ (conservé - sécurité critique)
     */
    public function generateHmac($data) {
        $serialized = serialize($data);
        return hash_hmac('sha256', $serialized, APP_HMAC_KEY);
    }
    
    /**
     * ✅ VÉRIFICATION HMAC UNIFIÉE (conservée)
     */
    public function verifyHmac($data, $signature) {
        $expectedSignature = $this->generateHmac($data);
        $isValid = hash_equals($expectedSignature, $signature);
        
        if (!$isValid) {
            if (class_exists('Logger')) {
                Logger::security('SECURE_DATABASE', "Tentative de manipulation de données signées détectée");
            }
            $this->logSecurityEvent('security_warning', 'Manipulation de données HMAC', [
                'ip' => $_SERVER['REMOTE_ADDR'] ?? 'unknown'
            ]);
        }
        
        return $isValid;
    }

    // ================================================================================================
    // RATE LIMITING UNIFIÉ (CONSERVÉ INTÉGRALEMENT - SÉCURITÉ CRITIQUE)
    // ================================================================================================
    
   /**
 * Rate limiting générique pour toute action
 * @param string $key Clé unique
 * @param int $limit Nombre max requêtes
 * @param int $period Période en secondes
 */
    public function rateLimiter($key, $limit = 10, $period = 60) {
        if (empty($key)) return true;
        
        $now = time();
        
        // Stockage en session
        if (!isset($_SESSION['rate_limits'])) {
            $_SESSION['rate_limits'] = [];
        }
        
        if (!isset($_SESSION['rate_limits'][$key])) {
            $_SESSION['rate_limits'][$key] = ['count' => 1, 'start_time' => $now];
            return true;
        }
        
        $data = $_SESSION['rate_limits'][$key];
        
        // Reset si période écoulée
        if (($now - $data['start_time']) >= $period) {
            $_SESSION['rate_limits'][$key] = ['count' => 1, 'start_time' => $now];
            return true;
        }
        
        // Vérifier limite
        if ($data['count'] >= $limit) {
            return false;
        }
        
        // Incrémenter
        $_SESSION['rate_limits'][$key]['count']++;
        return true;
    }
    
 /**
 * Rate limiting spécialisé pour actions panier
 * Utilise des limites pré-configurées par action
 * @param string $action add, update, remove, etc.
 * @param mixed $productId ID produit optionnel
 */
    public function cartRateLimiter($action, $productId = null) {
        $ip = $_SERVER['REMOTE_ADDR'] ?? 'unknown';
        $sessionId = session_id();
        $key = "cart_{$action}_{$ip}_{$sessionId}";
        
        if ($productId) {
            $key .= "_{$productId}";
        }
        
        $limits = [
            'add' => ['limit' => 10, 'period' => 15],
            'update' => ['limit' => 15, 'period' => 15],
            'remove' => ['limit' => 10, 'period' => 15],
            'clear' => ['limit' => 3, 'period' => 15],
            'api_info' => ['limit' => 50, 'period' => 15],
            'api_update' => ['limit' => 25, 'period' => 15],
            'discount_apply' => ['limit' => 5, 'period' => 15],
            'discount_remove' => ['limit' => 10, 'period' => 15],
            'test' => ['limit' => 3, 'period' => 15]
        ];
        
        $config = $limits[$action] ?? ['limit' => 5, 'period' => 60];
        
        return $this->rateLimiter($key, $config['limit'], $config['period']);
    }

    // ================================================================================================
    // GESTION CSRF (CONSERVÉE INTÉGRALEMENT - SÉCURITÉ CRITIQUE)
    // ================================================================================================
    
    /**
     * ✅ GÉNÉRATION CSRF UNIFIÉE (conservée)
     */
    public function generateCsrfToken() {
        if (!function_exists('random_bytes')) {
            throw new Exception("Environnement cryptographiquement non sécurisé");
        }
        
        $sessionData = $this->getValidCsrfSession();
        if ($sessionData !== null && $sessionData['csrf_token_strong'] === true) {
            return $sessionData['csrf_token'];
        }
        
        try {
            $tokenLength = defined('CSRF_TOKEN_LENGTH') ? CSRF_TOKEN_LENGTH : 64;
            if ($tokenLength < 32 || $tokenLength % 2 !== 0) {
                throw new Exception("Longueur token invalide: {$tokenLength}");
            }
            
            $token = bin2hex(random_bytes($tokenLength / 2));
            
            if (strlen(count_chars($token, 3)) < 8) {
                throw new Exception("Entropie insuffisante");
            }
            
            $_SESSION['csrf_token'] = $token;
            $_SESSION['csrf_token_time'] = time();
            $_SESSION['csrf_token_strong'] = true;
            $_SESSION['csrf_token_fingerprint'] = $this->generateTokenFingerprint($token);
            
            if (class_exists('Logger')) {
                Logger::debug('SECURE_DATABASE', "Token CSRF généré", [
                    'length' => strlen($token),
                    'entropy' => strlen(count_chars($token, 3))
                ]);
            }
            
            return $token;
        } catch (Exception $e) {
            if (class_exists('Logger')) {
                Logger::critical('SECURE_DATABASE', "Échec génération CSRF", [
                    'error' => $e->getMessage()
                ]);
            }
            throw new Exception("Impossible de générer un token CSRF sécurisé: " . $e->getMessage());
        }
    }
    
    /**
     * ✅ VALIDATION CSRF (conservée)
     */
    /*public function validateCsrfToken($token) {
    if (empty($token)) {
            return false;
        }
        if (!isset($_SESSION['csrf_token'])) {
            return false;
        }
        if ($_SESSION['csrf_token'] !== $token) {
            return false;
        }
        if (isset($_SESSION['csrf_expires']) && time() > $_SESSION['csrf_expires']) {
            return false;
        }
        return true;
    }*/
    
    public function validateCsrfToken($token) {
    if (empty($token)) {
        return false;
    }
    if (!isset($_SESSION['csrf_token'])) {
        return false;
    }
    if ($_SESSION['csrf_token'] !== $token) {
        return false;
    }
    
    // ✅ CORRECTION : Vérifier l'expiration avec csrf_token_time
    if (isset($_SESSION['csrf_token_time'])) {
        $age = time() - $_SESSION['csrf_token_time'];
        $expiration = defined('CSRF_TOKEN_EXPIRATION') ? CSRF_TOKEN_EXPIRATION : 1800;
        
        if ($age > $expiration) {
            if (class_exists('Logger')) {
                Logger::error('SECURE_DATABASE', "Token CSRF expiré dans validateCsrfToken", [
                    'age' => $age,
                    'expiration' => $expiration
                ]);
            }
            return false;
        }
    }
    
    return true;
}
    
    /**
     * Validation centralisée de la session CSRF
     */
    private function getValidCsrfSession() {
        if (!isset($_SESSION['csrf_token'], $_SESSION['csrf_token_time'], $_SESSION['csrf_token_fingerprint'])) {
            return null;
        }
        
        $age = time() - $_SESSION['csrf_token_time'];
       $expiration = defined('CSRF_TOKEN_EXPIRATION') ? CSRF_TOKEN_EXPIRATION : 1800;
        
        if ($age > $expiration) {
            if (class_exists('Logger')) {
                Logger::error('SECURE_DATABASE', "Token CSRF expiré", [
                    'age' => $age, 
                    'limit' => $expiration
                ]);
            }
            return null;
        }
        
        $expectedFingerprint = $this->generateTokenFingerprint($_SESSION['csrf_token']);
        if (!hash_equals($_SESSION['csrf_token_fingerprint'], $expectedFingerprint)) {
            if (class_exists('Logger')) {
                Logger::error('SECURE_DATABASE', "Possible manipulation de token CSRF détectée");
            }
            $this->logSecurityEvent('security_warning', 'Manipulation de token CSRF détectée', [
                'ip' => $_SERVER['REMOTE_ADDR'] ?? 'unknown'
            ]);
            return null;
        }
        
        return $_SESSION;
    }
    
    /**
     * Génère une empreinte pour vérifier l'intégrité du token CSRF
     */
    private function generateTokenFingerprint($token) {
        return hash_hmac('sha256', $token, APP_HMAC_KEY);
    }

    // ================================================================================================
    // GESTION DES SESSIONS (CONSERVÉE INTÉGRALEMENT - SÉCURITÉ)
    // ================================================================================================
    
    /**
     * ✅ CONFIGURATION SESSION UNIFIÉE (conservée)
     */
    public function configureSession() {
       // $sessionLifetime = 1800;  // 30 minutes
       $sessionLifetime = SESSION_LIFETIME;  // 30 minutes
        $cartLifetime = CART_LIFETIME;   // 24 heures
        
        $sessionConfig = [
            'cookie_httponly' => 1,
            'cookie_samesite' => 'Lax',
            'use_strict_mode' => 1,
            'use_only_cookies' => 1,
            'use_trans_sid' => 0,
            'gc_maxlifetime' => $sessionLifetime,
            'cookie_lifetime' => 0,
            'sid_length' => 48,
            'sid_bits_per_character' => 6,
            'name' => 'DECOSBOIS_SESSION'
        ];
        
        if (isset($_SERVER['HTTPS']) && $_SERVER['HTTPS'] === 'on') {
            $sessionConfig['cookie_secure'] = 1;
        }
        
        foreach ($sessionConfig as $directive => $value) {
            if (ini_set("session.{$directive}", $value) === false) {
                if (class_exists('Logger')) {
                    Logger::warning('SECURE_DATABASE', "Impossible de définir session.{$directive}");
                }
            }
        }
        
        if (session_status() === PHP_SESSION_NONE) {
            if (!session_start()) {
                throw new Exception("Impossible de démarrer la session");
            }
        }
        
        if (class_exists('Logger')) {
            Logger::info('SECURE_DATABASE', 'Session configurée V2', [
                'session_lifetime' => $sessionLifetime,
                'cart_lifetime' => $cartLifetime,
                'session_id' => substr(session_id(), 0, 8) . '...',
                'config_applied' => count($sessionConfig)
            ]);
        }
        
        return true;
    }
    
    /**
     * ✅ VALIDATION SESSION (conservée)
     */
    public function validateSession($strict = true) {
        if (session_status() === PHP_SESSION_NONE) {
            session_start();
        }
        
        if (!$this->checkSessionExpiration()) {
            return false;
        }
        
        if (!$this->checkSessionFingerprint($strict)) {
            if (class_exists('Logger')) {
                Logger::error('SECURE_DATABASE', 'Empreinte de session invalide - hijacking détecté');
            }
            if (class_exists('SecureRedirect')) {
                SecureRedirect::sessionHijacking();
            }
            return false;
        }
        
        $_SESSION['last_activity'] = time();
        return true;
    }
    
    /**
     * Vérification expiration session
     */
    private function checkSessionExpiration() {
        $now = time();
        
        if (!isset($_SESSION['last_activity'])) {
            $_SESSION['last_activity'] = $now;
            $_SESSION['session_start'] = $now;
            return true;
        }
        
        $lastActivity = $_SESSION['last_activity'];
        $inactiveTime = $now - $lastActivity;
        //$sessionLifetime = 1800; // 30 minutes fixe
        $sessionLifetime = SESSION_LIFETIME;  // 30 minutes fixe
        
        if ($inactiveTime > $sessionLifetime) {
            $sessionDuration = $now - ($_SESSION['session_start'] ?? $now);
            
            if (class_exists('Logger')) {
                Logger::warning('SECURE_DATABASE', 'Session expirée détectée', [
                    'user_id' => $_SESSION['user_id'] ?? 'anonymous',
                    'session_duration_minutes' => round($sessionDuration / 60, 1),
                    'inactive_duration_minutes' => round($inactiveTime / 60, 1),
                    'ip' => $_SERVER['REMOTE_ADDR'] ?? 'unknown'
                ]);
            }
            
            $this->logSecurityEvent('session_expired', 'Session expirée par inactivité', [
                'inactive_time' => $inactiveTime,
                'session_duration' => $sessionDuration,
                'user_id' => $_SESSION['user_id'] ?? null
            ]);
            
            session_unset();
            session_destroy();
            
            if (session_status() === PHP_SESSION_NONE) {
                session_start();
            }
            session_regenerate_id(true);
            
            return false;
        }
        
        return true;
    }
    
// ✅ MÉTHODE checkSessionFingerprint() CORRIGÉE AUSSI
/**
 * Vérification empreinte session avec gestion intelligente
 */
private function checkSessionFingerprint($strict = true) {
    $sessionId = session_id();
    
    if (!isset($_SESSION['fingerprint'])) {
        // Première visite : générer et stocker
        $_SESSION['fingerprint'] = $this->generateSessionFingerprint();
        $_SESSION['fingerprint_created'] = time();
        
        if (class_exists('Logger')) {
            Logger::debug('SECURE_DATABASE', 'Premier fingerprint généré', [
                'session_id_preview' => substr($sessionId, 0, 8) . '...'
            ]);
        }
        
        return true; // ✅ Première visite = OK
    }
    
    $currentFingerprint = $this->generateSessionFingerprint();
    $storedFingerprint = $_SESSION['fingerprint'];
    
    if ($strict) {
        // Mode strict : correspondance exacte requise
        $isValid = hash_equals($storedFingerprint, $currentFingerprint);
        
        if (!$isValid) {
            // ✅ DIAGNOSTIC : Pourquoi le mismatch ?
            $fingerprintAge = time() - ($_SESSION['fingerprint_created'] ?? 0);
            
            if (class_exists('Logger')) {
                Logger::warning('SECURE_DATABASE', 'Fingerprint mismatch en mode strict', [
                    'stored_preview' => substr($storedFingerprint, 0, 16) . '...',
                    'current_preview' => substr($currentFingerprint, 0, 16) . '...',
                    'age_minutes' => round($fingerprintAge / 60, 1),
                    'ip' => $_SERVER['REMOTE_ADDR'] ?? 'unknown',
                    'user_agent_length' => strlen($_SERVER['HTTP_USER_AGENT'] ?? '')
                ]);
            }
            
            // ✅ GESTION INTELLIGENTE : Régénérer si ancien (24h)
            if ($fingerprintAge > 86400) {
                $_SESSION['fingerprint'] = $currentFingerprint;
                $_SESSION['fingerprint_created'] = time();
                
                if (class_exists('Logger')) {
                    Logger::info('SECURE_DATABASE', 'Fingerprint régénéré après 24h');
                }
                
                return true;
            }
            
            // ✅ SÉCURITÉ : Log des tentatives suspectes
            $this->logSecurityEvent('fingerprint_mismatch', 'Possible détournement de session', [
                'ip' => $_SERVER['REMOTE_ADDR'] ?? 'unknown',
                'user_agent' => $_SERVER['HTTP_USER_AGENT'] ?? 'unknown',
                'session_age_minutes' => round($fingerprintAge / 60, 1)
            ]);
        }
        
        return $isValid;
        
    } else {
        // Mode non-strict : tolérance plus élevée
        if ($storedFingerprint === $currentFingerprint) {
            return true; // Match parfait
        }
        
        // Calculer similarité
        $similarity = 0;
        $length = min(strlen($storedFingerprint), strlen($currentFingerprint));
        
        if ($length === 0) {
            return false;
        }
        
        for ($i = 0; $i < $length; $i++) {
            if ($storedFingerprint[$i] === $currentFingerprint[$i]) {
                $similarity++;
            }
        }
        
        $similarityPercentage = ($similarity / $length) * 100;
        $threshold = 95; // 95% de similarité requise en mode non-strict
        $isValid = $similarityPercentage >= $threshold;
        
        if (!$isValid) {
            if (class_exists('Logger')) {
                Logger::warning('SECURE_DATABASE', 'Fingerprint similarité insuffisante', [
                    'similarity_percent' => round($similarityPercentage, 1),
                    'threshold' => $threshold
                ]);
            }
        }
        
        // Vérifier âge du fingerprint même en mode non-strict
        if (isset($_SESSION['fingerprint_created'])) {
            $fingerprintAge = time() - $_SESSION['fingerprint_created'];
            $maxAge = 86400; // 24 heures
            
            if ($fingerprintAge > $maxAge) {
                // Trop ancien : régénérer
                $_SESSION['fingerprint'] = $currentFingerprint;
                $_SESSION['fingerprint_created'] = time();
                
                if (class_exists('Logger')) {
                    Logger::info('SECURE_DATABASE', 'Fingerprint régénéré en mode non-strict');
                }
                
                return true;
            }
        }
        
        return $isValid;
    }
}
    
    /**
     * Génération empreinte session
     */
private function generateSessionFingerprint() {
    // Facteurs STABLES (ne changent pas entre les requêtes)
    $stableFactors = [
        $_SERVER['REMOTE_ADDR'] ?? 'unknown',
        $_SERVER['HTTP_USER_AGENT'] ?? 'unknown',
        // ❌ SUPPRIMER les headers qui peuvent varier :
        // $_SERVER['HTTP_ACCEPT'] - Peut changer selon la requête
        // $_SERVER['HTTP_ACCEPT_LANGUAGE'] - Peut être modifié par le navigateur  
        // $_SERVER['HTTP_ACCEPT_ENCODING'] - Varie selon le contenu
        $_SERVER['SERVER_SOFTWARE'] ?? 'unknown',
        $_SERVER['REQUEST_SCHEME'] ?? 'http'
    ];
    
    // SSL uniquement si disponible et stable
    if (isset($_SERVER['HTTPS']) && $_SERVER['HTTPS'] === 'on') {
        // ❌ SUPPRIMER SSL_CIPHER et SSL_PROTOCOL qui peuvent varier
        $stableFactors[] = 'https_enabled';
    }
    
    // Sel de session - STABLE une fois généré
    if (!isset($_SESSION['fingerprint_salt'])) {
        $_SESSION['fingerprint_salt'] = bin2hex(random_bytes(16));
        $_SESSION['fingerprint_created'] = time();
        
        if (class_exists('Logger')) {
            Logger::debug('SECURE_DATABASE', 'Nouveau sel fingerprint généré', [
                'salt_preview' => substr($_SESSION['fingerprint_salt'], 0, 8) . '...'
            ]);
        }
    }
    
    $stableFactors[] = $_SESSION['fingerprint_salt'];
    
 // ✅ SÉCURITÉ : Vérifier que le timestamp existe
if (!isset($_SESSION['fingerprint_created'])) {
    $_SESSION['fingerprint_created'] = time(); // Créer si manquant
}

// Maintenant on peut l'utiliser en sécurité
$stableFactors[] = floor($_SESSION['fingerprint_created'] / 86400);
    
    $fingerprint = hash('sha256', implode('|', $stableFactors));
    
    if (class_exists('Logger')) {
        Logger::debug('SECURE_DATABASE', 'Fingerprint généré', [
            'factors_count' => count($stableFactors),
            'fingerprint_preview' => substr($fingerprint, 0, 16) . '...',
            'created_day' => floor($_SESSION['fingerprint_created'] / 86400)
        ]);
    }
    
    return $fingerprint;
}

    // ================================================================================================
    // GESTION TOKENS PANIER (CONSERVÉE INTÉGRALEMENT)
    // ================================================================================================
    
    /**
     * ✅ GÉNÉRATION TOKEN PANIER (conservée)
     */
    public function generateCartToken($cartId, $sessionId) {
        try {
            $data = [
                'cart_id' => $cartId,
                'session_id' => $sessionId,
                'timestamp' => time(),
                'random' => bin2hex(random_bytes(8))
            ];
            return hash_hmac('sha256', serialize($data), APP_HMAC_KEY);
        } catch (Exception $e) {
            if (class_exists('Logger')) {
                Logger::error('SECURE_DATABASE', "Erreur génération token panier: " . $e->getMessage());
            }
            return hash('sha256', $cartId . $sessionId . time() . mt_rand());
        }
    }
    
    /**
     * ✅ VÉRIFICATION TOKEN PANIER (conservée)
     */
    public function verifyCartToken($token, $cartId, $sessionId) {
        try {
            if (empty($token) || empty($cartId) || empty($sessionId)) {
                return false;
            }
            
            if (!ctype_xdigit($token) || strlen($token) !== 64) {
                if (class_exists('Logger')) {
                    Logger::security('SECURE_DATABASE', "Format de token panier invalide", [
                        'token_length' => strlen($token),
                        'cart_id' => $cartId
                    ]);
                }
                return false;
            }
            
            $cartData = $this->queryRow(
                "SELECT cart_id, session_id, created_at, updated_at, status 
                 FROM carts 
                 WHERE cart_id = ? AND cart_token = ? AND status = 'active'",
                [$cartId, $token]
            );
            
            if (!$cartData) {
                if (class_exists('Logger')) {
                    Logger::security('SECURE_DATABASE', "Token panier introuvable en base", [
                        'cart_id' => $cartId,
                        'ip' => $_SERVER['REMOTE_ADDR'] ?? 'unknown'
                    ]);
                }
                return false;
            }
            
            $tokenAge = time() - strtotime($cartData['created_at']);
            $maxTokenAge = 30 * 86400; // 30 jours
            
            if ($tokenAge > $maxTokenAge) {
                if (class_exists('Logger')) {
                    Logger::warning('SECURE_DATABASE', "Token panier expiré", [
                        'cart_id' => $cartId,
                        'age_days' => round($tokenAge / 86400, 1)
                    ]);
                }
                return false;
            }
            
            return true;
            
        } catch (Exception $e) {
            if (class_exists('Logger')) {
                Logger::error('SECURE_DATABASE', "Erreur vérification token panier: " . $e->getMessage());
            }
            return false;
        }
    }

    // ================================================================================================
    // VALIDATION API (CONSERVÉE INTÉGRALEMENT)
    // ================================================================================================
    
    /**
     * ✅ VALIDATION API UNIFIÉE (conservée)
     */
   public function validateApiRequest($apiType = 'general', $requireCsrf = false) {
        if (!$this->validateSession(true)) {
            return false;
        }
        
        if (!$this->cartRateLimiter($apiType)) {
            return false;
        }
        
        if ($requireCsrf && !$this->validateCsrfFromRequest()) {
            return false;
        }
        
        return true;
    }
    
    
    
    // ✅ AJOUTER cette méthode pour l'API panier
public function validateCartApiRequest($action = 'general') {
    // Validation session
    if (!$this->validateSession(true)) {
        $this->sendApiError('Session invalide', 'session_invalid', 401);
        return false;
    }
    
    // Rate limiting spécialisé
    if (!$this->cartRateLimiter($action)) {
        $this->sendApiError('Trop de requêtes', 'rate_limit', 429);
        return false;
    }
    
    // Token panier si présent
    if (!$this->validateCartTokenFromRequest(false)) {
        $this->sendApiError('Token panier invalide', 'invalid_token', 403);
        return false;
    }
    
    return true;
}
    
    
    
    
    
    
    /**
     * Validation CSRF depuis requête
     */
    private function validateCsrfFromRequest() {
        $csrfToken = $this->extractCsrfTokenFromRequest();
        
        if (empty($csrfToken)) {
            $this->logSecurityEvent('csrf_validation_failed', 'Token CSRF manquant', [
                'ip' => $_SERVER['REMOTE_ADDR'] ?? 'unknown'
            ]);
            return false;
        }
        
        $isValid = $this->validateCsrfToken($csrfToken);
        if (!$isValid) {
            $this->logSecurityEvent('csrf_validation_failed', 'Token CSRF invalide', [
                'ip' => $_SERVER['REMOTE_ADDR'] ?? 'unknown'
            ]);
        }
        
        return $isValid;
    }
    
    /**
     * Extraction token CSRF
     */
    private function extractCsrfTokenFromRequest() {
        if (isset($_SERVER['HTTP_X_CSRF_TOKEN'])) {
            return $_SERVER['HTTP_X_CSRF_TOKEN'];
        }
        if (isset($_POST['csrf_token'])) {
            return $_POST['csrf_token'];
        }
        if (isset($_GET['csrf_token'])) {
            return $_GET['csrf_token'];
        }
        return null;
    }

    // ================================================================================================
    // SANITISATION (CONSERVÉE INTÉGRALEMENT)
    // ================================================================================================
    
    /**
     * ✅ SANITISATION UNIFIÉE (conservée pour sécurité)
     */
    public static function sanitizeInput($input, $type = 'string') {
        try {
            // Détection des données sensibles
            $sensitiveTypes = ['password', 'token', 'secret', 'key', 'csrf_token', 'session_id'];
            $isSensitiveType = in_array(strtolower($type), $sensitiveTypes);
            $isSensitiveContent = is_string($input) && preg_match('/\b(pass|pwd|token|secret|key|auth|csrf|session)\b/i', $input);
            $isSensitive = $isSensitiveType || $isSensitiveContent;
            
            if (!is_scalar($input) && !is_array($input) && !is_null($input)) {
                if (class_exists('Logger')) {
                    Logger::warning('SECURE_DATABASE', 'Type d\'entrée non supporté pour sanitisation', [
                        'input_type' => gettype($input),
                        'target_type' => $type
                    ]);
                }
                return '';
            }
            
            // Traitement récursif des tableaux
            if (is_array($input)) {
                static $depth = 0;
                if ($depth > 10) {
                    throw new InvalidArgumentException("Profondeur de tableau excessive (max 10)");
                }
                $depth++;
                $sanitized = [];
                $count = 0;
                foreach ($input as $key => $value) {
                    if ($count > 1000) {
                        throw new InvalidArgumentException("Tableau trop volumineux (max 1000 éléments)");
                    }
                    $sanitizedKey = self::sanitizeInput($key, 'key');
                    $sanitized[$sanitizedKey] = self::sanitizeInput($value, $type);
                    $count++;
                }
                $depth--;
                return $sanitized;
            }
            
            if (is_null($input)) {
                return null;
            }
            if ($input === '' || $input === false) {
                return '';
            }
            
            $stringInput = (string)$input;
            
            // Protection contre les URI dangereuses
            if ($type === 'string') {
                $dangerousSchemes = [
                    'javascript:',
                    'vbscript:',
                    'data:text/html',
                    'data:application/',
                    'data:image/svg+xml'
                ];
                foreach ($dangerousSchemes as $scheme) {
                    if (stripos($stringInput, $scheme) !== false) {
                        $stringInput = str_ireplace($scheme, '', $stringInput);
                        if (class_exists('Logger')) {
                            Logger::security('SECURE_DATABASE', 'URI dangereuse neutralisée', [
                                'scheme' => $scheme,
                                'type' => $type,
                                'ip' => $_SERVER['REMOTE_ADDR'] ?? 'unknown'
                            ]);
                        }
                    }
                }
            }
            
            // Validation de longueur
            $maxLengths = [
                'key' => 64,
                'filename' => 255,
                'email' => 320,
                'url' => 2048,
                'string' => 65535,
                'alphanum' => 255
            ];
            $maxLength = $maxLengths[$type] ?? $maxLengths['string'];
            
            if (strlen($stringInput) > $maxLength) {
                throw new InvalidArgumentException("Entrée trop longue pour le type {$type} (max {$maxLength})");
            }
            
            // Traitement selon le type
            switch ($type) {
                case 'int':
                    $result = filter_var($stringInput, FILTER_VALIDATE_INT);
                    if ($result === false) {
                        throw new InvalidArgumentException("Valeur entière invalide");
                    }
                    break;
                case 'float':
                    $result = filter_var($stringInput, FILTER_VALIDATE_FLOAT);
                    if ($result === false) {
                        throw new InvalidArgumentException("Valeur décimale invalide");
                    }
                    break;
                case 'email':
                    $email = filter_var($stringInput, FILTER_SANITIZE_EMAIL);
                    $result = filter_var($email, FILTER_VALIDATE_EMAIL);
                    if ($result === false) {
                        throw new InvalidArgumentException("Format email invalide");
                    }
                    $result = strtolower(trim($result));
                    break;
                case 'url':
                    $result = filter_var($stringInput, FILTER_VALIDATE_URL);
                    if ($result === false) {
                        throw new InvalidArgumentException("Format URL invalide");
                    }
                    if (!preg_match('/^https?:\/\//i', $result)) {
                        throw new InvalidArgumentException("Seuls HTTP et HTTPS sont autorisés");
                    }
                    break;
                case 'filename':
                    $filename = preg_replace('/[^a-zA-Z0-9._-]/', '', $stringInput);
                    $filename = str_replace('..', '', $filename);
                    if (empty($filename) || $filename === '.' || $filename === '..') {
                        throw new InvalidArgumentException("Nom de fichier invalide");
                    }
                    $result = $filename;
                    break;
                case 'key':
                    $result = preg_replace('/[^a-zA-Z0-9_]/', '', $stringInput);
                    if (empty($result)) {
                        throw new InvalidArgumentException("Clé invalide - aucun caractère valide");
                    }
                    break;
                case 'alphanum':
                    $result = preg_replace('/[^a-zA-Z0-9]/', '', $stringInput);
                    break;
                case 'string':
                default:
                    $cleaned = htmlspecialchars(trim($stringInput), ENT_QUOTES | ENT_HTML5, 'UTF-8');
                    $result = preg_replace('/[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]/', '', $cleaned);
                    break;
            }
            
            return $result;
        } catch (Exception $e) {
            if (class_exists('Logger')) {
                Logger::error('SECURE_DATABASE', 'Erreur sanitizeInput: ' . $e->getMessage());
            }
            return ''; // Retourne une valeur vide sécurisée en cas d'erreur
        }
    }

    // ================================================================================================
    // MÉTHODES DATABASE COMPLÈTES (CONSERVÉES INTÉGRALEMENT)
    // ================================================================================================
    
    /**
     * ✅ ÉCHAPPEMENT IDENTIFIANTS (conservé)
     */
    public function escapeIdentifier($identifier) {
        if (!is_string($identifier) || empty($identifier) || strlen($identifier) > 128) {
            throw new InvalidArgumentException("Identifiant invalide");
        }
        
        if (!preg_match('/^[a-zA-Z_][a-zA-Z0-9_]{0,63}(\.[a-zA-Z_][a-zA-Z0-9_]{0,63})?$/', $identifier)) {
            if (class_exists('Logger')) {
                Logger::security('SECURE_DATABASE', "Format d'identifiant invalide", [
                    'identifier' => htmlspecialchars($identifier)
                ]);
            }
            throw new InvalidArgumentException("Format d'identifiant invalide");
        }
        
        $reservedWords = [
            'SELECT', 'INSERT', 'UPDATE', 'DELETE', 'DROP', 'CREATE', 'ALTER',
            'UNION', 'EXEC', 'EXECUTE'
        ];
        
        $parts = explode('.', strtoupper($identifier));
        foreach ($parts as $part) {
            if (in_array($part, $reservedWords, true)) {
                if (class_exists('Logger')) {
                    Logger::security('SECURE_DATABASE', "Tentative mot-clé réservé", [
                        'identifier' => htmlspecialchars($identifier)
                    ]);
                }
                throw new InvalidArgumentException("Mot-clé réservé: " . htmlspecialchars($identifier));
            }
        }
        
        $escapedParts = array_map(function($part) {
            return "`{$part}`";
        }, explode('.', $identifier));
        
        return implode('.', $escapedParts);
    }
    
    /**
     * ✅ VÉRIFICATION CONNEXION (conservée)
     */
    private function isConnected() {
        if ($this->pdo === null) {
            return false;
        }
        
        try {
            $stmt = $this->pdo->query("SELECT 1");
            return ($stmt !== false);
        } catch (PDOException $e) {
            return false;
        }
    }
    
    /**
     * ✅ RECONNEXION SÉCURISÉE (conservée)
     */
    private function reconnectSafely() {
        try {
            if ($this->pdo !== null) {
                $this->pdo = null;
            }
            
            $this->transactionStack = [];
            $this->connect();
            
            if (class_exists('Logger')) {
                Logger::info('SECURE_DATABASE', "Reconnexion réussie");
            }
        } catch (Exception $e) {
            $this->reconnectAttempts++;
            if (class_exists('Logger')) {
                Logger::error('SECURE_DATABASE', "Échec de reconnexion: " . $e->getMessage());
            }
            
            if ($this->reconnectAttempts >= $this->maxReconnectAttempts) {
                throw new Exception("Impossible de rétablir la connexion à la base de données");
            }
            
            sleep(min($this->reconnectAttempts, 3));
            $this->reconnectSafely();
        }
    }
    
    /**
     * ✅ EXÉCUTION REQUÊTE UNIFIÉE (conservée)
     */
    public function query($sql, $params = []) {
        try {
            if (!empty($params)) {
                $params = $this->validateParams($params);
            }
            
            $stmt = $this->pdo->prepare($sql);
            if ($stmt === false) {
                throw new PDOException("Échec de la préparation de la requête");
            }
            
            $success = $stmt->execute($params);
            if (!$success) {
                throw new PDOException("Échec de l'exécution de la requête");
            }
            
            return $stmt;
        } catch (PDOException $e) {
            $this->handleQueryError($e, $sql);
            throw $e;
        }
    }
    
    /**
     * ✅ GESTION ERREURS REQUÊTE (conservée)
     */
    private function handleQueryError(PDOException $e, $sql) {
        if (class_exists('Logger')) {
            Logger::error('SECURE_DATABASE', "Erreur d'exécution de requête", [
                'error' => $e->getMessage(),
                'sql_preview' => substr($this->sanitizeSQL($sql), 0, 100)
            ]);
        }
        
        if ($this->isConnectionLostError($e)) {
            if (class_exists('Logger')) {
                Logger::warning('SECURE_DATABASE', "Perte de connexion détectée, tentative de reconnexion");
            }
            $this->reconnectSafely();
        }
    }
    
    /**
     * ✅ DÉTECTION ERREUR CONNEXION (conservée)
     */
    private function isConnectionLostError(PDOException $e) {
        $connectionErrorCodes = [2006, 2013, 2003, 2002, 1053, 1077];
        $errorCode = $e->errorInfo[1] ?? 0;
        return in_array($errorCode, $connectionErrorCodes);
    }
    
    /**
     * ✅ NETTOYAGE SQL (conservé)
     */
    private function sanitizeSQL($sql) {
        if (!is_string($sql)) {
            return '[NON_STRING_SQL]';
        }
        
        if (strlen($sql) > 1000) {
            $sql = substr($sql, 0, 1000) . '... [TRUNCATED]';
        }
        
        $sensitivePatterns = [
            '/(\b(?:password|pwd|pass|secret|key|token)\s*[=:]\s*)[\'"][^\'"]*[\'"]?/i' => '$1\'[REDACTED]\'',
            '/([\'"])([A-Fa-f0-9]{32,})\1/i' => '$1[HASH_REDACTED]$1'
        ];
        
        foreach ($sensitivePatterns as $pattern => $replacement) {
            $sql = preg_replace($pattern, $replacement, $sql);
        }
        
        return htmlspecialchars(trim($sql), ENT_QUOTES | ENT_HTML5, 'UTF-8');
    }

    /**
     * ✅ RÉCUPÉRATION VALEUR UNIQUE (conservée)
     */
    public function queryValue($sql, $params = [], $default = null) {
        try {
            $stmt = $this->query($sql, $params);
            $value = $stmt->fetchColumn();
            return ($value !== false) ? $value : $default;
        } catch (Exception $e) {
            if (class_exists('Logger')) {
                Logger::error('SECURE_DATABASE', "Erreur queryValue: " . $e->getMessage());
            }
            return $default;
        }
    }
    
    /**
     * ✅ RÉCUPÉRATION LIGNE UNIQUE (conservée)
     */
    public function queryRow($sql, $params = []) {
        try {
            $stmt = $this->query($sql, $params);
            return $stmt->fetch();
        } catch (Exception $e) {
            if (class_exists('Logger')) {
                Logger::error('SECURE_DATABASE', "Erreur queryRow: " . $e->getMessage());
            }
            return null;
        }
    }
    
    /**
     * ✅ RÉCUPÉRATION TOUTES LIGNES (conservée)
     */
    public function queryAll($sql, $params = []) {
        try {
            $stmt = $this->query($sql, $params);
            return $stmt->fetchAll();
        } catch (Exception $e) {
            if (class_exists('Logger')) {
                Logger::error('SECURE_DATABASE', "Erreur queryAll: " . $e->getMessage());
            }
            return [];
        }
    }
    
    /**
     * ✅ INSERTION SIMPLIFIÉE (conservée)
     */
    public function insert($tableName, $data) {
        if (empty($data) || !is_array($data)) {
            return false;
        }
        
        $tableName = $this->escapeIdentifier($tableName);
        $fields = array_map([$this, 'escapeIdentifier'], array_keys($data));
        $placeholders = array_fill(0, count($data), '?');
        
        $sql = "INSERT INTO {$tableName} (" . implode(', ', $fields) . ") VALUES (" . implode(', ', $placeholders) . ")";
        
        try {
            $this->query($sql, array_values($data));
            return $this->lastInsertId();
        } catch (Exception $e) {
            if (class_exists('Logger')) {
                Logger::error('SECURE_DATABASE', "Erreur insertion: " . $e->getMessage());
            }
            return false;
        }
    }
    
    /**
     * ✅ MISE À JOUR SIMPLIFIÉE (conservée)
     */
    public function update($tableName, $data, $where) {
        if (empty($data) || empty($where) || !is_array($data) || !is_array($where)) {
            return false;
        }
        
        $tableName = $this->escapeIdentifier($tableName);
        
        $setParts = [];
        $params = [];
        foreach ($data as $field => $value) {
            $field = $this->escapeIdentifier($field);
            $setParts[] = "{$field} = ?";
            $params[] = $value;
        }
        
        $whereResult = $this->buildWhereClause($where);
        $params = array_merge($params, $whereResult['params']);
        
        $sql = "UPDATE {$tableName} SET " . implode(', ', $setParts) . " WHERE " . $whereResult['sql'];
        
        try {
            $stmt = $this->query($sql, $params);
            return $stmt->rowCount();
        } catch (Exception $e) {
            if (class_exists('Logger')) {
                Logger::error('SECURE_DATABASE', "Erreur mise à jour: " . $e->getMessage());
            }
            return false;
        }
    }
    
    /**
     * ✅ SUPPRESSION SIMPLIFIÉE (conservée)
     */
    public function delete($tableName, $where) {
        if (empty($where) || !is_array($where)) {
            if (class_exists('Logger')) {
                Logger::error('SECURE_DATABASE', "Tentative de suppression sans condition WHERE");
            }
            return false;
        }
        
        $tableName = $this->escapeIdentifier($tableName);
        $whereResult = $this->buildWhereClause($where);
        
        $sql = "DELETE FROM {$tableName} WHERE " . $whereResult['sql'];
        
        try {
            $stmt = $this->query($sql, $whereResult['params']);
            return $stmt->rowCount();
        } catch (Exception $e) {
            if (class_exists('Logger')) {
                Logger::error('SECURE_DATABASE', "Erreur suppression: " . $e->getMessage());
            }
            return false;
        }
    }
    
    /**
     * ✅ CONSTRUCTION CLAUSE WHERE (conservée)
     */
    private function buildWhereClause($conditions) {
        if (!is_array($conditions) || empty($conditions)) {
            throw new InvalidArgumentException("Les conditions WHERE doivent être un tableau non vide");
        }
        
        $whereParts = [];
        $params = [];
        
        foreach ($conditions as $field => $value) {
            $field = $this->validateFieldName($field);
            $escapedField = $this->escapeIdentifier($field);
            
            if (is_array($value)) {
                $placeholders = str_repeat('?,', count($value) - 1) . '?';
                $whereParts[] = "{$escapedField} IN ({$placeholders})";
                $params = array_merge($params, $value);
            } else {
                $whereParts[] = "{$escapedField} = ?";
                $params[] = $value;
            }
        }
        
        return [
            'sql' => implode(' AND ', $whereParts),
            'params' => $params
        ];
    }
    
    /**
     * ✅ VALIDATION NOM CHAMP (conservée)
     */
    private function validateFieldName($field) {
        if (!is_string($field) || empty($field) || strlen($field) > 128) {
            throw new InvalidArgumentException("Nom de champ invalide");
        }
        
        if (!preg_match('/^[a-zA-Z_][a-zA-Z0-9_]{0,63}(\.[a-zA-Z_][a-zA-Z0-9_]{0,63})?$/', $field)) {
            throw new InvalidArgumentException("Format SQL invalide: " . htmlspecialchars($field));
        }
        
        return $field;
    }

    // ================================================================================================
    // GESTION DES TRANSACTIONS (CONSERVÉE INTÉGRALEMENT)
    // ================================================================================================
    
    /**
     * ✅ DÉBUT TRANSACTION (conservée)
     */
    public function beginTransaction() {
        try {
            if (empty($this->transactionStack)) {
                $success = $this->pdo->beginTransaction();
                if ($success) {
                    $this->transactionStack[] = 'main';
                }
                return $success;
            } else {
                $savepointName = 'sp_' . count($this->transactionStack);
                $this->pdo->exec("SAVEPOINT {$savepointName}");
                $this->transactionStack[] = $savepointName;
                return true;
            }
        } catch (PDOException $e) {
            if (class_exists('Logger')) {
                Logger::error('SECURE_DATABASE', "Erreur démarrage transaction: " . $e->getMessage());
            }
            return false;
        }
    }
    
    /**
     * ✅ VALIDATION TRANSACTION (conservée)
     */
    public function commit() {
        try {
            if (empty($this->transactionStack)) {
                if (class_exists('Logger')) {
                    Logger::warning('SECURE_DATABASE', "Tentative de commit sans transaction active");
                }
                return false;
            }
            
            $lastTransaction = array_pop($this->transactionStack);
            
            if ($lastTransaction === 'main') {
                $success = $this->pdo->commit();
                return $success;
            } else {
                $this->pdo->exec("RELEASE SAVEPOINT {$lastTransaction}");
                return true;
            }
        } catch (PDOException $e) {
            if (class_exists('Logger')) {
                Logger::error('SECURE_DATABASE', "Erreur commit transaction: " . $e->getMessage());
            }
            return false;
        }
    }
    
    /**
     * ✅ ANNULATION TRANSACTION (conservée)
     */
    public function rollback() {
        try {
            if (empty($this->transactionStack)) {
                if (class_exists('Logger')) {
                    Logger::warning('SECURE_DATABASE', "Tentative de rollback sans transaction active");
                }
                return false;
            }
            
            $lastTransaction = array_pop($this->transactionStack);
            
            if ($lastTransaction === 'main') {
                $success = $this->pdo->rollback();
                $this->transactionStack = [];
                if (class_exists('Logger')) {
                    Logger::debug('SECURE_DATABASE', "Transaction principale annulée");
                }
                return $success;
            } else {
                $this->pdo->exec("ROLLBACK TO SAVEPOINT {$lastTransaction}");
                if (class_exists('Logger')) {
                    Logger::debug('SECURE_DATABASE', "Rollback au savepoint", ['name' => $lastTransaction]);
                }
                return true;
            }
        } catch (PDOException $e) {
            if (class_exists('Logger')) {
                Logger::error('SECURE_DATABASE', "Erreur rollback transaction: " . $e->getMessage());
            }
            return false;
        }
    }
    
    /**
     * ✅ VÉRIFICATION TRANSACTION ACTIVE (conservée)
     */
    public function inTransaction() {
        return !empty($this->transactionStack);
    }
    
    /**
     * ✅ DERNIER ID INSÉRÉ (conservé)
     */
    public function lastInsertId() {
        return $this->pdo->lastInsertId();
    }

    // ================================================================================================
    // UTILITAIRES API (CONSERVÉS INTÉGRALEMENT)
    // ================================================================================================
    
    /**
     * ✅ DÉTECTION AJAX (conservée)
     */
    public function isAjaxRequest() {
        return (isset($_GET['ajax']) && $_GET['ajax'] == '1') || 
               (isset($_SERVER['HTTP_X_REQUESTED_WITH']) && 
                strtolower($_SERVER['HTTP_X_REQUESTED_WITH']) === 'xmlhttprequest');
    }
    
    /**
     * ✅ NETTOYAGE BUFFER (conservé)
     */
    public function cleanOutputBuffer() {
        while (ob_get_level() > 0) {
            ob_end_clean();
        }
    }
    
    /**
     * ✅ RÉPONSE ERREUR API (conservée)
     */
    public function sendApiError($message, $errorCode = 'generic_error', $httpCode = 400) {
        $this->cleanOutputBuffer();
        if (!headers_sent()) {
            http_response_code($httpCode);
            header('Content-Type: application/json; charset=utf-8');
        }
        
        $response = [
            'success' => false,
            'error' => $message,
            'errorCode' => $errorCode,
            'timestamp' => time()
        ];
        
        echo json_encode($response, JSON_UNESCAPED_UNICODE);
        $this->logSecurityEvent('api_error_sent', $message, [
            'error_code' => $errorCode,
            'http_code' => $httpCode
        ]);
        exit;
    }
    
    /**
     * ✅ VALIDATION TOKEN PANIER REQUÊTE (conservée)
     */
    public function validateCartTokenFromRequest($strict = false) {
        $cartToken = $_COOKIE['cart_token'] ?? null;
        $cartId = $_SESSION['cart_id'] ?? null;
        
        if (!$cartToken || !$cartId) {
            return true;
        }
        
        $isValid = $this->verifyCartToken($cartToken, $cartId, session_id());
        if (!$isValid) {
            $this->logSecurityEvent('invalid_cart_token_api', 'Token panier invalide dans API', [
                'cart_id' => $cartId,
                'ip' => $_SERVER['REMOTE_ADDR'] ?? 'unknown',
                'user_agent' => $_SERVER['HTTP_USER_AGENT'] ?? 'unknown'
            ]);
            
            setcookie('cart_token', '', time() - 3600, '/');
            unset($_SESSION['cart_id']);
            
            if ($strict) {
                throw new Exception('Token de panier invalide - Veuillez recharger la page');
            }
        }
        
        return $isValid;
    }
    
    /**
     * ✅ NETTOYAGE SESSION (conservé)
     */
    public function cleanupSession() {
        $keysToKeep = ['csrf_token', 'csrf_token_time', 'fingerprint_salt'];
        $dataToKeep = array_intersect_key($_SESSION, array_flip($keysToKeep));
        $_SESSION = $dataToKeep;
        $_SESSION['last_activity'] = time();
        session_regenerate_id(true);
        
        if (class_exists('Logger')) {
            Logger::debug('SECURE_DATABASE', "Session nettoyée");
        }
        return true;
    }
    
    /**
     * ✅ RÉGÉNÉRATION SESSION (conservée)
     */
    public function regenerateSession() {
        try {
            $sessionData = $_SESSION;
            if (!session_regenerate_id(true)) {
                return false;
            }
            
            $_SESSION = $sessionData;
            $_SESSION['last_activity'] = time();
            $_SESSION['fingerprint'] = $this->generateSessionFingerprint();
            $_SESSION['security_token'] = bin2hex(random_bytes(16));
            
            return true;
        } catch (Exception $e) {
            if (class_exists('Logger')) {
                Logger::error('SECURE_DATABASE', "Erreur régénération session: " . $e->getMessage());
            }
            return false;
        }
    }
    
    
    
    /**
 * Gestion d'erreur unifiée - Respecte les méthodes de sécurité
 */
public function handleSecureError($component, $errorType, $message, $context = [], $logLevel = 'error') {
    $userMessage = $this->sanitizeInput($message, 'string');
    
    $securityContext = array_merge($context, [
        'ip' => $_SERVER['REMOTE_ADDR'] ?? 'unknown',
        'user_agent' => $_SERVER['HTTP_USER_AGENT'] ?? 'unknown',
        'session_id' => substr(session_id(), 0, 8) . '...',
        'timestamp' => time(),
        'error_type' => $errorType
    ]);
    
    switch ($logLevel) {
        case 'security':
            Logger::security($component, $message, $securityContext);
            $this->logSecurityEvent($errorType, $message, $securityContext);
            break;
        case 'warning':
            Logger::warning($component, $message, $securityContext);
            break;
        case 'error':
        default:
            Logger::error($component, $message, $securityContext);
            break;
    }
    
    return $userMessage;
}

/**
 * Validation produit unifiée avec gestion d'erreurs
 */
public function validateProductWithError($productId, $component, $checkDatabase = true) {
    if (!is_numeric($productId) || $productId <= 0 || floor($productId) != $productId) {
        $error = $this->handleSecureError(
            $component,
            'invalid_product_format',
            'ID produit invalide',
            ['provided_id' => $productId, 'type' => gettype($productId)],
            'security'
        );
        return ['valid' => false, 'error' => $error];
    }
    
    $productId = (int)$productId;
    
    if ($checkDatabase) {
        if (!$this->validateProductId($productId, true)) {
            $error = $this->handleSecureError(
                $component,
                'product_not_found',
                'Produit introuvable',
                ['product_id' => $productId],
                'security'
            );
            return ['valid' => false, 'error' => $error];
        }
    }
    
    return ['valid' => true, 'error' => null, 'product_id' => $productId];
}

/**
 * Validation quantité unifiée avec gestion d'erreurs
 */
public function validateQuantityWithError($quantity, $component, $maxQuantity = null) {
    if ($maxQuantity === null) {
        $maxQuantity = defined('MAX_ITEM_QUANTITY') ? MAX_ITEM_QUANTITY : 100;
    }
    
    if (!$this->validateQuantity($quantity, $maxQuantity)) {
        $error = $this->handleSecureError(
            $component,
            'invalid_quantity',
            "Quantité invalide (1-{$maxQuantity})",
            [
                'provided_quantity' => $quantity,
                'max_allowed' => $maxQuantity,
                'type' => gettype($quantity)
            ],
            'warning'
        );
        return ['valid' => false, 'error' => $error];
    }
    
    return ['valid' => true, 'error' => null, 'quantity' => (int)$quantity];
}
    
    
    
    

    
    
    
    
    
    
    
    
    
    
    
    
    

    // ================================================================================================
    // NETTOYAGE ET FINALISATION ULTRA-SIMPLIFIÉS (VERSION 2)
    // ================================================================================================
    
    /**
     * ✅ NETTOYAGE FINAL ULTRA-SIMPLIFIÉ (VERSION 2)
     */
    public function cleanup() {
        // Rollback des transactions non fermées
        if (!empty($this->transactionStack)) {
            if (class_exists('Logger')) {
                Logger::warning('SECURE_DATABASE', "Transactions non fermées détectées, rollback automatique");
            }
            try {
                while (!empty($this->transactionStack)) {
                    $this->rollback();
                }
            } catch (Exception $e) {
                // Ignorer les erreurs de cleanup
            }
        }
        
        // ✅ VERSION 2 : Plus de cache du tout à nettoyer
        
        if (class_exists('Logger')) {
            Logger::debug('SECURE_DATABASE', "Nettoyage SecureDatabase V2 terminé (ultra-simplifié)");
        }
    }
    
    /**
     * ✅ CACHE CLEANUP ULTRA-SIMPLIFIÉ (VERSION 2)
     */
    public static function clearCache() {
        // ✅ VERSION 2 : Plus de cache statique du tout
        self::$rateLimits = []; // Seulement rate limits
        
        if (class_exists('Logger')) {
            Logger::debug('SECURE_DATABASE', "Cache statique V2 nettoyé (rate limits uniquement)");
        }
    }

// ================================================================================================
    // PROTECTION SINGLETON (CONSERVÉE)
    // ================================================================================================
    
    /**
     * Empêche le clonage
     */
    private function __clone() {}
    
    /**
     * Empêche la désérialisation
     */
    public function __wakeup() {
        throw new Exception("Cannot unserialize singleton");
    }
}

// ================================================================================================
// NETTOYAGE AUTOMATIQUE ULTRA-SIMPLIFIÉ (VERSION 2)
// ================================================================================================

// Enregistrer le nettoyage automatique en fin de script
register_shutdown_function(function() {
    SecureDatabase::clearCache();
});

?>