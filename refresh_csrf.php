<?php
//refresh_csrf.php
/**
 * Endpoint de renouvellement des tokens CSRF
 * Fournit de nouveaux tokens CSRF pour les requêtes AJAX
 * Compatible avec l'architecture de sécurité existante
 */

// Définir une constante pour protéger les fichiers inclus
define('SECURE_ACCESS', true);

// Enregistrer le temps de début pour mesurer les performances
$startTime = microtime(true);

// Inclure les fichiers nécessaires avec gestion d'erreurs
try {
    require_once "../securite/config.php";
    require_once "../securite/Logger.php";
    require_once "../securite/Database.php";
    require_once "../securite/Security.php";
    require_once "../securite/SecureRedirect.php";
} catch (Exception $e) {
    error_log("CRITICAL_ERROR: Impossible de charger les dépendances: " . $e->getMessage());
    
    if (!headers_sent()) {
        header('HTTP/1.1 500 Internal Server Error');
        header('Content-Type: application/json; charset=UTF-8');
    }
    
    echo json_encode([
        'success' => false,
        'error' => 'Erreur système critique',
        'timestamp' => date('c')
    ]);
    exit;
}

// Initialiser les dépendances si nécessaire
if (class_exists('DependencyManager') && !DependencyManager::isInitialized()) {
    $initSuccess = DependencyManager::initialize();
    if (!$initSuccess) {
        error_log("CRITICAL_ERROR: Échec initialisation dépendances");
        
        if (!headers_sent()) {
            header('HTTP/1.1 500 Internal Server Error');
            header('Content-Type: application/json; charset=UTF-8');
        }
        
        echo json_encode([
            'success' => false,
            'error' => 'Erreur d\'initialisation système',
            'timestamp' => date('c')
        ]);
        exit;
    }
}

/**
 * Fonction pour envoyer une réponse JSON avec headers sécurisés
 */
function sendJsonResponse($data, $httpCode = 200) {
    if (!headers_sent()) {
        header("HTTP/1.1 {$httpCode}");
        header('Content-Type: application/json; charset=UTF-8');
        header('X-Content-Type-Options: nosniff');
        header('X-Frame-Options: DENY');
        header('Cache-Control: no-cache, no-store, must-revalidate');
        header('Pragma: no-cache');
        header('Expires: 0');
    }
    
    echo json_encode($data, JSON_UNESCAPED_UNICODE);
    exit;
}

// Démarrer la session si elle n'est pas déjà démarrée
if (session_status() === PHP_SESSION_NONE) {
    session_start();
}

// ========================================
// VÉRIFICATIONS DE SÉCURITÉ
// ========================================

// Vérifier la méthode HTTP (GET autorisé pour ce endpoint)
if (!in_array($_SERVER['REQUEST_METHOD'], ['GET', 'POST'])) {
    if (class_exists('Logger')) {
        Logger::security('REFRESH_CSRF', "Méthode HTTP non autorisée", [
            'method' => $_SERVER['REQUEST_METHOD'] ?? 'unknown',
            'ip' => $_SERVER['REMOTE_ADDR'] ?? 'unknown'
        ]);
    }
    
    sendJsonResponse([
        'success' => false,
        'error' => 'Méthode non autorisée',
        'timestamp' => date('c')
    ], 405);
}

// Vérifier l'empreinte de session pour prévenir le hijacking
if (!Security::checkSessionFingerprint()) {
    if (class_exists('Logger')) {
        Logger::security('REFRESH_CSRF', "Empreinte de session invalide", [
            'ip' => $_SERVER['REMOTE_ADDR'] ?? 'unknown',
            'session_id' => session_id()
        ]);
    }
    
    Security::logSecurityEvent('security_warning', 'Tentative de refresh CSRF avec session compromise', [
        'ip' => $_SERVER['REMOTE_ADDR'] ?? 'unknown',
        'session_id' => session_id()
    ]);
    
    sendJsonResponse([
        'success' => false,
        'error' => 'Session invalide',
        'session_expired' => true,
        'timestamp' => date('c')
    ], 403);
}

// Protection contre le rate limiting
if (!Security::rateLimiter('refresh_csrf', 30)) { // 30 requêtes par minute
    if (class_exists('Logger')) {
        Logger::security('REFRESH_CSRF', "Rate limit dépassé", [
            'ip' => $_SERVER['REMOTE_ADDR'] ?? 'unknown'
        ]);
    }
    
    Security::logSecurityEvent('security_warning', 'Rate limit dépassé pour refresh CSRF', [
        'ip' => $_SERVER['REMOTE_ADDR'] ?? 'unknown'
    ]);
    
    sendJsonResponse([
        'success' => false,
        'error' => 'Trop de requêtes',
        'retry_after' => 60,
        'timestamp' => date('c')
    ], 429);
}

// ========================================
// GÉNÉRATION DU TOKEN CSRF
// ========================================

try {
    // Journaliser la requête (niveau debug uniquement)
    if (class_exists('Logger')) {
        Logger::debug('REFRESH_CSRF', "Requête de renouvellement CSRF", [
            'method' => $_SERVER['REQUEST_METHOD'],
            'ip' => $_SERVER['REMOTE_ADDR'] ?? 'unknown',
            'user_agent' => substr($_SERVER['HTTP_USER_AGENT'] ?? 'unknown', 0, 100)
        ]);
    }
    
    // Utiliser la méthode existante de Security (avec cache intelligent)
    $newToken = Security::generateCsrfToken();
    
    // Vérifier que le token a été généré avec succès
    if (empty($newToken)) {
        throw new Exception("Échec de la génération du token CSRF");
    }
    
    // Calculer le temps d'expiration
    $tokenExpiration = defined('CSRF_TOKEN_EXPIRATION') ? CSRF_TOKEN_EXPIRATION : 3600;
    $tokenCreatedAt = $_SESSION['csrf_token_time'] ?? time();
    $expiresIn = max(0, $tokenExpiration - (time() - $tokenCreatedAt));
    
    // Calculer le temps d'exécution
    $executionTime = round((microtime(true) - $startTime) * 1000, 2);
    
    // Journaliser le succès (niveau debug)
    if (class_exists('Logger')) {
        Logger::debug('REFRESH_CSRF', "Token CSRF généré avec succès", [
            'token_length' => strlen($newToken),
            'expires_in' => $expiresIn,
            'execution_time_ms' => $executionTime
        ]);
    }
    
    // Réponse de succès
    sendJsonResponse([
        'success' => true,
        'token' => $newToken,
        'expires_in' => $expiresIn,
        'expires_at' => date('c', time() + $expiresIn),
        'generated_at' => date('c'),
        'execution_time_ms' => $executionTime,
        'timestamp' => date('c')
    ]);
    
} catch (Exception $e) {
    // Journaliser l'erreur
    if (class_exists('Logger')) {
        Logger::error('REFRESH_CSRF', "Erreur lors de la génération du token: " . $e->getMessage(), [
            'file' => $e->getFile(),
            'line' => $e->getLine()
        ]);
    }
    
    Security::logSecurityEvent('error', 'Erreur génération token CSRF', [
        'error' => $e->getMessage(),
        'ip' => $_SERVER['REMOTE_ADDR'] ?? 'unknown'
    ]);
    
    sendJsonResponse([
        'success' => false,
        'error' => 'Erreur lors de la génération du token',
        'timestamp' => date('c')
    ], 500);
}
?>