<?php
// ✅ UTILISER error_log() AVANT le chargement des classes
error_log("=== DÉBUT GET_CSRF_TOKEN.PHP ===");

define('SECURE_ACCESS', true);

try {
    require_once "../securite/config.php";
    error_log("✅ Config chargé dans GET_CSRF_TOKEN");
    
    // ✅ MAINTENANT Logger est disponible, on peut l'utiliser
    Logger::info('GET_CSRF_TOKEN', 'Configuration chargée avec succès');
} catch (Exception $e) {
    error_log("❌ ERREUR CONFIG GET_CSRF_TOKEN: " . $e->getMessage());
    echo json_encode(['success' => false, 'message' => 'Erreur configuration']);
    exit;
}

header('Content-Type: application/json');
header('Cache-Control: no-cache, must-revalidate');

// ✅ VÉRIFICATION CLASSES DISPONIBLES
error_log("SecureDatabase exists dans GET_CSRF_TOKEN: " . (class_exists('SecureDatabase') ? 'OUI' : 'NON'));
Logger::debug('GET_CSRF_TOKEN', 'Vérification classes disponibles', [
    'SecureDatabase' => class_exists('SecureDatabase'),
    'Security' => class_exists('Security'),
    'Cart' => class_exists('Cart')
]);

try {
    // ✅ UTILISER SecureDatabase DIRECTEMENT
    error_log("🔍 Récupération instance SecureDatabase GET_CSRF_TOKEN...");
    Logger::debug('GET_CSRF_TOKEN', 'Récupération instance SecureDatabase');
    
    $secureDb = SecureDatabase::getInstance();
    
    error_log("✅ Instance SecureDatabase récupérée dans GET_CSRF_TOKEN");
    Logger::info('GET_CSRF_TOKEN', 'Instance SecureDatabase récupérée');
    
    // Validation session sans CSRF (car on génère le token)
    error_log("🔍 Validation session GET_CSRF_TOKEN...");
    Logger::debug('GET_CSRF_TOKEN', 'Début validation session');
    
    if (!$secureDb->validateSession(false)) {
        error_log("❌ Validation session échouée pour GET_CSRF_TOKEN");
        Logger::error('GET_CSRF_TOKEN', 'Échec validation session');
        throw new Exception('Session invalide');
    }
    
    error_log("✅ Session validée pour GET_CSRF_TOKEN");
    Logger::info('GET_CSRF_TOKEN', 'Session validée avec succès');
    
    // Générer le token CSRF
    error_log("🔍 Génération token CSRF GET_CSRF_TOKEN...");
    Logger::debug('GET_CSRF_TOKEN', 'Début génération token CSRF');
    
    $csrfToken = $secureDb->generateCsrfToken();
    
    if (!$csrfToken) {
        error_log("❌ Échec génération token CSRF GET_CSRF_TOKEN");
        Logger::error('GET_CSRF_TOKEN', 'Échec génération token CSRF');
        throw new Exception('Impossible de générer le token CSRF');
    }
    
    error_log("✅ Token CSRF généré GET_CSRF_TOKEN: " . substr($csrfToken, 0, 10) . "...");
    Logger::info('GET_CSRF_TOKEN', 'Token CSRF généré avec succès', [
        'token_length' => strlen($csrfToken),
        'token_preview' => substr($csrfToken, 0, 10) . '...'
    ]);
    
    // Préparer la réponse
    $response = [
        'success' => true,
        'token' => $csrfToken,
        'expires_in' => defined('CSRF_TOKEN_EXPIRATION') ? CSRF_TOKEN_EXPIRATION : 1800,
        'timestamp' => time()
    ];
    
    error_log("✅ Réponse token CSRF préparée GET_CSRF_TOKEN");
    Logger::info('GET_CSRF_TOKEN', 'Réponse token CSRF préparée avec succès', [
        'expires_in' => $response['expires_in']
    ]);
    
    echo json_encode($response);
    
} catch (Exception $e) {
    error_log("❌ ERREUR CRITIQUE GET_CSRF_TOKEN: " . $e->getMessage());
    error_log("❌ STACK TRACE GET_CSRF_TOKEN: " . $e->getTraceAsString());
    
    if (class_exists('Logger')) {
        Logger::error('GET_CSRF_TOKEN', 'Erreur critique dans endpoint', [
            'error_message' => $e->getMessage(),
            'error_file' => $e->getFile(),
            'error_line' => $e->getLine(),
            'stack_trace' => $e->getTraceAsString()
        ]);
    }
    
    echo json_encode([
        'success' => false,
        'message' => $e->getMessage()
    ]);
}

error_log("=== FIN GET_CSRF_TOKEN.PHP ===");
if (class_exists('Logger')) {
    Logger::info('GET_CSRF_TOKEN', 'Fin exécution get_csrf_token.php');
}
?>