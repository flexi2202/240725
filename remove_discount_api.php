<?php
define('SECURE_ACCESS', true);

try {
    require_once "../securite/config.php";
    Logger::info('REMOVE_DISCOUNT_API', 'Configuration chargée avec succès');
} catch (Exception $e) {
    Logger::error('REMOVE_DISCOUNT_API', 'Erreur configuration critique', ['error' => $e->getMessage()]);
    echo json_encode(['success' => false, 'message' => 'Erreur configuration']);
    exit;
}

header('Content-Type: application/json');
header('Cache-Control: no-cache, must-revalidate');

// Vérification AJAX
if (!isset($_SERVER['HTTP_X_REQUESTED_WITH']) || 
    strtolower($_SERVER['HTTP_X_REQUESTED_WITH']) !== 'xmlhttprequest') {
    Logger::warning('REMOVE_DISCOUNT_API', 'Requête non AJAX rejetée', [
        'headers' => $_SERVER['HTTP_X_REQUESTED_WITH'] ?? 'ABSENT',
        'ip' => $_SERVER['REMOTE_ADDR'] ?? 'unknown'
    ]);
    echo json_encode(['success' => false, 'message' => 'Requête non autorisée']);
    exit;
}

// Vérification méthode POST
if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    Logger::warning('REMOVE_DISCOUNT_API', 'Méthode HTTP incorrecte', [
        'method' => $_SERVER['REQUEST_METHOD'],
        'ip' => $_SERVER['REMOTE_ADDR'] ?? 'unknown'
    ]);
    echo json_encode(['success' => false, 'message' => 'Méthode non autorisée']);
    exit;
}

Logger::debug('REMOVE_DISCOUNT_API', 'Requête AJAX POST validée');

try {
    $secureDb = SecureDatabase::getInstance();
    Logger::debug('REMOVE_DISCOUNT_API', 'Instance SecureDatabase récupérée');
    
    // Validation sécurité
    if (!$secureDb->validateApiRequest('discount_remove', true)) {
        Logger::error('REMOVE_DISCOUNT_API', 'Échec validation API request');
        throw new Exception('Validation sécurité échouée');
    }
    
    Logger::debug('REMOVE_DISCOUNT_API', 'Validation API réussie');
    
    // Vérification token panier si fourni
    $cartToken = $_COOKIE['cart_token'] ?? null;
    $cartId = $_SESSION['cart_id'] ?? null;
    
    if ($cartToken && $cartId) {
        if (!$secureDb->verifyCartToken($cartToken, $cartId, session_id())) {
            Logger::warning('REMOVE_DISCOUNT_API', 'Token panier invalide détecté', [
                'cart_id' => $cartId,
                'ip' => $_SERVER['REMOTE_ADDR'] ?? 'unknown'
            ]);
            
            Logger::security('REMOVE_DISCOUNT_API', "Tentative suppression code promo avec token invalide", [
                'api' => 'remove_discount',
                'cart_id' => $cartId,
                'ip' => $_SERVER['REMOTE_ADDR'] ?? 'unknown'
            ]);
            
            // Supprimer le token compromis
            setcookie('cart_token', '', time() - 3600, '/');
            unset($_SESSION['cart_id']);
            
            Logger::info('REMOVE_DISCOUNT_API', 'Token panier supprimé, continuation en mode session');
        } else {
            Logger::debug('REMOVE_DISCOUNT_API', 'Token panier validé');
        }
    }
    
    // Rate limiting spécifique suppression codes promo
    if (!$secureDb->cartRateLimiter('discount_remove')) {
        Logger::warning('REMOVE_DISCOUNT_API', 'Rate limit dépassé pour suppression codes promo', [
            'ip' => $_SERVER['REMOTE_ADDR'] ?? 'unknown'
        ]);
        throw new Exception('Trop de tentatives de suppression, veuillez patienter');
    }
    
    Logger::debug('REMOVE_DISCOUNT_API', 'Rate limiting suppression codes promo validé');
    
    // Vérifier qu'un code promo est appliqué
    if (!isset($_SESSION['discount_code'])) {
        Logger::warning('REMOVE_DISCOUNT_API', 'Tentative suppression sans code promo appliqué');
        throw new Exception('Aucun code promo n\'est appliqué');
    }
    
    $discountCode = $_SESSION['discount_code']['code'] ?? 'unknown';
    $discountAmount = $_SESSION['discount_code']['amount'] ?? 0;
    
    Logger::info('REMOVE_DISCOUNT_API', 'Code promo trouvé pour suppression', [
        'discount_code' => $discountCode,
        'discount_amount' => $discountAmount
    ]);
    
    // Initialiser le panier
    $cart = new Cart();
    Logger::debug('REMOVE_DISCOUNT_API', 'Panier initialisé');
    
    // Supprimer le code promo via la classe Cart
    Logger::info('REMOVE_DISCOUNT_API', 'Début suppression code promo', [
        'discount_code' => $discountCode
    ]);
    
    $result = $cart->removeDiscount();
    
    if ($result !== true) {
        // $result contient le message d'erreur
        Logger::warning('REMOVE_DISCOUNT_API', 'Échec suppression code promo', [
            'discount_code' => $discountCode,
            'error_message' => $result
        ]);
        throw new Exception($result);
    }
    
    Logger::info('REMOVE_DISCOUNT_API', 'Code promo supprimé avec succès', [
        'discount_code' => $discountCode
    ]);
    
    // Log de succès détaillé
    Logger::info('REMOVE_DISCOUNT_API', 'Code promo supprimé avec succès - détails complets', [
        'code' => $discountCode,
        'previous_amount' => $discountAmount,
        'new_total' => $cart->getTotal(),
        'cart_items' => $cart->getItemCount(),
        'ip' => $_SERVER['REMOTE_ADDR'] ?? 'unknown',
        'user_agent' => $_SERVER['HTTP_USER_AGENT'] ?? 'unknown'
    ]);
    
    // Préparer la réponse de succès
    $response = [
        'success' => true,
        'message' => "Code promo {$discountCode} supprimé avec succès",
        'data' => [
            'removed_code' => $discountCode,
            'removed_amount' => $discountAmount,
            'new_total' => $cart->getTotal(),
            'cart_count' => $cart->getItemCount()
        ]
    ];
    
    Logger::info('REMOVE_DISCOUNT_API', 'Réponse API préparée avec succès', [
        'response_data' => $response['data']
    ]);
    
    echo json_encode($response);
    
} catch (Exception $e) {
    Logger::warning('REMOVE_DISCOUNT_API', 'Tentative de suppression code promo échouée', [
        'error' => $e->getMessage(),
        'existing_code' => $_SESSION['discount_code']['code'] ?? 'none',
        'ip' => $_SERVER['REMOTE_ADDR'] ?? 'unknown',
        'error_file' => $e->getFile(),
        'error_line' => $e->getLine(),
        'stack_trace' => $e->getTraceAsString()
    ]);
    
    // Déterminer le type d'erreur pour personnaliser la réponse
    $errorMessage = $e->getMessage();
    $errorCode = 'remove_error';
    
    if (strpos($errorMessage, 'Aucun code') !== false) {
        $errorCode = 'no_discount_applied';
    } elseif (strpos($errorMessage, 'token') !== false) {
        $errorCode = 'invalid_token';
    } elseif (strpos($errorMessage, 'tentatives') !== false) {
        $errorCode = 'rate_limit_exceeded';
    } elseif (strpos($errorMessage, 'Validation') !== false) {
        $errorCode = 'security_validation_failed';
    }
    
    Logger::debug('REMOVE_DISCOUNT_API', 'Code erreur déterminé', [
        'error_code' => $errorCode,
        'error_message' => $errorMessage
    ]);
    
    echo json_encode([
        'success' => false,
        'message' => $errorMessage,
        'error_code' => $errorCode
    ]);
}
?>