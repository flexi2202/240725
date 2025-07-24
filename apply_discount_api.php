<?php
define('SECURE_ACCESS', true);

try {
    require_once "../securite/config.php";
    Logger::info('APPLY_DISCOUNT_API', 'Configuration chargée avec succès');
} catch (Exception $e) {
    Logger::error('APPLY_DISCOUNT_API', 'Erreur configuration critique', ['error' => $e->getMessage()]);
    echo json_encode(['success' => false, 'message' => 'Erreur configuration']);
    exit;
}

header('Content-Type: application/json');
header('Cache-Control: no-cache, must-revalidate');

// Vérification AJAX
if (!isset($_SERVER['HTTP_X_REQUESTED_WITH']) || 
    strtolower($_SERVER['HTTP_X_REQUESTED_WITH']) !== 'xmlhttprequest') {
    Logger::warning('APPLY_DISCOUNT_API', 'Requête non AJAX rejetée', [
        'headers' => $_SERVER['HTTP_X_REQUESTED_WITH'] ?? 'ABSENT',
        'ip' => $_SERVER['REMOTE_ADDR'] ?? 'unknown'
    ]);
    echo json_encode(['success' => false, 'message' => 'Requête non autorisée']);
    exit;
}

// Vérification méthode POST
if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    Logger::warning('APPLY_DISCOUNT_API', 'Méthode HTTP incorrecte', [
        'method' => $_SERVER['REQUEST_METHOD'],
        'ip' => $_SERVER['REMOTE_ADDR'] ?? 'unknown'
    ]);
    echo json_encode(['success' => false, 'message' => 'Méthode non autorisée']);
    exit;
}

Logger::debug('APPLY_DISCOUNT_API', 'Requête AJAX POST validée');

try {
    $secureDb = SecureDatabase::getInstance();
    Logger::debug('APPLY_DISCOUNT_API', 'Instance SecureDatabase récupérée');
    
    // Validation sécurité
    if (!$secureDb->validateApiRequest('api_discount', true)) {
        Logger::error('APPLY_DISCOUNT_API', 'Échec validation API request');
        throw new Exception('Validation sécurité échouée');
    }
    
    Logger::debug('APPLY_DISCOUNT_API', 'Validation API réussie');
    
    // Vérification token panier si fourni
    $cartToken = $_COOKIE['cart_token'] ?? null;
    $cartId = $_SESSION['cart_id'] ?? null;
    
    if ($cartToken && $cartId) {
        if (!$secureDb->verifyCartToken($cartToken, $cartId, session_id())) {
            Logger::warning('APPLY_DISCOUNT_API', 'Token panier invalide détecté', [
                'cart_id' => $cartId,
                'ip' => $_SERVER['REMOTE_ADDR'] ?? 'unknown'
            ]);
            
            Logger::security('APPLY_DISCOUNT_API', "Tentative application code promo avec token invalide", [
                'api' => 'apply_discount',
                'discount_code' => $_POST['discount_code'] ?? 'unknown',
                'cart_id' => $cartId,
                'ip' => $_SERVER['REMOTE_ADDR'] ?? 'unknown'
            ]);
            
            // Supprimer le token compromis
            setcookie('cart_token', '', time() - 3600, '/');
            unset($_SESSION['cart_id']);
            
            Logger::info('APPLY_DISCOUNT_API', 'Token panier supprimé, continuation en mode session');
        } else {
            Logger::debug('APPLY_DISCOUNT_API', 'Token panier validé');
        }
    }
    
    // Rate limiting spécifique aux codes promo (15 tentatives/minute)
    if (!$secureDb->cartRateLimiter('discount_apply', null)) {
        Logger::warning('APPLY_DISCOUNT_API', 'Rate limit dépassé pour codes promo', [
            'ip' => $_SERVER['REMOTE_ADDR'] ?? 'unknown'
        ]);
        throw new Exception('Trop de tentatives de codes promo, veuillez patienter');
    }
    
    Logger::debug('APPLY_DISCOUNT_API', 'Rate limiting codes promo validé');
    
    // Sanitisation unifiée via SecureDatabase
    $discountCode = $secureDb->sanitizeInput($_POST['discount_code'] ?? '', 'string');
    
    Logger::debug('APPLY_DISCOUNT_API', 'Code promo sanitisé', ['discount_code' => $discountCode]);
    
    // Validation du code promo
    if (empty($discountCode)) {
        Logger::error('APPLY_DISCOUNT_API', 'Code promo requis mais vide');
        throw new Exception('Code promo requis');
    }
    
    // Validation format du code (2-20 caractères alphanumériques)
    if (!preg_match('/^[A-Za-z0-9]{2,20}$/', $discountCode)) {
        Logger::error('APPLY_DISCOUNT_API', 'Format code promo invalide', [
            'discount_code' => $discountCode,
            'length' => strlen($discountCode)
        ]);
        throw new Exception('Format de code promo invalide');
    }
    
    // Convertir en majuscules pour consistance
    $discountCode = strtoupper($discountCode);
    
    Logger::info('APPLY_DISCOUNT_API', 'Validation code promo réussie', [
        'discount_code' => $discountCode
    ]);
    
    // Vérifier qu'aucun code n'est déjà appliqué
    if (isset($_SESSION['discount_code'])) {
        $existingCode = $_SESSION['discount_code']['code'] ?? 'unknown';
        Logger::warning('APPLY_DISCOUNT_API', 'Tentative application code alors qu\'un code existe déjà', [
            'existing_code' => $existingCode,
            'attempted_code' => $discountCode
        ]);
        throw new Exception('Un code promo est déjà appliqué. Veuillez le retirer avant d\'en ajouter un autre.');
    }
    
    Logger::debug('APPLY_DISCOUNT_API', 'Aucun code promo déjà appliqué');
    
    // Initialiser le panier et valider
    $cart = new Cart();
    Logger::debug('APPLY_DISCOUNT_API', 'Panier initialisé');
    
    $cartTotal = $cart->getTotal();
    
    if ($cart->isEmpty()) {
        Logger::error('APPLY_DISCOUNT_API', 'Tentative application code promo sur panier vide');
        throw new Exception('Votre panier est vide');
    }
    
    Logger::info('APPLY_DISCOUNT_API', 'Panier validé', [
        'cart_total' => $cartTotal,
        'cart_items' => $cart->getItemCount()
    ]);
    
    // Appliquer le code promo via la classe Cart
    Logger::info('APPLY_DISCOUNT_API', 'Début application code promo', [
        'discount_code' => $discountCode,
        'cart_total_before' => $cartTotal
    ]);
    
    $result = $cart->applyDiscount($discountCode);
    
    if ($result !== true) {
        // $result contient le message d'erreur
        Logger::warning('APPLY_DISCOUNT_API', 'Échec application code promo', [
            'discount_code' => $discountCode,
            'error_message' => $result
        ]);
        throw new Exception($result);
    }
    
    Logger::info('APPLY_DISCOUNT_API', 'Code promo appliqué avec succès', [
        'discount_code' => $discountCode
    ]);
    
    // Récupérer les informations du code appliqué
    $discountInfo = $cart->getDiscountInfo();
    
    if (!$discountInfo) {
        Logger::error('APPLY_DISCOUNT_API', 'Impossible de récupérer informations réduction après application');
        throw new Exception('Erreur lors de la récupération des informations de réduction');
    }
    
    // Log de succès détaillé
    Logger::info('APPLY_DISCOUNT_API', 'Code promo appliqué avec succès - détails complets', [
        'code' => $discountCode,
        'type' => $discountInfo['type'],
        'value' => $discountInfo['value'],
        'discount_amount' => $discountInfo['amount'],
        'cart_total_before' => $discountInfo['subtotal_before'],
        'cart_total_after' => $discountInfo['total_after'],
        'savings_percentage' => round(($discountInfo['amount'] / $discountInfo['subtotal_before']) * 100, 1),
        'ip' => $_SERVER['REMOTE_ADDR'] ?? 'unknown',
        'user_agent' => $_SERVER['HTTP_USER_AGENT'] ?? 'unknown'
    ]);
    
    // Préparer la réponse de succès
    $response = [
        'success' => true,
        'message' => "Code promo {$discountCode} appliqué avec succès !",
        'data' => [
            'code' => $discountInfo['code'],
            'type' => $discountInfo['type'],
            'value' => $discountInfo['value'],
            'discount_amount' => $discountInfo['amount'],
            'cart_subtotal' => $discountInfo['subtotal_before'],
            'cart_total' => $discountInfo['total_after'],
            'savings' => $discountInfo['amount'],
            'savings_percentage' => round(($discountInfo['amount'] / $discountInfo['subtotal_before']) * 100, 1)
        ]
    ];
    
    Logger::info('APPLY_DISCOUNT_API', 'Réponse API préparée avec succès', [
        'response_data' => $response['data']
    ]);
    
    echo json_encode($response);
    
} catch (Exception $e) {
    Logger::warning('APPLY_DISCOUNT_API', 'Tentative de code promo échouée', [
        'error' => $e->getMessage(),
        'code' => $_POST['discount_code'] ?? 'unknown',
        'ip' => $_SERVER['REMOTE_ADDR'] ?? 'unknown',
        'error_file' => $e->getFile(),
        'error_line' => $e->getLine(),
        'stack_trace' => $e->getTraceAsString()
    ]);
    
    // Déterminer le type d'erreur pour personnaliser la réponse
    $errorMessage = $e->getMessage();
    $errorCode = 'discount_error';
    
    if (strpos($errorMessage, 'expiré') !== false) {
        $errorCode = 'discount_expired';
    } elseif (strpos($errorMessage, 'invalide') !== false || strpos($errorMessage, 'introuvable') !== false) {
        $errorCode = 'discount_invalid';
    } elseif (strpos($errorMessage, 'minimum') !== false) {
        $errorCode = 'minimum_not_reached';
    } elseif (strpos($errorMessage, 'limite') !== false || strpos($errorMessage, 'épuisé') !== false) {
        $errorCode = 'usage_limit_reached';
    } elseif (strpos($errorMessage, 'déjà appliqué') !== false) {
        $errorCode = 'already_applied';
    } elseif (strpos($errorMessage, 'panier vide') !== false) {
        $errorCode = 'empty_cart';
    } elseif (strpos($errorMessage, 'token') !== false) {
        $errorCode = 'invalid_token';
    } elseif (strpos($errorMessage, 'tentatives') !== false) {
        $errorCode = 'rate_limit_exceeded';
    }
    
    Logger::debug('APPLY_DISCOUNT_API', 'Code erreur déterminé', [
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