<?php
define('SECURE_ACCESS', true);

try {
    require_once "../securite/config.php";
    Logger::info('GET_CART_API', 'Configuration chargée avec succès');
} catch (Exception $e) {
    Logger::error('GET_CART_API', 'Erreur configuration critique', ['error' => $e->getMessage()]);
    echo json_encode(['success' => false, 'message' => 'Erreur configuration']);
    exit;
}

header('Content-Type: application/json');
header('Cache-Control: no-cache, must-revalidate');

// Vérification AJAX
if (!isset($_SERVER['HTTP_X_REQUESTED_WITH']) || 
    strtolower($_SERVER['HTTP_X_REQUESTED_WITH']) !== 'xmlhttprequest') {
    Logger::warning('GET_CART_API', 'Requête non AJAX rejetée', [
        'headers' => $_SERVER['HTTP_X_REQUESTED_WITH'] ?? 'ABSENT',
        'ip' => $_SERVER['REMOTE_ADDR'] ?? 'unknown'
    ]);
    echo json_encode(['success' => false, 'message' => 'Requête non autorisée']);
    exit;
}

Logger::debug('GET_CART_API', 'Requête AJAX validée');

try {
    $secureDb = SecureDatabase::getInstance();
    Logger::debug('GET_CART_API', 'Instance SecureDatabase récupérée');
    
    // Validation sécurité
    if (!$secureDb->validateApiRequest('api_info', false)) {
        Logger::error('GET_CART_API', 'Échec validation API request');
        throw new Exception('Accès non autorisé');
    }
    
    Logger::debug('GET_CART_API', 'Validation API réussie');
    
    // Vérification token panier
    $cartToken = $_COOKIE['cart_token'] ?? null;
    $cartId = $_SESSION['cart_id'] ?? null;
    
    if ($cartToken && $cartId) {
        if (!$secureDb->verifyCartToken($cartToken, $cartId, session_id())) {
            Logger::warning('GET_CART_API', 'Token panier invalide, nettoyage effectué', [
                'cart_id' => $cartId,
                'ip' => $_SERVER['REMOTE_ADDR'] ?? 'unknown'
            ]);
            
            Logger::security('GET_CART_API', "Token panier invalide dans API", [
                'api' => 'get_cart',
                'cart_id' => $cartId,
                'ip' => $_SERVER['REMOTE_ADDR'] ?? 'unknown'
            ]);
            
            // Supprimer le token compromis
            setcookie('cart_token', '', time() - 3600, '/');
            unset($_SESSION['cart_id']);
        } else {
            Logger::debug('GET_CART_API', 'Token panier validé');
        }
    }
    
    // Initialisation panier
    $cart = new Cart();
    Logger::debug('GET_CART_API', 'Panier initialisé');
    
    // Récupération données panier
    $items = $cart->getItems(true); // avec détails
    $subtotal = $cart->getSubtotalBeforeDiscount();
    $discountInfo = $cart->getDiscountInfo();
    $total = $cart->getTotal();
    $itemCount = $cart->getItemCount();
    
    Logger::info('GET_CART_API', 'Données panier récupérées', [
        'items_count' => $itemCount,
        'subtotal' => $subtotal,
        'total' => $total,
        'has_discount' => $discountInfo !== null
    ]);
    
    // Préparer la réponse avec les informations de base
    $responseData = [
        'cart_id' => $cart->getCartId(),
        'items' => $items,
        'subtotal' => round($subtotal, 2),
        'total' => round($total, 2),
        'item_count' => $itemCount,
        'timestamp' => time()
    ];
    
    // Préparation des informations de réduction
    if ($discountInfo) {
        $responseData['discount_info'] = [
            'code' => $discountInfo['code'],
            'type' => $discountInfo['type'],
            'value' => $discountInfo['value'],
            'amount' => $discountInfo['amount'],
            'applied_at' => $discountInfo['applied_at']
        ];
        
        Logger::debug('GET_CART_API', 'Code promo inclus dans réponse', [
            'code' => $discountInfo['code']
        ]);
    } else {
        $responseData['discount_info'] = null;
    }
    
    // Totaux finaux
    $responseData['totals'] = [
        'subtotal' => round($subtotal, 2),
        'discount_amount' => $discountInfo ? round($discountInfo['amount'], 2) : 0,
        'total_after_discount' => round($total, 2)
    ];
    
    Logger::info('GET_CART_API', 'Réponse préparée et envoyée', [
        'items_count' => $itemCount,
        'has_discount' => $discountInfo !== null,
        'total' => $total
    ]);
    
    echo json_encode([
        'success' => true,
        'data' => $responseData
    ]);
    
} catch (Exception $e) {
    Logger::error('GET_CART_API', 'Erreur critique dans API', [
        'error_message' => $e->getMessage(),
        'error_file' => $e->getFile(),
        'error_line' => $e->getLine(),
        'stack_trace' => $e->getTraceAsString()
    ]);
    
    echo json_encode([
        'success' => false,
        'message' => $e->getMessage()
    ]);
}
?>