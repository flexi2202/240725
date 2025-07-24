<?php
define('SECURE_ACCESS', true);

try {
    require_once "../securite/config.php";
    Logger::info('REMOVE_ITEM_API', 'Configuration chargée avec succès');
} catch (Exception $e) {
    Logger::error('REMOVE_ITEM_API', 'Erreur configuration critique', ['error' => $e->getMessage()]);
    echo json_encode(['success' => false, 'message' => 'Erreur configuration']);
    exit;
}

header('Content-Type: application/json');

// Vérification AJAX
if (!isset($_SERVER['HTTP_X_REQUESTED_WITH']) || 
    strtolower($_SERVER['HTTP_X_REQUESTED_WITH']) !== 'xmlhttprequest') {
    Logger::warning('REMOVE_ITEM_API', 'Requête non AJAX rejetée', [
        'headers' => $_SERVER['HTTP_X_REQUESTED_WITH'] ?? 'ABSENT',
        'ip' => $_SERVER['REMOTE_ADDR'] ?? 'unknown'
    ]);
    echo json_encode(['success' => false, 'message' => 'Requête non autorisée']);
    exit;
}

// Vérification méthode POST
if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    Logger::warning('REMOVE_ITEM_API', 'Méthode HTTP incorrecte', [
        'method' => $_SERVER['REQUEST_METHOD'],
        'ip' => $_SERVER['REMOTE_ADDR'] ?? 'unknown'
    ]);
    echo json_encode(['success' => false, 'message' => 'Méthode non autorisée']);
    exit;
}

Logger::debug('REMOVE_ITEM_API', 'Requête AJAX POST validée');

try {
    $secureDb = SecureDatabase::getInstance();
    Logger::debug('REMOVE_ITEM_API', 'Instance SecureDatabase récupérée');
    
    // Validation sécurité
    if (!$secureDb->validateApiRequest('remove', true)) {
        Logger::error('REMOVE_ITEM_API', 'Échec validation API request');
        throw new Exception('Validation sécurité échouée');
    }
    
    Logger::debug('REMOVE_ITEM_API', 'Validation API réussie');
    
    // Vérification token panier avant modification
    $cartToken = $_COOKIE['cart_token'] ?? null;
    $cartId = $_SESSION['cart_id'] ?? null;
    
    if ($cartToken && $cartId) {
        if (!$secureDb->verifyCartToken($cartToken, $cartId, session_id())) {
            Logger::warning('REMOVE_ITEM_API', 'Token panier invalide pour suppression', [
                'cart_id' => $cartId,
                'ip' => $_SERVER['REMOTE_ADDR'] ?? 'unknown'
            ]);
            
            Logger::security('REMOVE_ITEM_API', "Tentative suppression article avec token invalide", [
                'api' => 'remove_item',
                'product_id' => $_POST['product_id'] ?? 'unknown',
                'cart_id' => $cartId,
                'ip' => $_SERVER['REMOTE_ADDR'] ?? 'unknown'
            ]);
            
            // Pour les suppressions, être strict sur la sécurité
            throw new Exception('Token de panier invalide - Veuillez recharger la page');
        } else {
            Logger::debug('REMOVE_ITEM_API', 'Token panier validé pour suppression');
        }
    }
    
    // Sanitisation unifiée via SecureDatabase
    $productId = $secureDb->sanitizeInput($_POST['product_id'] ?? 0, 'int');
    
    Logger::debug('REMOVE_ITEM_API', 'Données sanitisées', [
        'product_id' => $productId
    ]);
    
    // Validation des valeurs
    if ($productId <= 0) {
        Logger::error('REMOVE_ITEM_API', 'Product ID invalide', ['product_id' => $productId]);
        throw new Exception('ID produit invalide');
    }
    
    Logger::info('REMOVE_ITEM_API', 'Validation des données réussie', [
        'product_id' => $productId
    ]);
    
    // Rate limiting pour suppression
    if (!$secureDb->cartRateLimiter('remove', $productId)) {
        Logger::warning('REMOVE_ITEM_API', 'Rate limit dépassé pour suppression', [
            'product_id' => $productId,
            'ip' => $_SERVER['REMOTE_ADDR'] ?? 'unknown'
        ]);
        throw new Exception('Trop de suppressions rapides');
    }
    
    Logger::debug('REMOVE_ITEM_API', 'Rate limiting validé');
    
    // Validation produit via SecureDatabase (pas besoin de vérifier en DB pour suppression)
    if (!$secureDb->validateProductId($productId, false)) {
        Logger::error('REMOVE_ITEM_API', 'Format Product ID invalide', [
            'product_id' => $productId
        ]);
        throw new Exception('Format ID produit invalide');
    }
    
    Logger::debug('REMOVE_ITEM_API', 'Format produit validé', ['product_id' => $productId]);
    
    // Initialiser panier
    $cart = new Cart();
    Logger::debug('REMOVE_ITEM_API', 'Panier initialisé');
    
    // Récupérer les informations de l'article avant suppression pour le log
    $itemToRemove = $cart->getItem($productId);
    if (!$itemToRemove) {
        Logger::warning('REMOVE_ITEM_API', 'Tentative suppression article inexistant', [
            'product_id' => $productId
        ]);
        throw new Exception('Article non trouvé dans le panier');
    }
    
    // Supprimer l'article
    Logger::info('REMOVE_ITEM_API', 'Début suppression article du panier', [
        'product_id' => $productId,
        'product_name' => $itemToRemove['name'] ?? "Produit #{$productId}",
        'quantity' => $itemToRemove['quantity'],
        'price' => $itemToRemove['price']
    ]);
    
    $result = $cart->removeItem($productId);
    
    if ($result === true) {
        Logger::info('REMOVE_ITEM_API', 'Article supprimé avec succès du panier', [
            'product_id' => $productId,
            'product_name' => $itemToRemove['name'] ?? "Produit #{$productId}",
            'quantity_removed' => $itemToRemove['quantity'],
            'value_removed' => $itemToRemove['subtotal']
        ]);
        
        // Générer trigger de synchronisation
        $_SESSION['cart_sync_trigger'] = [
            'action' => 'item_removed',
            'product_id' => $productId,
            'product_name' => $itemToRemove['name'] ?? "Produit #{$productId}",
            'quantity_removed' => $itemToRemove['quantity'],
            'value_removed' => $itemToRemove['subtotal'],
            'timestamp' => time()
        ];
        
        $cartTotal = $cart->getTotal();
        $cartCount = $cart->getItemCount();
        
        Logger::info('REMOVE_ITEM_API', 'État panier après suppression', [
            'total' => $cartTotal,
            'item_count' => $cartCount
        ]);
        
        $response = [
            'success' => true,
            'message' => 'Article supprimé avec succès',
            'data' => [
                'product_id' => $productId,
                'product_name' => $itemToRemove['name'] ?? "Produit #{$productId}",
                'quantity_removed' => $itemToRemove['quantity'],
                'value_removed' => $itemToRemove['subtotal'],
                'cart_total' => $cartTotal,
                'cart_count' => $cartCount
            ]
        ];
        
        Logger::info('REMOVE_ITEM_API', 'Réponse API préparée avec succès', [
            'response_data' => $response['data']
        ]);
        
        echo json_encode($response);
        
    } else {
        Logger::error('REMOVE_ITEM_API', 'Échec suppression article du panier', [
            'product_id' => $productId,
            'error_result' => $result
        ]);
        throw new Exception($result);
    }
    
} catch (Exception $e) {
    Logger::error('REMOVE_ITEM_API', 'Erreur critique dans API', [
        'error_message' => $e->getMessage(),
        'error_file' => $e->getFile(),
        'error_line' => $e->getLine(),
        'post_data' => $_POST,
        'stack_trace' => $e->getTraceAsString()
    ]);
    
    // Déterminer le type d'erreur pour personnaliser la réponse
    $errorMessage = $e->getMessage();
    $errorCode = 'remove_error';
    
    if (strpos($errorMessage, 'ID produit invalide') !== false) {
        $errorCode = 'invalid_product_id';
    } elseif (strpos($errorMessage, 'non trouvé') !== false) {
        $errorCode = 'item_not_found';
    } elseif (strpos($errorMessage, 'token') !== false) {
        $errorCode = 'invalid_token';
    } elseif (strpos($errorMessage, 'suppressions rapides') !== false) {
        $errorCode = 'rate_limit_exceeded';
    } elseif (strpos($errorMessage, 'Validation') !== false) {
        $errorCode = 'security_validation_failed';
    }
    
    Logger::debug('REMOVE_ITEM_API', 'Code erreur déterminé', [
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