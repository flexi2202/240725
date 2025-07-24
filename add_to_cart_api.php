<?php
define('SECURE_ACCESS', true);

try {
    require_once "../securite/config.php";
    Logger::info('ADD_TO_CART_API', 'Configuration chargée avec succès');
} catch (Exception $e) {
    Logger::error('ADD_TO_CART_API', 'Erreur configuration critique', ['error' => $e->getMessage()]);
    echo json_encode(['success' => false, 'message' => 'Erreur configuration']);
    exit;
}

header('Content-Type: application/json');

// Vérification AJAX
if (!isset($_SERVER['HTTP_X_REQUESTED_WITH']) || 
    strtolower($_SERVER['HTTP_X_REQUESTED_WITH']) !== 'xmlhttprequest') {
    Logger::warning('ADD_TO_CART_API', 'Requête non AJAX rejetée', [
        'headers' => $_SERVER['HTTP_X_REQUESTED_WITH'] ?? 'ABSENT',
        'ip' => $_SERVER['REMOTE_ADDR'] ?? 'unknown'
    ]);
    echo json_encode(['success' => false, 'message' => 'Requête non autorisée']);
    exit;
}

// Vérification méthode POST
if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    Logger::warning('ADD_TO_CART_API', 'Méthode HTTP incorrecte', [
        'method' => $_SERVER['REQUEST_METHOD'],
        'ip' => $_SERVER['REMOTE_ADDR'] ?? 'unknown'
    ]);
    echo json_encode(['success' => false, 'message' => 'Méthode non autorisée']);
    exit;
}

Logger::debug('ADD_TO_CART_API', 'Requête AJAX POST validée');

try {
    $secureDb = SecureDatabase::getInstance();
    Logger::debug('ADD_TO_CART_API', 'Instance SecureDatabase récupérée');
    
    // Validation sécurité
    if (!$secureDb->validateApiRequest('add', true)) {
        Logger::error('ADD_TO_CART_API', 'Échec validation API request');
        throw new Exception('Validation sécurité échouée');
    }
    
    Logger::debug('ADD_TO_CART_API', 'Validation API réussie');
    
    // Vérification token panier avant modification
    $cartToken = $_COOKIE['cart_token'] ?? null;
    $cartId = $_SESSION['cart_id'] ?? null;
    
    if ($cartToken && $cartId) {
        if (!$secureDb->verifyCartToken($cartToken, $cartId, session_id())) {
            Logger::warning('ADD_TO_CART_API', 'Token panier invalide pour modification', [
                'cart_id' => $cartId,
                'ip' => $_SERVER['REMOTE_ADDR'] ?? 'unknown'
            ]);
            
            Logger::security('ADD_TO_CART_API', "Tentative modification panier avec token invalide", [
                'api' => 'add_to_cart',
                'product_id' => $_POST['product_id'] ?? 'unknown',
                'cart_id' => $cartId,
                'ip' => $_SERVER['REMOTE_ADDR'] ?? 'unknown'
            ]);
            
            // Pour les modifications, être plus strict
            throw new Exception('Token de panier invalide - Veuillez recharger la page');
        } else {
            Logger::debug('ADD_TO_CART_API', 'Token panier validé pour modification');
        }
    }
    
    // Sanitisation unifiée via SecureDatabase
    $productId = $secureDb->sanitizeInput($_POST['product_id'] ?? 0, 'int');
    $quantity = $secureDb->sanitizeInput($_POST['quantity'] ?? 1, 'int');
    
    Logger::debug('ADD_TO_CART_API', 'Données sanitisées', [
        'product_id' => $productId,
        'quantity' => $quantity
    ]);
    
    // Validation des valeurs
    if ($productId <= 0) {
        Logger::error('ADD_TO_CART_API', 'Product ID invalide', ['product_id' => $productId]);
        throw new Exception('ID produit invalide');
    }
    
    if ($quantity <= 0 || $quantity > 100) {
        Logger::error('ADD_TO_CART_API', 'Quantité invalide', ['quantity' => $quantity]);
        throw new Exception('Quantité invalide');
    }
    
    Logger::info('ADD_TO_CART_API', 'Validation des données réussie', [
        'product_id' => $productId,
        'quantity' => $quantity
    ]);
    
    // Rate limiting
    if (!$secureDb->cartRateLimiter('add', $productId)) {
        Logger::warning('ADD_TO_CART_API', 'Rate limit dépassé', [
            'product_id' => $productId,
            'ip' => $_SERVER['REMOTE_ADDR'] ?? 'unknown'
        ]);
        throw new Exception('Trop d\'ajouts rapides');
    }
    
    Logger::debug('ADD_TO_CART_API', 'Rate limiting validé');
    
    // Validation produit via SecureDatabase
    if (!$secureDb->validateProductId($productId, true)) {
        Logger::error('ADD_TO_CART_API', 'Produit invalide ou inexistant', [
            'product_id' => $productId
        ]);
        throw new Exception('Produit invalide ou inexistant');
    }
    
    Logger::debug('ADD_TO_CART_API', 'Produit validé', ['product_id' => $productId]);
    
    // Initialiser panier
    $cart = new Cart();
    Logger::debug('ADD_TO_CART_API', 'Panier initialisé');
    
    // Ajouter le produit
    Logger::info('ADD_TO_CART_API', 'Début ajout produit au panier', [
        'product_id' => $productId,
        'quantity' => $quantity
    ]);
    
    $result = $cart->addItem($productId, $quantity);
    
    if ($result === true) {
        Logger::info('ADD_TO_CART_API', 'Produit ajouté avec succès au panier', [
            'product_id' => $productId,
            'quantity' => $quantity
        ]);
        
        // Générer trigger de synchronisation
        $_SESSION['cart_sync_trigger'] = [
            'action' => 'product_added',
            'product_id' => $productId,
            'quantity' => $quantity,
            'timestamp' => time()
        ];
        
        $cartTotal = $cart->getTotal();
        $cartCount = $cart->getItemCount();
        
        Logger::info('ADD_TO_CART_API', 'État panier après ajout', [
            'total' => $cartTotal,
            'item_count' => $cartCount
        ]);
        
        $response = [
            'success' => true,
            'message' => 'Produit ajouté avec succès',
            'data' => [
                'product_id' => $productId,
                'quantity' => $quantity,
                'cart_total' => $cartTotal,
                'cart_count' => $cartCount
            ]
        ];
        
        Logger::info('ADD_TO_CART_API', 'Réponse API préparée avec succès', [
            'response_data' => $response['data']
        ]);
        
        echo json_encode($response);
        
    } else {
        Logger::error('ADD_TO_CART_API', 'Échec ajout produit au panier', [
            'product_id' => $productId,
            'quantity' => $quantity,
            'error_result' => $result
        ]);
        throw new Exception($result);
    }
    
} catch (Exception $e) {
    Logger::error('ADD_TO_CART_API', 'Erreur critique dans API', [
        'error_message' => $e->getMessage(),
        'error_file' => $e->getFile(),
        'error_line' => $e->getLine(),
        'post_data' => $_POST,
        'stack_trace' => $e->getTraceAsString()
    ]);
    
    echo json_encode([
        'success' => false,
        'message' => $e->getMessage()
    ]);
}
?>