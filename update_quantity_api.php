<?php
define('SECURE_ACCESS', true);

try {
    require_once "../securite/config.php";
    Logger::info('UPDATE_QUANTITY_API', 'Configuration chargée avec succès');
} catch (Exception $e) {
    Logger::error('UPDATE_QUANTITY_API', 'Erreur configuration critique', ['error' => $e->getMessage()]);
    echo json_encode(['success' => false, 'message' => 'Erreur configuration']);
    exit;
}

header('Content-Type: application/json');

// Vérification AJAX
if (!isset($_SERVER['HTTP_X_REQUESTED_WITH']) || 
    strtolower($_SERVER['HTTP_X_REQUESTED_WITH']) !== 'xmlhttprequest') {
    Logger::warning('UPDATE_QUANTITY_API', 'Requête non AJAX rejetée', [
        'headers' => $_SERVER['HTTP_X_REQUESTED_WITH'] ?? 'ABSENT',
        'ip' => $_SERVER['REMOTE_ADDR'] ?? 'unknown'
    ]);
    echo json_encode(['success' => false, 'message' => 'Requête non autorisée']);
    exit;
}

// Vérification méthode POST
if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    Logger::warning('UPDATE_QUANTITY_API', 'Méthode HTTP incorrecte', [
        'method' => $_SERVER['REQUEST_METHOD'],
        'ip' => $_SERVER['REMOTE_ADDR'] ?? 'unknown'
    ]);
    echo json_encode(['success' => false, 'message' => 'Méthode non autorisée']);
    exit;
}

Logger::debug('UPDATE_QUANTITY_API', 'Requête AJAX POST validée');

try {
    $secureDb = SecureDatabase::getInstance();
    Logger::debug('UPDATE_QUANTITY_API', 'Instance SecureDatabase récupérée');
    
    // Validation sécurité
    if (!$secureDb->validateApiRequest('api_update', true)) {
        Logger::error('UPDATE_QUANTITY_API', 'Échec validation API request');
        throw new Exception('Validation sécurité échouée');
    }
    
    Logger::debug('UPDATE_QUANTITY_API', 'Validation API réussie');
    
    // Vérification token panier avant modification
    $cartToken = $_COOKIE['cart_token'] ?? null;
    $cartId = $_SESSION['cart_id'] ?? null;
    
    if ($cartToken && $cartId) {
        if (!$secureDb->verifyCartToken($cartToken, $cartId, session_id())) {
            Logger::warning('UPDATE_QUANTITY_API', 'Token panier invalide pour modification', [
                'cart_id' => $cartId,
                'ip' => $_SERVER['REMOTE_ADDR'] ?? 'unknown'
            ]);
            
            Logger::security('UPDATE_QUANTITY_API', "Tentative modification panier avec token invalide", [
                'api' => 'update_quantity',
                'product_id' => $_POST['product_id'] ?? 'unknown',
                'action' => $_POST['action'] ?? 'unknown',
                'cart_id' => $cartId,
                'ip' => $_SERVER['REMOTE_ADDR'] ?? 'unknown'
            ]);
            
            // Pour les modifications, être plus strict
            throw new Exception('Token de panier invalide - Veuillez recharger la page');
        } else {
            Logger::debug('UPDATE_QUANTITY_API', 'Token panier validé pour modification');
        }
    }
    
    // Sanitisation unifiée via SecureDatabase
    $productId = $secureDb->sanitizeInput($_POST['product_id'] ?? 0, 'int');
    $action = $secureDb->sanitizeInput($_POST['action'] ?? '', 'string');
    
    Logger::debug('UPDATE_QUANTITY_API', 'Données sanitisées', [
        'product_id' => $productId,
        'action' => $action
    ]);
    
    // Validation des valeurs
    if ($productId <= 0) {
        Logger::error('UPDATE_QUANTITY_API', 'Product ID invalide', ['product_id' => $productId]);
        throw new Exception('ID produit invalide');
    }
    
    $allowedActions = ['increase', 'decrease', 'remove'];
    if (!in_array($action, $allowedActions, true)) {
        Logger::error('UPDATE_QUANTITY_API', 'Action invalide', [
            'action' => $action,
            'allowed_actions' => $allowedActions
        ]);
        throw new Exception('Action non autorisée');
    }
    
    Logger::info('UPDATE_QUANTITY_API', 'Validation des données réussie', [
        'product_id' => $productId,
        'action' => $action
    ]);
    
    // Rate limiting
    if (!$secureDb->cartRateLimiter($action, $productId)) {
        Logger::warning('UPDATE_QUANTITY_API', 'Rate limit dépassé', [
            'action' => $action,
            'product_id' => $productId,
            'ip' => $_SERVER['REMOTE_ADDR'] ?? 'unknown'
        ]);
        throw new Exception('Trop de requêtes rapides');
    }
    
    Logger::debug('UPDATE_QUANTITY_API', 'Rate limiting validé');
    
    // Validation produit via SecureDatabase
    if (!$secureDb->validateProductId($productId, true)) {
        Logger::error('UPDATE_QUANTITY_API', 'Produit invalide ou inexistant', [
            'product_id' => $productId
        ]);
        throw new Exception('Produit invalide ou inexistant');
    }
    
    Logger::debug('UPDATE_QUANTITY_API', 'Produit validé', ['product_id' => $productId]);
    
    // Initialiser panier
    $cart = new Cart();
    Logger::debug('UPDATE_QUANTITY_API', 'Panier initialisé');
    
    // Exécuter l'action selon le type
    Logger::info('UPDATE_QUANTITY_API', 'Début exécution action', [
        'action' => $action,
        'product_id' => $productId
    ]);
    
    $result = false;
    $message = '';
    $newQuantity = 0;
    
    switch ($action) {
        case 'increase':
            $currentItem = $cart->getItem($productId);
            if ($currentItem) {
                $newQuantity = $currentItem['quantity'] + 1;
                $result = $cart->updateItem($productId, $newQuantity);
                $message = 'Quantité augmentée';
                Logger::debug('UPDATE_QUANTITY_API', 'Quantité augmentée', [
                    'product_id' => $productId,
                    'new_quantity' => $newQuantity
                ]);
            } else {
                $newQuantity = 1;
                $result = $cart->addItem($productId, 1);
                $message = 'Produit ajouté';
                Logger::debug('UPDATE_QUANTITY_API', 'Produit ajouté', ['product_id' => $productId]);
            }
            break;
            
        case 'decrease':
            $currentItem = $cart->getItem($productId);
            if ($currentItem && $currentItem['quantity'] > 1) {
                $newQuantity = $currentItem['quantity'] - 1;
                $result = $cart->updateItem($productId, $newQuantity);
                $message = 'Quantité diminuée';
                Logger::debug('UPDATE_QUANTITY_API', 'Quantité diminuée', [
                    'product_id' => $productId,
                    'new_quantity' => $newQuantity
                ]);
            } else {
                $newQuantity = 0;
                $result = $cart->removeItem($productId);
                $message = 'Produit supprimé';
                Logger::debug('UPDATE_QUANTITY_API', 'Produit supprimé (quantité 0)', [
                    'product_id' => $productId
                ]);
            }
            break;
            
        case 'remove':
            $newQuantity = 0;
            $result = $cart->removeItem($productId);
            $message = 'Produit supprimé';
            Logger::debug('UPDATE_QUANTITY_API', 'Produit supprimé', ['product_id' => $productId]);
            break;
    }
    
    if ($result === true) {
        Logger::info('UPDATE_QUANTITY_API', 'Action exécutée avec succès', [
            'action' => $action,
            'product_id' => $productId,
            'new_quantity' => $newQuantity,
            'message' => $message
        ]);
        
        // Générer trigger de synchronisation
        $_SESSION['cart_sync_trigger'] = [
            'action' => $action,
            'product_id' => $productId,
            'new_quantity' => $newQuantity,
            'timestamp' => time()
        ];
        
        $cartTotal = $cart->getTotal();
        $cartCount = $cart->getItemCount();
        
        Logger::info('UPDATE_QUANTITY_API', 'État panier après action', [
            'total' => $cartTotal,
            'item_count' => $cartCount
        ]);
        
        $response = [
            'success' => true,
            'message' => $message,
            'data' => [
                'action' => $action,
                'product_id' => $productId,
                'new_quantity' => $newQuantity,
                'cart_total' => $cartTotal,
                'cart_count' => $cartCount
            ]
        ];
        
        Logger::info('UPDATE_QUANTITY_API', 'Réponse API préparée avec succès', [
            'response_data' => $response['data']
        ]);
        
        echo json_encode($response);
        
    } else {
        Logger::error('UPDATE_QUANTITY_API', 'Échec exécution action', [
            'action' => $action,
            'product_id' => $productId,
            'error_result' => $result
        ]);
        throw new Exception($result);
    }
    
} catch (Exception $e) {
    Logger::error('UPDATE_QUANTITY_API', 'Erreur critique dans API', [
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