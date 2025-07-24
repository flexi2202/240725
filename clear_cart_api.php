<?php
define('SECURE_ACCESS', true);

try {
    require_once "../securite/config.php";
    Logger::info('CLEAR_CART_API', 'Configuration chargée avec succès');
} catch (Exception $e) {
    Logger::error('CLEAR_CART_API', 'Erreur configuration critique', ['error' => $e->getMessage()]);
    echo json_encode(['success' => false, 'message' => 'Erreur configuration']);
    exit;
}

header('Content-Type: application/json');

// Vérification AJAX
if (!isset($_SERVER['HTTP_X_REQUESTED_WITH']) || 
    strtolower($_SERVER['HTTP_X_REQUESTED_WITH']) !== 'xmlhttprequest') {
    Logger::warning('CLEAR_CART_API', 'Requête non AJAX rejetée', [
        'headers' => $_SERVER['HTTP_X_REQUESTED_WITH'] ?? 'ABSENT',
        'ip' => $_SERVER['REMOTE_ADDR'] ?? 'unknown'
    ]);
    echo json_encode(['success' => false, 'message' => 'Requête non autorisée']);
    exit;
}

// Vérification méthode POST
if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    Logger::warning('CLEAR_CART_API', 'Méthode HTTP incorrecte', [
        'method' => $_SERVER['REQUEST_METHOD'],
        'ip' => $_SERVER['REMOTE_ADDR'] ?? 'unknown'
    ]);
    echo json_encode(['success' => false, 'message' => 'Méthode non autorisée']);
    exit;
}

Logger::debug('CLEAR_CART_API', 'Requête AJAX POST validée');

try {
    $secureDb = SecureDatabase::getInstance();
    Logger::debug('CLEAR_CART_API', 'Instance SecureDatabase récupérée');
    
    // Validation sécurité
    if (!$secureDb->validateApiRequest('api_update', true)) {
        Logger::error('CLEAR_CART_API', 'Échec validation API request');
        throw new Exception('Validation sécurité échouée');
    }
    
    Logger::debug('CLEAR_CART_API', 'Validation API réussie');
    
    // Vérification token panier avant modification majeure
    $cartToken = $_COOKIE['cart_token'] ?? null;
    $cartId = $_SESSION['cart_id'] ?? null;
    
    if ($cartToken && $cartId) {
        if (!$secureDb->verifyCartToken($cartToken, $cartId, session_id())) {
            Logger::warning('CLEAR_CART_API', 'Token panier invalide pour vidage', [
                'cart_id' => $cartId,
                'ip' => $_SERVER['REMOTE_ADDR'] ?? 'unknown'
            ]);
            
            Logger::security('CLEAR_CART_API', "Tentative vidage panier avec token invalide", [
                'api' => 'clear_cart',
                'cart_id' => $cartId,
                'ip' => $_SERVER['REMOTE_ADDR'] ?? 'unknown'
            ]);
            
            // Pour le vidage complet, être très strict
            throw new Exception('Token de panier invalide - Veuillez recharger la page');
        } else {
            Logger::debug('CLEAR_CART_API', 'Token panier validé pour vidage');
        }
    }
    
    // Rate limiting spécifique au vidage (action destructive)
    if (!$secureDb->cartRateLimiter('clear')) {
        Logger::warning('CLEAR_CART_API', 'Rate limit dépassé pour vidage panier', [
            'ip' => $_SERVER['REMOTE_ADDR'] ?? 'unknown'
        ]);
        throw new Exception('Trop de demandes de vidage, veuillez patienter');
    }
    
    Logger::debug('CLEAR_CART_API', 'Rate limiting vidage panier validé');
    
    // Initialiser panier et récupérer état avant vidage
    $cart = new Cart();
    Logger::debug('CLEAR_CART_API', 'Panier initialisé');
    
    // Récupérer informations avant vidage pour logs
    $itemCountBefore = $cart->getItemCount();
    $totalBefore = $cart->getTotal();
    $discountInfoBefore = $cart->getDiscountInfo();
    
    Logger::info('CLEAR_CART_API', 'État panier avant vidage', [
        'items_count_before' => $itemCountBefore,
        'total_before' => $totalBefore,
        'had_discount' => $discountInfoBefore ? $discountInfoBefore['code'] : null
    ]);
    
    // Vider le panier
    Logger::info('CLEAR_CART_API', 'Début vidage panier');
    
    $result = $cart->clear();
    
    if ($result === true) {
        Logger::info('CLEAR_CART_API', 'Panier vidé avec succès', [
            'items_removed' => $itemCountBefore,
            'total_cleared' => $totalBefore,
            'discount_removed' => $discountInfoBefore ? $discountInfoBefore['code'] : null
        ]);
        
        // Générer trigger de synchronisation
        $_SESSION['cart_sync_trigger'] = [
            'action' => 'cart_cleared',
            'product_id' => 0,
            'items_removed' => $itemCountBefore,
            'total_cleared' => $totalBefore,
            'timestamp' => time()
        ];
        
        Logger::debug('CLEAR_CART_API', 'Trigger synchronisation généré');
        
        // Log de succès détaillé
        Logger::info('CLEAR_CART_API', 'Vidage panier réussi - détails complets', [
            'items_count_before' => $itemCountBefore,
            'total_before' => $totalBefore,
            'discount_before' => $discountInfoBefore ? $discountInfoBefore['code'] : 'none',
            'items_count_after' => $cart->getItemCount(),
            'total_after' => $cart->getTotal(),
            'ip' => $_SERVER['REMOTE_ADDR'] ?? 'unknown',
            'user_agent' => $_SERVER['HTTP_USER_AGENT'] ?? 'unknown'
        ]);
        
        $response = [
            'success' => true,
            'message' => 'Panier vidé avec succès',
            'data' => [
                'items_removed' => $itemCountBefore,
                'total_cleared' => $totalBefore,
                'cart_total' => 0,
                'cart_count' => 0
            ]
        ];
        
        Logger::info('CLEAR_CART_API', 'Réponse API préparée avec succès', [
            'response_data' => $response['data']
        ]);
        
        echo json_encode($response);
        
    } else {
        Logger::error('CLEAR_CART_API', 'Échec vidage panier', [
            'error_result' => $result
        ]);
        throw new Exception($result ?: 'Erreur lors du vidage du panier');
    }
    
} catch (Exception $e) {
    Logger::error('CLEAR_CART_API', 'Erreur critique dans API', [
        'error_message' => $e->getMessage(),
        'error_file' => $e->getFile(),
        'error_line' => $e->getLine(),
        'post_data' => $_POST,
        'stack_trace' => $e->getTraceAsString()
    ]);
    
    // Déterminer le type d'erreur
    $errorMessage = $e->getMessage();
    $errorCode = 'clear_error';
    
    if (strpos($errorMessage, 'token') !== false) {
        $errorCode = 'invalid_token';
    } elseif (strpos($errorMessage, 'demandes') !== false) {
        $errorCode = 'rate_limit_exceeded';
    } elseif (strpos($errorMessage, 'Validation') !== false) {
        $errorCode = 'security_validation_failed';
    }
    
    Logger::debug('CLEAR_CART_API', 'Code erreur déterminé', [
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