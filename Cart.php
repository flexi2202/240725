<?php
//Cart.php


// Vérification des dépendances de sécurité
if (!defined('SECURE_ACCESS')) {
    Logger::critical('CART', "Accès direct au fichier Cart.php détecté");
    exit('Accès direct au fichier interdit');
}

class Cart {
    // ================================================================================================
    // PROPRIÉTÉS DE CLASSE SIMPLIFIÉES (SANS CACHE)
    // ================================================================================================
    
    /**
     * Articles du panier
     * @var array
     */
    private $items = [];
    
    /**
     * Signature HMAC du panier pour l'intégrité
     * @var string
     */
    private $signature = '';
    
    /**
     * Horodatage de dernière modification
     * @var int
     */
    private $lastModified = 0;
    
    /**
     * Instance de la base de données
     * @var Database
     */
    private $db;
    
    /**
     * ID unique du panier
     * @var string
     */
    private $cartId;
    
    /**
     * Identifiant du client associé au panier (si connecté)
     * @var int|null
     */
    private $clientId = null;
    
    /**
     * Flag simple d'intégrité
     * @var bool
     */
    private $integrityVerified = false;
    
    /**
     * Indique si le panier a été sauvegardé en base de données
     * @var bool
     */
    private $savedToDatabase = false;
    
    /**
     * Indique s'il y a des changements non sauvegardés
     * @var bool
     */
    private $hasUnsavedChanges = false;

    // ❌ SUPPRIMÉ : Cache produits statique (productCache)
    // ❌ SUPPRIMÉ : Rate limiters statiques (rateLimiters) 
    // ❌ SUPPRIMÉ : Timestamp cleanup cache (lastCacheCleanup)

    // ================================================================================================
    // CONSTRUCTEUR SIMPLIFIÉ
    // ================================================================================================

    /**
     * ✅ CONSTRUCTEUR SIMPLIFIÉ - Sans initialisation des caches
     */
    public function __construct() {
        Logger::info('CART', "Initialisation du panier simplifié (sans cache)");
        
        // Instance DB
        $this->db = SecureDatabase::getInstance();
        
        // Client connecté ?
        if (isset($_SESSION['user_id'])) {
            $this->clientId = (int)$_SESSION['user_id'];
        }
        
        // ID panier
        $this->initializeCartId();
        
        // Initialiser et charger
        $this->initCart();
        $this->loadCart();
    }

    /**
     * ✅ CONSERVÉ - Initialisation ID panier
     */
    private function initializeCartId() {
        // 1. Vérifier cookie token en PRIORITÉ avec vérification sécurité
        $cookieToken = $_COOKIE['cart_token'] ?? null;
        
        if ($cookieToken && $this->isValidToken($cookieToken)) {
            $existingCart = $this->getCartByToken($cookieToken);
            
            if ($existingCart) {
                $this->cartId = $existingCart['cart_id'];
                $_SESSION['cart_id'] = $this->cartId;
                
                // Mettre à jour la session courante
                $this->updateCartSession($this->cartId, session_id());
                
                Logger::info('CART', "Panier récupéré via cookie token sécurisé", [
                    'cart_id' => $this->cartId
                ]);
                return;
            } else {
                Logger::warning('CART', "Token cookie invalide, suppression");
                $this->clearCartCookie();
            }
        }
        
        // 2. Session (comportement normal)
        if (isset($_SESSION['cart_id']) && !empty($_SESSION['cart_id'])) {
            $this->cartId = $_SESSION['cart_id'];
            
            if (!$this->validateExistingCart($this->cartId)) {
                Logger::warning('CART', "Panier session invalide, création nouveau panier");
                $this->createNewCart();
            }
        } else {
            // 3. Créer nouveau panier
            $this->createNewCart();
        }
    }

    /**
     * ✅ CONSERVÉ - Valide l'existence d'un panier
     */
    private function validateExistingCart($cartId) {
        if (empty($cartId)) {
            return false;
        }
        
        try {
            $exists = $this->db->queryValue(
                "SELECT COUNT(*) FROM carts WHERE cart_id = ? AND status IN ('active', 'abandoned')",
                [$cartId]
            );
            
            if ($exists > 0) {
                return true;
            }
            
            if (isset($_SESSION['cart']) && !empty($_SESSION['cart'])) {
                Logger::info('CART', "Panier trouvé en session mais pas en DB - normal pour nouveau panier", [
                    'cart_id' => $cartId
                ]);
                return true;
            }
            
            Logger::debug('CART', "Panier non trouvé en DB ni en session", ['cart_id' => $cartId]);
            return false;
            
        } catch (Exception $e) {
            Logger::error('CART', "Erreur validation panier existant: " . $e->getMessage());
            return false;
        }
    }

    /**
     * ✅ CONSERVÉ - Crée un nouveau panier
     */
    private function createNewCart() {
        $this->cartId = $this->generateCartId();
        $_SESSION['cart_id'] = $this->cartId;
        
        Logger::info('CART', "Nouveau panier créé", [
            'cart_id' => $this->cartId
        ]);
    }

    /**
     * ✅ CONSERVÉ - Supprime le cookie de panier
     */
    private function clearCartCookie() {
        $cookieDomain = $_SERVER['HTTP_HOST'];
        if (strpos($cookieDomain, ':') !== false) {
            $cookieDomain = explode(':', $cookieDomain)[0];
        }
        
        setcookie('cart_token', '', [
            'expires' => time() - 3600,
            'path' => '/',
            'domain' => $cookieDomain,
            'secure' => (defined('ENVIRONMENT') && ENVIRONMENT === 'production'),
            'httponly' => true,
            'samesite' => 'Lax'
        ]);
        
        Logger::debug('CART', "Cookie panier supprimé");
    }

    /**
     * ✅ CONSERVÉ - Génération d'ID sécurisée interne
     */
    private function generateCartId() {
        try {
            return bin2hex(random_bytes(16)); // 32 chars hex
        } catch (Exception $e) {
            Logger::error('CART', "Erreur génération ID: " . $e->getMessage());
            throw $e;
        }
    }

    /**
     * ✅ CONSERVÉ - Met à jour la session_id d'un panier existant
     */
    private function updateCartSession($cartId, $newSessionId) {
        try {
            $this->db->query(
                "UPDATE carts SET session_id = ?, updated_at = NOW() WHERE cart_id = ?",
                [$newSessionId, $cartId]
            );
            Logger::debug('CART', "Session ID mise à jour pour panier récupéré", [
                'cart_id' => $cartId
            ]);
        } catch (Exception $e) {
            Logger::error('CART', "Erreur mise à jour session panier: " . $e->getMessage());
        }
    }

    /**
     * ✅ CONSERVÉ - Validation token avec format strict
     */
    private function isValidToken($token) {
        if (empty($token) || !is_string($token)) {
            return false;
        }
        
        // Validation format : exactement 64 caractères hexadécimaux
        if (!ctype_xdigit($token) || strlen($token) !== 64) {
            Logger::warning('CART', "Format token invalide", [
                'length' => strlen($token),
                'is_hex' => ctype_xdigit($token)
            ]);
            return false;
        }
        
        return true;
    }

    /**
     * ✅ CONSERVÉ - Récupère un panier par son token avec vérification
     */
    private function getCartByToken($token) {
        try {
            // Validation préliminaire du token
            if (empty($token) || !ctype_alnum($token) || strlen($token) !== 64) {
                Logger::warning('CART', "Format de token invalide", [
                    'token_length' => strlen($token)
                ]);
                return false;
            }

            // Récupération basique des données panier
            $cartData = $this->db->queryRow(
                "SELECT cart_id, session_id FROM carts WHERE cart_token = ? AND status = 'active'",
                [$token]
            );

            if (!$cartData) {
                Logger::debug('CART', "Aucun panier trouvé pour ce token");
                return false;
            }

            // Vérification de sécurité du token
            if (!SecureDatabase::getInstance()->verifyCartToken($token, $cartData['cart_id'], session_id())) {
                Logger::security('CART', "Échec vérification sécurité token panier", [
                    'cart_id' => $cartData['cart_id']
                ]);
                
                // Marquer le panier comme compromis
                $this->markCartAsCompromised($cartData['cart_id']);
                return false;
            }

            Logger::info('CART', "Panier récupéré et vérifié par token", [
                'cart_id' => $cartData['cart_id']
            ]);

            return $cartData;

        } catch (Exception $e) {
            Logger::error('CART', "Erreur récupération panier par token: " . $e->getMessage());
            return false;
        }
    }

    /**
     * ✅ CONSERVÉ - Marque un panier comme compromis
     */
    private function markCartAsCompromised($cartId) {
        try {
            $this->db->query(
                "UPDATE carts SET status = 'compromised', updated_at = NOW() WHERE cart_id = ?",
                [$cartId]
            );
            
            Logger::security('CART', "Panier marqué comme compromis", [
                'cart_id' => $cartId,
                'ip' => $_SERVER['REMOTE_ADDR'] ?? 'unknown'
            ]);
            
        } catch (Exception $e) {
            Logger::error('CART', "Erreur marquage panier compromis: " . $e->getMessage());
        }
    }

    // ================================================================================================
    // MÉTHODES PRODUITS SIMPLIFIÉES (SANS CACHE)
    // ================================================================================================

    /**
     * ✅ SIMPLIFIÉ - Récupère les infos produit DIRECTEMENT depuis la DB (sans cache)
     * 
     * AVANT : Cache local de 5 minutes + nettoyage automatique + gestion mémoire
     * APRÈS : Accès direct DB (optimal pour 100 produits + 5 visiteurs)
     */
    private function getProductInfo($productId, $field = null) {
        try {
            // ✅ ACCÈS DIRECT BASE DE DONNÉES (pas de cache)
            $product = $this->db->queryRow(
                "SELECT id, price, stock, weight, reference, image_url, category, tva_rate, 
                        largeur, longueur, hauteur, name 
                 FROM products 
                 WHERE id = ?",
                [$productId]
            );
            
            if ($product) {
                $product = $this->normalizeProductData($product);
                
                if ($field !== null) {
                    return $product[$field] ?? null;
                }
                return $product;
                
            } else {
                Logger::debug('CART', "Produit non trouvé", [
                    'product_id' => $productId
                ]);
                
                return $field !== null ? null : false;
            }
            
        } catch (Exception $e) {
            Logger::error('CART', "Erreur récupération produit: " . $e->getMessage(), [
                'product_id' => $productId,
                'exception_type' => get_class($e)
            ]);
            return $field !== null ? null : false;
        }
    }

    /**
     * ✅ CONSERVÉ - Normalisation des données produit
     */
    private function normalizeProductData($product) {
        return [
            'id' => (int)$product['id'],
            'price' => (float)$product['price'],
            'stock' => (int)$product['stock'],
            'weight' => (int)$product['weight'],
            'tva_rate' => (int)$product['tva_rate'],
            'largeur' => (int)$product['largeur'],
            'longueur' => (int)$product['longueur'],
            'hauteur' => (int)$product['hauteur'],
            'reference' => $product['reference'] ?? '',
            'image_url' => $product['image_url'] ?? '',
            'category' => $product['category'] ?? '',
            'name' => $product['name'] ?? "Produit #{$product['id']}"
        ];
    }

    /**
     * ✅ SIMPLIFIÉ - Prix actuel (accès direct)
     */
    private function getActualProductPrice($productId) {
        return $this->getProductInfo($productId, 'price') ?: false;
    }

    /**
     * ✅ SIMPLIFIÉ - Stock actuel (accès direct)
     */
    private function getProductStock($productId) {
        return $this->getProductInfo($productId, 'stock') ?: 0;
    }

    // ================================================================================================
    // CACHE SUPPRIMÉ - MÉTHODES NETTOYAGE SIMPLIFIÉES
    // ================================================================================================

    /**
     * ✅ CACHE CLEANUP SÉCURISÉ - Version simplifiée sans cache local
     */
    public static function clearCache() {
  // Plus de cache local à nettoyer dans cette version
        Logger::debug('CART', "Cache cleanup simplifié - Pas de cache local à nettoyer");
    }

    // ❌ SUPPRIMÉ : getCachedProduct()
    // ❌ SUPPRIMÉ : setCachedProduct() 
    // ❌ SUPPRIMÉ : cleanupProductCache()
    // ❌ SUPPRIMÉ : Gestion cache mémoire
    // ❌ SUPPRIMÉ : Rate limiters statiques

    // ================================================================================================
    // INITIALISATION ET CHARGEMENT DU PANIER (CONSERVÉ)
    // ================================================================================================

    /**
     * ✅ CONSERVÉ - Initialise le panier depuis la session avec vérifications d'intégrité
     */
    private function initCart() {
        if (session_status() === PHP_SESSION_NONE) {
            session_start();
        }
        
        Logger::debug('CART', "Chargement du panier depuis la session");
        
        if (isset($_SESSION['cart'], $_SESSION['cart_signature'], $_SESSION['cart_last_modified'])) {
            if ($this->loadFromSession()) {
                if ($this->isCartExpired()) {
                    $this->resetCart('Panier expiré');
                } else {
                    if (empty($this->items)) {
                        Logger::debug('CART', "Panier session vide, tentative de chargement depuis DB");
                        $this->loadFromDatabase();
                    }
                    $this->scheduleIntegrityCheck();
                }
            } else {
                $this->resetCart('Intégrité du panier compromise');
            }
        } else {
            Logger::debug('CART', "Aucun panier trouvé, création d'un nouveau panier");
            $this->resetCart('Nouveau panier');
        }
    }

    /**
     * ✅ CONSERVÉ - Charge le panier depuis la session
     */
    private function loadFromSession() {
        try {
            $secureDb = SecureDatabase::getInstance();
            $decryptedCart = $secureDb->decrypt($_SESSION['cart']);
            if ($decryptedCart === null) {
                Logger::warning('CART', "Échec du déchiffrement du panier");
                return false;
            }
            
            if (!$secureDb->verifyHmac($decryptedCart, $_SESSION['cart_signature'])) {
                Logger::security('CART', "Intégrité HMAC du panier compromise");
                return false;
            }
            
            $this->items = $decryptedCart;
            $this->signature = $_SESSION['cart_signature'];
            $this->lastModified = $_SESSION['cart_last_modified'];
            
            Logger::debug('CART', "Panier chargé depuis la session avec succès", [
                'items_count' => count($this->items)
            ]);
            
            return true;
        } catch (Exception $e) {
            Logger::error('CART', "Erreur lors du chargement depuis la session: " . $e->getMessage());
            return false;
        }
    }

    /**
     * ✅ CONSERVÉ - Vérifie si le panier a expiré
     */
    private function isCartExpired() {
        $cartLifetime = defined('CART_LIFETIME') ? CART_LIFETIME : 86400;
        $age = time() - $this->lastModified;
        
        if ($age > $cartLifetime) {
            Logger::info('CART', "Panier expiré", [
                'age_hours' => round($age / 3600, 1),
                'lifetime_hours' => round($cartLifetime / 3600, 1)
            ]);
            return true;
        }
        
        return false;
    }

    /**
     * ✅ CONSERVÉ - Remet à zéro le panier
     */
    private function resetCart($reason = '') {
        $this->items = [];
        $this->signature = '';
        $this->lastModified = time();
        $this->integrityVerified = false;
        
        if ($reason) {
            Logger::info('CART', "Panier réinitialisé", ['reason' => $reason]);
        }
        
        $this->saveCart();
    }

    /**
     * ✅ CONSERVÉ - Programmation d'intégrité simple
     */
    private function scheduleIntegrityCheck() {
        $this->integrityVerified = false;
    }

    /**
     * ✅ CONSERVÉ - Vérification si nécessaire
     */
    private function ensureIntegrityChecked() {
        if (!$this->integrityVerified) {
            $this->verifyCartIntegrity();
        }
    }

    /**
     * ✅ MODIFIÉ - Vérification d'intégrité SANS cache (accès direct DB)
     */
    private function verifyCartIntegrity() {
        if ($this->integrityVerified) {
            return;
        }
        
        $secureDb = SecureDatabase::getInstance();
        
        $itemsToRemove = [];
        $modified = false;
        
        foreach ($this->items as $id => $item) {
            if (!$secureDb->validateProductId($id, false)) {
                $itemsToRemove[] = $id;
                $modified = true;
                continue;
            }
            
            // ✅ ACCÈS DIRECT DB (sans cache)
            $productInfo = $this->getProductInfo($id);
            if (!$productInfo) {
                $itemsToRemove[] = $id;
                $modified = true;
                continue;
            }
            
            // Mettre à jour prix (tolérance 1%)
            $actualPrice = (float)$productInfo['price'];
            $priceDiff = abs($actualPrice - $item['price']);
            if ($item['price'] > 0 && ($priceDiff / $item['price']) > 0.01) {
                $this->items[$id]['price'] = $actualPrice;
                $this->items[$id]['subtotal'] = $actualPrice * $item['quantity'];
                $modified = true;
            }
            
            // Ajuster stock
            $stock = (int)$productInfo['stock'];
            if ($stock <= 0) {
                $itemsToRemove[] = $id;
                $modified = true;
            } elseif ($item['quantity'] > $stock) {
                $this->items[$id]['quantity'] = $stock;
                $this->items[$id]['subtotal'] = $this->items[$id]['price'] * $stock;
                $modified = true;
            }
        }
        
        // Supprimer les articles invalides
        foreach ($itemsToRemove as $id) {
            unset($this->items[$id]);
        }
        
        if ($modified) {
            $this->saveCart();
            Logger::info('CART', "Intégrité vérifiée - modifications appliquées", [
                'items_removed' => count($itemsToRemove),
                'total_items' => count($this->items)
            ]);
        }
        
        $this->integrityVerified = true;
    }

    /**
     * ✅ CONSERVÉ - Charge le panier approprié selon le contexte
     */
 private function loadCart() {
    // Pour client connecté : charger son panier SANS fusion automatique
    if ($this->clientId) {
        $this->loadClientCartWithoutFusion();
        
    } else {
        $this->loadAnonymousCart();
    }
}







/**
 * Charge le panier client SANS déclencher de fusion automatique
 */
private function loadClientCartWithoutFusion() {
    try {
        // Récupérer le panier actif du client
        $clientCart = $this->db->queryRow(
            "SELECT cart_id FROM carts 
             WHERE id_client = ? AND status = 'active' 
             ORDER BY updated_at DESC LIMIT 1",
            [$this->clientId]
        );
        
        if ($clientCart) {
            $dbCartId = $clientCart['cart_id'];
            
            // Adopter ce panier SANS fusion
            $this->cartId = $dbCartId;
            $_SESSION['cart_id'] = $dbCartId;
            
            // Charger les items
            $this->items = $this->loadCartItems($dbCartId);
            $this->saveCart();
            
            Logger::info('CART', "Panier client chargé sans fusion", [
                'cart_id' => $dbCartId,
                'items_count' => count($this->items)
            ]);
        }
        
        return true;
    } catch (Exception $e) {
        Logger::error('CART', "Erreur chargement panier client: " . $e->getMessage());
        return false;
    }
}

    /**
     * ✅ CONSERVÉ - Charge le panier depuis la base de données
     */
    private function loadFromDatabase() {
        if (empty($this->items)) {
            $this->items = $this->loadCartItems($this->cartId);
            $this->saveCart();
            Logger::debug('CART', "Panier chargé depuis DB", [
                'items_count' => count($this->items)
            ]);
        }
    }

    /**
     * ✅ CONSERVÉ - Charge un panier client depuis la base de données
     */
   /* private function loadClientCart() {
   try {
            $clientCart = $this->db->queryRow(
                "SELECT cart_id FROM carts 
                 WHERE id_client = ? AND status = 'active' 
                 ORDER BY updated_at DESC LIMIT 1",
                [$this->clientId]
            );
            
            if (!$clientCart) {
                Logger::debug('CART', "Aucun panier client trouvé en DB");
                return false;
            }
            
            $dbCartId = $clientCart['cart_id'];
            $sessionHasItems = !empty($this->items);
            $cartChanged = ($dbCartId !== $this->cartId);
            
            if ($cartChanged) {
                if ($sessionHasItems) {
                    $this->mergeWithDatabaseCart($dbCartId);
                } else {
                    $this->switchToCart($dbCartId);
                }
            } else {
                $this->syncWithDatabase();
            }
            
            return true;
        } catch (Exception $e) {
            Logger::error('CART', "Erreur chargement panier client: " . $e->getMessage());
            return false;
        }
    }*/

    /**
     * ✅ CONSERVÉ - Fusionne le panier session avec un panier de base de données
     */
    private function mergeWithDatabaseCart($dbCartId) {
        Logger::info('CART', "FUSION DB↔SESSION DÉCLENCHÉE", [
            'current_cart' => $this->cartId,
            'db_cart' => $dbCartId,
            'session_items' => count($this->items)
        ]);
        
        $oldCartId = $this->cartId;
        $this->cartId = $dbCartId;
        $_SESSION['cart_id'] = $dbCartId;
        
        // Charger les articles du panier DB
        $dbItems = $this->loadCartItems($dbCartId);
        
        // Configuration de la stratégie de fusion
        $mergeStrategy = defined('CART_MERGE_STRATEGY') ? CART_MERGE_STRATEGY : 'add';
        
        // Sauvegarder le code promo de la session
        $sessionDiscount = isset($_SESSION['discount_code']) ? $_SESSION['discount_code'] : null;
        
        // Fusionner avec les articles en session
        foreach ($dbItems as $productId => $dbItem) {
            if (isset($this->items[$productId])) {
                try {
                    $this->items[$productId] = $this->mergeCartItems(
                        $this->items[$productId], 
                        $dbItem, 
                        $mergeStrategy
                    );
                } catch (Exception $e) {
                    Logger::error('CART', "Erreur fusion article: " . $e->getMessage(), [
                        'product_id' => $productId
                    ]);
                    continue;
                }
            } else {
                $this->items[$productId] = $dbItem;
                $this->items[$productId]['merged_from'] = 'database';
                $this->items[$productId]['merged_at'] = time();
            }
        }
        
        // Vérifier le code promo après fusion
        if ($sessionDiscount) {
            $this->checkDiscountMinimumAfterUpdate();
        }
        
        $this->save();
        
        Logger::info('CART', "Paniers fusionnés avec base de données", [
            'old_cart' => $oldCartId,
            'new_cart' => $dbCartId,
            'total_items' => count($this->items),
            'merge_strategy' => $mergeStrategy
        ]);
    }

    /**
     * ✅ CONSERVÉ - Charge un panier anonyme depuis la base de données
     */
    private function loadAnonymousCart() {
        try {
            $cartExists = $this->db->queryRow(
                "SELECT cart_id FROM carts 
                 WHERE cart_id = ? AND session_id = ? AND status = 'active'",
                [$this->cartId, session_id()]
            );
            
            if (!$cartExists) {
                return false;
            }
            
            if (empty($this->items)) {
                $this->items = $this->loadCartItems($this->cartId);
                $this->saveCart();
                Logger::debug('CART', "Panier anonyme chargé depuis DB", [
                    'items_count' => count($this->items)
                ]);
            } else {
                $this->syncWithDatabase();
            }
            
            return true;
        } catch (Exception $e) {
            Logger::error('CART', "Erreur chargement panier anonyme: " . $e->getMessage());
            return false;
        }
    }

    /**
     * ✅ CONSERVÉ - Bascule vers un autre panier
     */
    private function switchToCart($newCartId) {
        Logger::info('CART', "BASCULEMENT VERS AUTRE PANIER", [
            'old_cart' => $this->cartId,
            'new_cart' => $newCartId
        ]);
        
        $this->cartId = $newCartId;
        $_SESSION['cart_id'] = $newCartId;
        $this->items = $this->loadCartItems($newCartId);
        $this->saveCart();
        
        Logger::debug('CART', "Basculé vers le panier", [
            'cart_id' => $newCartId,
            'items_count' => count($this->items)
        ]);
    }

    /**
     * ✅ CONSERVÉ - Synchronise le panier avec la base de données
     */
    private function syncWithDatabase() {
        try {
            $dbItemCount = $this->db->queryValue(
                "SELECT COUNT(*) FROM cart_items WHERE cart_id = ?",
                [$this->cartId]
            );
            
            $sessionItemCount = count($this->items);
            
            if ($dbItemCount != $sessionItemCount) {
                if ($sessionItemCount > 0) {
                    $this->saveToDatabase();
                    Logger::debug('CART', "DB mise à jour depuis la session", [
                        'session_items' => $sessionItemCount,
                        'db_items' => $dbItemCount
                    ]);
                } else {
                    $this->items = $this->loadCartItems($this->cartId);
                    $this->saveCart();
                    Logger::debug('CART', "Session mise à jour depuis la DB", [
                        'loaded_items' => count($this->items)
                    ]);
                }
            }
        } catch (Exception $e) {
            Logger::error('CART', "Erreur synchronisation: " . $e->getMessage());
        }
    }

    /**
     * ✅ CONSERVÉ - Sauvegarde session avec crypto
     */
    private function saveCart() {
        Logger::debug('CART', "Sauvegarde du panier en session");
        
        // Mettre à jour l'horodatage
        $this->lastModified = time();
        
        // Générer signature HMAC
        $secureDb = SecureDatabase::getInstance();
        $this->signature = $secureDb->generateHmac($this->items);
        
        // Chiffrement des données
        $encryptedCart = $secureDb->encrypt($this->items);
        if ($encryptedCart === false) {
            Logger::error('CART', "Échec du chiffrement du panier");
            return false;
        }
        
        // Stocker en session
        $_SESSION['cart'] = $encryptedCart;
        $_SESSION['cart_signature'] = $this->signature;
        $_SESSION['cart_last_modified'] = $this->lastModified;
        
        return true;
    }

    /**
     * ✅ CONSERVÉ - Sauvegarde unifiée (session + base de données)
     */
    private function save() {
        $sessionSaved = $this->saveCart();
        $databaseSaved = $this->saveToDatabase();
        
        if (!$sessionSaved) {
            Logger::warning('CART', "Échec sauvegarde session");
        }
        if (!$databaseSaved) {
            Logger::warning('CART', "Échec sauvegarde base de données");
        }
        
        return $sessionSaved && $databaseSaved;
    }

    /**
     * ✅ CONSERVÉ - Charge les articles d'un panier depuis la base de données
     */
    private function loadCartItems($cartId) {
        Logger::debug('CART', "Chargement des articles du panier depuis DB", ['cart_id' => $cartId]);
        
        $items = [];
        
        try {
            $cartItems = $this->db->queryAll(
                "SELECT ci.product_id, ci.quantity, ci.price_at_addition, 
                        p.name, p.weight, p.reference, p.image_url, p.category, 
                        p.tva_rate, p.largeur, p.longueur, p.hauteur
                 FROM cart_items ci
                 JOIN products p ON ci.product_id = p.id
                 WHERE ci.cart_id = ?",
                [$cartId]
            );
            
            foreach ($cartItems as $item) {
                $productId = $item['product_id'];
                $items[$productId] = [
                    'id' => $productId,
                    'quantity' => (int)$item['quantity'],
                    'price' => (float)$item['price_at_addition'],
                    'subtotal' => (float)$item['price_at_addition'] * (int)$item['quantity'],
                    'weight' => (int)$item['weight'],
                    'reference' => $item['reference'],
                    'image_url' => $item['image_url'],
                    'category' => $item['category'],
                    'tva_rate' => (int)$item['tva_rate'],
                    'largeur' => (int)$item['largeur'],
                    'longueur' => (int)$item['longueur'],
                    'hauteur' => (int)$item['hauteur'],
                    'name' => $item['name'],
                    'added_at' => time() // Approximation
                ];
            }
            
            Logger::debug('CART', "Articles chargés depuis DB", ['items_count' => count($items)]);
        } catch (Exception $e) {
            Logger::error('CART', "Erreur chargement articles DB: " . $e->getMessage());
        }
        
        return $items;
    }

    // ================================================================================================
    // GESTION DES CODES PROMO - CONSERVÉE INTÉGRALEMENT
    // ================================================================================================


// ✅ DÉPLACER CES 2 MÉTHODES AVANT applyDiscount()






























    /**
     * ✅ CONSERVÉ - Applique un code promo au panier
     */
public function applyDiscount($discountCode) {
    $secureDb = SecureDatabase::getInstance();
    
    if (!is_string($discountCode) || empty($discountCode)) {
        return $secureDb->handleSecureError(
            'CART',
            'invalid_discount_code_format',
            'Code promo invalide',
            ['provided_code' => $discountCode, 'type' => gettype($discountCode)],
            'warning'
        );
    }
    
    if (!$secureDb->cartRateLimiter('discount_apply')) {
        return $secureDb->handleSecureError(
            'CART',
            'discount_rate_limit',
            'Trop de tentatives, veuillez patienter',
            ['action' => 'discount_apply'],
            'security'
        );
    }
    
    // Vérifier qu'aucun code n'est déjà appliqué
    if (isset($_SESSION['discount_code'])) {
        return $secureDb->handleSecureError(
            'CART',
            'discount_already_applied',
            'Un code promo est déjà appliqué',
            ['existing_code' => $_SESSION['discount_code']['code'] ?? 'unknown'],
            'warning'
        );
    }
    
    // Vérifier que le panier n'est pas vide
    if (empty($this->items)) {
        return $secureDb->handleSecureError(
            'CART',
            'empty_cart_discount',
            'Votre panier est vide',
            ['items_count' => count($this->items)],
            'warning'
        );
    }
    
    try {
        // Récupérer les informations du code promo depuis la base de données
        $discountData = $this->getDiscountCodeData($discountCode);
        
        if (!$discountData) {
            return $secureDb->handleSecureError(
                'CART',
                'discount_code_not_found',
                'Code promo invalide ou inactif',
                ['discount_code' => $discountCode],
                'warning'
            );
        }
        
        // Valider le code promo
        $validation = $this->validateDiscountCode($discountData);
        if ($validation !== true) {
            return $validation;
        }
        
        // Calculer le montant de la réduction - MÉTHODE CORRIGÉE
        $subtotal = $this->getSubtotalBeforeDiscount();
        $discountAmount = $this->calculateDiscountAmountFixed($discountData, $subtotal);
        
        if ($discountAmount <= 0.01) {
            return $secureDb->handleSecureError(
                'CART',
                'discount_no_reduction',
                'Ce code promo n\'apporte aucune réduction',
                [
                    'discount_code' => $discountCode,
                    'discount_amount' => $discountAmount,
                    'subtotal' => $subtotal
                ],
                'warning'
            );
        }
        
        // Stocker le code promo en session
        $_SESSION['discount_code'] = [
            'id' => $discountData['id'],
            'code' => $discountData['code'],
            'type' => $discountData['type'],
            'value' => $discountData['value'],
            'amount' => round($discountAmount, 2),
            'applied_at' => time(),
            'min_order_value' => $discountData['min_order_value']
        ];
        
        // SUPPRIMÉ: incrementDiscountUsage (méthode manquante)
         $this->incrementDiscountUsage($discountData['id']);
        
        // Sauvegarder le panier
        $this->save();
        
        Logger::info('CART', "Code promo appliqué", [
            'code' => $discountCode,
            'discount_amount' => $discountAmount,
            'subtotal' => $subtotal
        ]);
        
        return true;
        
    } catch (Exception $e) {
        return $secureDb->handleSecureError(
            'CART',
            'discount_apply_exception',
            'Erreur lors de l\'application du code promo',
            [
                'discount_code' => $discountCode,
                'exception' => $e->getMessage(),
                'exception_type' => get_class($e)
            ],
            'error'
        );
    }
}














/**
 * Incrémente le compteur d'usage d'un code promo
 */
private function incrementDiscountUsage($discountId) {
    try {
        $this->db->query(
            "UPDATE discount_codes SET usage_count = usage_count + 1 WHERE id = ?",
            [$discountId]
        );
        
        Logger::info('CART', "Usage code promo incrémenté", [
            'discount_id' => $discountId
        ]);
        
        return true;
    } catch (Exception $e) {
        Logger::error('CART', "Erreur incrémentation usage: " . $e->getMessage());
        return false;
    }
}

/**
 * Décrémente le compteur d'usage d'un code promo (si suppression)
 */
private function decrementDiscountUsage($discountId) {
    try {
        $this->db->query(
            "UPDATE discount_codes SET usage_count = usage_count - 1 WHERE id = ? AND usage_count > 0",
            [$discountId]
        );
        
        Logger::info('CART', "Usage code promo décrémenté", [
            'discount_id' => $discountId
        ]);
        
        return true;
    } catch (Exception $e) {
        Logger::error('CART', "Erreur décrémentation usage: " . $e->getMessage());
        return false;
    }
}



























/**
 * MÉTHODE MANQUANTE AJOUTÉE - Calcule le montant de la réduction
 */
private function calculateDiscountAmountFixed($discountData, $subtotal) {
    switch ($discountData['type']) {
        case 'percent':
            return $subtotal * ($discountData['value'] / 100);
        case 'fixed':
            return min($discountData['value'], $subtotal);
        default:
            return 0;
    }
}
    
    /**
     * ✅ CONSERVÉ - Supprime le code promo appliqué
     */
public function removeDiscount() {
    $secureDb = SecureDatabase::getInstance(); 
    
    if (!isset($_SESSION['discount_code'])) {
        return $secureDb->handleSecureError(
            'CART',
            'no_discount_applied',
            'Aucun code promo n\'est appliqué',
            ['session_has_discount' => false],
            'warning'
        );
    }
        
        try {
            $removedCode = $_SESSION['discount_code']['code'];
            $discountId = $_SESSION['discount_code']['id'];
            
            // Décrémenter le compteur d'usage en base
            $this->decrementDiscountUsage($discountId);
            
            // Supprimer de la session
            unset($_SESSION['discount_code']);
            
            // Sauvegarder le panier
            $this->save();
            
            Logger::info('CART', "Code promo supprimé", [
                'code' => $removedCode
            ]);
            
            return true;
            
        } catch (Exception $e) {
   return $secureDb->handleSecureError(
       'CART',
       'discount_remove_exception',
       'Erreur lors de la suppression du code promo',
       [
           'discount_code' => $removedCode ?? 'unknown',
           'exception' => $e->getMessage(),
           'exception_type' => get_class($e)
       ],
       'error'
   );
}
    }
    
    /**
     * ✅ CONSERVÉ - Récupère les données d'un code promo depuis la base de données
     */
    private function getDiscountCodeData($code) {
        try {
            return $this->db->queryRow(
                "SELECT id, code, type, value, min_order_value, usage_limit, usage_count, 
                        expires_at, active, created_at 
                 FROM discount_codes 
                 WHERE code = ? AND active = 1",
                [$code]
            );
        } catch (Exception $e) {
            Logger::error('CART', "Erreur récupération code promo: " . $e->getMessage());
            return null;
        }
    }
    
    /**
     * ✅ CONSERVÉ - Valide un code promo selon tous les critères
     */
private function validateDiscountCode($discountData) {
   $secureDb = SecureDatabase::getInstance();
   
   // Vérifier si actif
   if ($discountData['active'] != 1) {
       return $secureDb->handleSecureError(
           'CART',
           'discount_code_inactive',
           'Ce code promo n\'est plus actif',
           [
               'discount_code' => $discountData['code'],
               'active_status' => $discountData['active']
           ],
           'warning'
       );
   }
   
   // Vérifier expiration
   if ($discountData['expires_at'] !== null) {
       $expirationDate = strtotime($discountData['expires_at']);
       if ($expirationDate && $expirationDate < time()) {
           return $secureDb->handleSecureError(
               'CART',
               'discount_code_expired',
               'Ce code promo a expiré',
               [
                   'discount_code' => $discountData['code'],
                   'expiration_date' => $discountData['expires_at'],
                   'current_time' => date('Y-m-d H:i:s')
               ],
               'warning'
           );
       }
   }

   // Vérifier limite d'usage
   if ($discountData['usage_limit'] !== null) {
       $usageLimit = (int)$discountData['usage_limit'];
       $usageCount = (int)$discountData['usage_count'];
       
       if ($usageCount >= $usageLimit) {
           return $secureDb->handleSecureError(
               'CART',
               'discount_usage_limit_reached',
               'Ce code promo a atteint sa limite d\'utilisation',
               [
                   'discount_code' => $discountData['code'],
                   'usage_count' => $usageCount,
                   'usage_limit' => $usageLimit
               ],
               'warning'
           );
       }
   }
   
   // Vérifier minimum de commande
   $subtotal = $this->getSubtotalBeforeDiscount();
   $minOrderValue = (float)$discountData['min_order_value'];
   
   if ($minOrderValue > 0 && $subtotal < $minOrderValue) {
       return $secureDb->handleSecureError(
           'CART',
           'discount_minimum_not_met',
           'Minimum de ' . number_format($minOrderValue, 2, ',', ' ') . '€ requis pour ce code promo',
           [
               'discount_code' => $discountData['code'],
               'required_minimum' => $minOrderValue,
               'current_subtotal' => $subtotal,
               'missing_amount' => $minOrderValue - $subtotal
           ],
           'warning'
       );
   }
   
   return true;
}






/**
 * Incrémente le compteur d'usage d'un code promo
 */
/*private function incrementDiscountUsage($discountId) {
try {
        $this->db->query(
            "UPDATE discount_codes SET usage_count = usage_count + 1 WHERE id = ?",
            [$discountId]
        );
        
        Logger::info('CART', "Usage code promo incrémenté", [
            'discount_id' => $discountId
        ]);
        
        return true;
    } catch (Exception $e) {
        Logger::error('CART', "Erreur incrémentation usage: " . $e->getMessage());
        return false;
    }
}*/

/**
 * Décrémente le compteur d'usage d'un code promo (si suppression)
 */
/*private function decrementDiscountUsage($discountId) {
try {
        $this->db->query(
            "UPDATE discount_codes SET usage_count = usage_count - 1 WHERE id = ? AND usage_count > 0",
            [$discountId]
        );
        
        Logger::info('CART', "Usage code promo décrémenté", [
            'discount_id' => $discountId
        ]);
        
        return true;
    } catch (Exception $e) {
        Logger::error('CART', "Erreur décrémentation usage: " . $e->getMessage());
        return false;
    }
}*/















    /**
     * ✅ CONSERVÉ - Calcule le montant de la réduction appliquée
     */
    private function getDiscountAmount($subtotal = null) {
        if (!isset($_SESSION['discount_code'])) {
            return 0;
        }
        
        if ($subtotal === null) {
            $subtotal = $this->getSubtotalBeforeDiscount();
        }
        
        $discount = $_SESSION['discount_code'];
        
        switch ($discount['type']) {
            case 'percent':
                return $subtotal * ($discount['value'] / 100);
            case 'fixed':
                return min($discount['value'], $subtotal);
            default:
                return 0;
        }
    }
    
    
    /**
 * Vérifie si le code promo respecte toujours le minimum après modification du panier
 */
private function checkDiscountMinimumAfterUpdate() {
    if (!isset($_SESSION['discount_code'])) {
        return; // Pas de code promo appliqué
    }
    
    $discountInfo = $_SESSION['discount_code'];
    $currentSubtotal = $this->getSubtotalBeforeDiscount();
    $minOrderValue = (float)($discountInfo['min_order_value'] ?? 0);
    
    if ($minOrderValue > 0 && $currentSubtotal < $minOrderValue) {
        // Le panier ne respecte plus le minimum, supprimer le code promo
        unset($_SESSION['discount_code']);
        
        if (class_exists('Logger')) {
            Logger::info('CART', 'Code promo retiré - minimum non respecté', [
                'code' => $discountInfo['code'],
                'minimum_required' => $minOrderValue,
                'current_subtotal' => $currentSubtotal
            ]);
        }
    }
}
    
    
    
    
    
    
    
    
    
    /**
     * ✅ CONSERVÉ - Obtient les informations sur la réduction appliquée
     */
    public function getDiscountInfo() {
        if (!isset($_SESSION['discount_code'])) {
            return null;
        }
        
        $discount = $_SESSION['discount_code'];
        $subtotalBefore = $this->getSubtotalBeforeDiscount();
        $discountAmount = $this->getDiscountAmount($subtotalBefore);
        
        return [
            'code' => $discount['code'],
            'type' => $discount['type'],
            'value' => $discount['value'],
            'amount' => round($discountAmount, 2),
            'subtotal_before' => round($subtotalBefore, 2),
            'total_after' => round($subtotalBefore - $discountAmount, 2),
            'applied_at' => $discount['applied_at'] ?? time()
        ];
    }
    
    /**
     * ✅ CONSERVÉ - Calcule le sous-total avant application de la réduction
     */
    public function getSubtotalBeforeDiscount() {
        $subtotal = 0;
        foreach ($this->items as $item) {
            $subtotal += $item['subtotal'];
        }
        return round($subtotal, 2);
    }

    /**
     * ✅ CONSERVÉ - Calcule le montant total du panier avec réductions
     */
    public function getTotal($includeTaxes = false) {
        $this->ensureIntegrityChecked();
        
        $subtotal = $this->getSubtotalBeforeDiscount();
        $totalTaxes = 0;
        
        // Calculer les taxes sur le sous-total si demandé
        if ($includeTaxes) {
            foreach ($this->items as $item) {
                if (isset($item['tva_rate'])) {
                    $totalTaxes += ($item['subtotal'] * $item['tva_rate'] / 100);
                }
            }
        }
        
        // Appliquer la réduction
        $discountAmount = $this->getDiscountAmount($subtotal);
        $subtotalAfterDiscount = max(0, $subtotal - $discountAmount);
        
        $total = $includeTaxes ? ($subtotalAfterDiscount + $totalTaxes) : $subtotalAfterDiscount;
        
        return round($total, 2);
    }

    // ================================================================================================
    // GESTION DES ARTICLES PANIER - CONSERVÉE AVEC SIMPLIFICATIONS
    // ================================================================================================

    /**
     * ✅ MODIFIÉ - Ajoute un produit avec validation + vérification codes promo (SANS cache)
     */
public function addItem($productId, $quantity = 1, $price = null) {
    $secureDb = SecureDatabase::getInstance();
    
    // ✅ VALIDATION PRODUIT UNIFIÉE
    $productValidation = $secureDb->validateProductWithError($productId, 'CART');
    if (!$productValidation['valid']) {
        return $productValidation['error'];
    }
    $productId = $productValidation['product_id'];
    
    // ✅ VALIDATION QUANTITÉ UNIFIÉE  
    $quantityValidation = $secureDb->validateQuantityWithError($quantity, 'CART');
    if (!$quantityValidation['valid']) {
        return $quantityValidation['error'];
    }
    $quantity = $quantityValidation['quantity'];
    
    // Rate limiting avec gestion d'erreur unifiée
    if (!$secureDb->cartRateLimiter('add', $productId)) {
        return $secureDb->handleSecureError(
            'CART',
            'rate_limit_exceeded',
            'Trop de demandes, veuillez patienter',
            ['product_id' => $productId, 'action' => 'add'],
            'security'
        );
    }
    
    // Si l'item existe déjà, rediriger vers updateItem
    if (isset($this->items[$productId])) {
        $newQuantity = $this->items[$productId]['quantity'] + $quantity;
        return $this->updateItem($productId, $newQuantity);
    }
    
    // Vérifier limite panier
    $maxItems = defined('MAX_CART_ITEMS') ? MAX_CART_ITEMS : 50;
    if (count($this->items) >= $maxItems) {
        return $secureDb->handleSecureError(
            'CART',
            'cart_limit_exceeded',
            'Nombre maximal d\'articles atteint',
            ['current_count' => count($this->items), 'max_items' => $maxItems],
            'warning'
        );
    }
    
    try {
        // Récupération produit avec gestion d'erreur
        $product = $this->getProductInfo($productId);
        if (!$product) {
            return $secureDb->handleSecureError(
                'CART',
                'product_fetch_failed',
                'Produit introuvable',
                ['product_id' => $productId],
                'error'
            );
        }
        
        // Vérifier stock
        $stock = (int)$product['stock'];
        if ($stock <= 0) {
            return $secureDb->handleSecureError(
                'CART',
                'out_of_stock',
                'Produit en rupture de stock',
                ['product_id' => $productId, 'stock' => $stock],
                'warning'
            );
        }
        
        // Ajuster quantité au stock disponible
        $finalQuantity = min($quantity, $stock);
        $actualPrice = (float)$product['price'];
        
        // Créer l'article
        $this->items[$productId] = [
            'id' => $productId,
            'quantity' => $finalQuantity,
            'price' => $actualPrice,
            'subtotal' => $actualPrice * $finalQuantity,
            'weight' => (int)($product['weight'] ?? 0),
            'reference' => $product['reference'] ?? '',
            'image_url' => $product['image_url'] ?? '',
            'category' => $product['category'] ?? '',
            'tva_rate' => (int)($product['tva_rate'] ?? 0),
            'largeur' => (int)($product['largeur'] ?? 0),
            'longueur' => (int)($product['longueur'] ?? 0),
            'hauteur' => (int)($product['hauteur'] ?? 0),
            'added_at' => time(),
            'name' => $product['name'] ?? "Produit #{$productId}"
        ];
        
        // Marquer les changements et sauvegarder
        $this->markChanges();
        $this->save();
        
        // Codes promo
        $this->checkDiscountMinimumAfterUpdate();
        
        Logger::info('CART', "Produit ajouté avec succès", [
            'product_id' => $productId,
            'quantity' => $finalQuantity
        ]);
        
        return true;
        
    } catch (Exception $e) {
        return $secureDb->handleSecureError(
            'CART',
            'add_item_exception',
            'Erreur lors de l\'ajout au panier',
            ['product_id' => $productId, 'exception' => $e->getMessage()],
            'error'
        );
    }
}

public function updateItem($productId, $quantity) {
    $secureDb = SecureDatabase::getInstance();
    
    // ✅ VALIDATION PRODUIT UNIFIÉE
    $productValidation = $secureDb->validateProductWithError($productId, 'CART');
    if (!$productValidation['valid']) {
        return $productValidation['error'];
    }
    $productId = $productValidation['product_id'];
    
    // ✅ VALIDATION QUANTITÉ UNIFIÉE (avec cas spécial quantity = 0)
    if ($quantity <= 0) {
        return $this->removeItem($productId);
    }
    
    $quantityValidation = $secureDb->validateQuantityWithError($quantity, 'CART');
    if (!$quantityValidation['valid']) {
        return $quantityValidation['error'];
    }
    $quantity = $quantityValidation['quantity'];
    
    // Rate limiting
    if (!$secureDb->cartRateLimiter('update', $productId)) {
        return $secureDb->handleSecureError(
            'CART',
            'rate_limit_exceeded',
            'Trop de demandes, veuillez patienter',
            ['product_id' => $productId, 'action' => 'update'],
            'security'
        );
    }
    
    // Vérifier existence en panier
    if (!isset($this->items[$productId])) {
        return $secureDb->handleSecureError(
            'CART',
            'item_not_in_cart',
            'Produit non trouvé dans le panier',
            ['product_id' => $productId],
            'warning'
        );
    }
    
    try {
        // Vérifier stock
        $stock = $this->getProductStock($productId);
        
        
        
        
              // ✅ CORRECTION : Vérifier stock AVANT ajustement silencieux
        if ($stock <= 0) {
            return $secureDb->handleSecureError(
                'CART',
                'out_of_stock',
                'Produit en rupture de stock',
                ['product_id' => $productId, 'stock' => $stock],
                'warning'
            );
        }
        
        if ($quantity > $stock) {
            return $secureDb->handleSecureError(
                'CART',
                'insufficient_stock',
                "Stock insuffisant : seulement {$stock} unités disponibles",
                [
                    'product_id' => $productId, 
                    'requested' => $quantity, 
                    'available' => $stock
                ],
                'warning'
            );
        }
        
        
        
        
        
        
        
        
        
        
        
        
        
        
        
        
        
        
        
        $finalQuantity = min($quantity, $stock);
        
        if ($finalQuantity <= 0) {
            return $this->removeItem($productId);
        }
        
        // Mettre à jour prix actuel
        $actualPrice = $this->getActualProductPrice($productId);
        if ($actualPrice === false) {
            $actualPrice = $this->items[$productId]['price'];
        }
        
        $this->items[$productId]['quantity'] = $finalQuantity;
        $this->items[$productId]['price'] = $actualPrice;
        $this->items[$productId]['subtotal'] = $actualPrice * $finalQuantity;
        $this->items[$productId]['updated_at'] = time();
        
        $this->markChanges();
        $this->save();
        
        // Codes promo
        $this->checkDiscountMinimumAfterUpdate();
        
        Logger::info('CART', "Quantité mise à jour", [
            'product_id' => $productId,
            'new_quantity' => $finalQuantity,
            'stock_adjusted' => ($finalQuantity != $quantity)
        ]);
        
        return true;
        
    } catch (Exception $e) {
        return $secureDb->handleSecureError(
            'CART',
            'update_item_exception',
            'Erreur lors de la mise à jour',
            ['product_id' => $productId, 'exception' => $e->getMessage()],
            'error'
        );
    }
}

    /**
     * ✅ CONSERVÉ - Supprime un produit du panier + vérification codes promo
     */
public function removeItem($productId) {
    $secureDb = SecureDatabase::getInstance();
    
    // ✅ VALIDATION PRODUIT UNIFIÉE (sans check database car on supprime)
    $productValidation = $secureDb->validateProductWithError($productId, 'CART', false);
    if (!$productValidation['valid']) {
        return $productValidation['error'];
    }
    $productId = $productValidation['product_id'];
    
    // Rate limiting
    if (!$secureDb->cartRateLimiter('remove', $productId)) {
        return $secureDb->handleSecureError(
            'CART',
            'rate_limit_exceeded',
            'Trop de demandes, veuillez patienter',
            ['product_id' => $productId, 'action' => 'remove'],
            'security'
        );
    }
    
    // Vérifier existence
    if (!isset($this->items[$productId])) {
        return $secureDb->handleSecureError(
            'CART',
            'item_not_in_cart',
            'Produit non trouvé dans le panier',
            ['product_id' => $productId],
            'warning'
        );
    }
    
    try {
        // Sauvegarder les informations avant suppression pour le log
        $productInfo = $this->items[$productId];
        
        // Supprimer l'article
        unset($this->items[$productId]);
        
        // Sauvegarder
        $this->markChanges();
        $this->save();
        
        // Codes promo
        $this->checkDiscountMinimumAfterUpdate();
        
        Logger::info('CART', "Produit supprimé avec succès", [
            'product_id' => $productId,
            'quantity' => $productInfo['quantity'],
            'price' => $productInfo['price'],
            'name' => $productInfo['name'] ?? "Produit #{$productId}"
        ]);
        
        return true;
        
    } catch (Exception $e) {
        return $secureDb->handleSecureError(
            'CART',
            'remove_item_exception',
            'Erreur lors de la suppression',
            ['product_id' => $productId, 'exception' => $e->getMessage()],
            'error'
        );
    }
}

    /**
     * ✅ CONSERVÉ - Vide complètement le panier et supprime les codes promo
     */
    public function clear() {
        $secureDb = SecureDatabase::getInstance();
        if (!$secureDb->cartRateLimiter('clear')) {
            return false;
        }
        
        try {
            // Sauvegarder les informations avant suppression
            $itemCount = count($this->items);
            $totalValue = $this->getTotal();
            
            // Codes promo : Supprimer le code promo avant de vider le panier
            if (isset($_SESSION['discount_code'])) {
                $this->removeDiscount();
            }
            
            // Vider le panier
            $this->items = [];
            
            // Réinitialiser les flags
            $this->integrityVerified = false;
            
            // Sauvegarder
            $this->markChanges();
            $this->save();
            
            Logger::info('CART', "Panier vidé avec succès", [
                'previous_item_count' => $itemCount,
                'previous_total_value' => $totalValue
            ]);
            
            return true;
        } catch (Exception $e) {
            Logger::error('CART', "Erreur vidage panier: " . $e->getMessage());
            return false;
        }
    }

    // ================================================================================================
    // MÉTHODES D'ACCÈS AUX DONNÉES - CONSERVÉES
    // ================================================================================================

    /**
     * ✅ CONSERVÉ - Récupère le contenu du panier avec vérification d'intégrité optionnelle
     */
    public function getItems($withDetails = false) {
        // Vérifier l'intégrité si programmée
        $this->ensureIntegrityChecked();
        
        Logger::debug('CART', "Récupération des articles du panier", [
            'items_count' => count($this->items),
            'with_details' => $withDetails
        ]);
        
        if (!$withDetails) {
            return $this->items;
        }
        
        // Enrichir avec les détails complets des produits (SANS cache)
        $itemsWithDetails = [];
        foreach ($this->items as $productId => $item) {
            $productInfo = $this->getProductInfo($productId);
            if ($productInfo) {
                $itemsWithDetails[$productId] = array_merge($item, [
                    'current_price' => $productInfo['price'],
                    'current_stock' => $productInfo['stock'],
                    'stock_remaining' => max(0, $productInfo['stock'] - $item['quantity']),
                    'is_in_stock' => ($productInfo['stock'] > 0),
                    'price_changed' => (abs($productInfo['price'] - $item['price']) > 0.01)
                ]);
            } else {
                // Produit non trouvé, utiliser les informations existantes
                $itemsWithDetails[$productId] = array_merge($item, [
                    'current_price' => null,
                    'current_stock' => 0,
                    'stock_remaining' => 0,
                    'is_in_stock' => false,
                    'price_changed' => false,
                    'product_unavailable' => true
                ]);
            }
        }
        
        return $itemsWithDetails;
    }

    /**
     * ✅ CONSERVÉ - Récupère les détails d'un article spécifique
     */
  public function getItem($productId, $withDetails = false) {
    $secureDb = SecureDatabase::getInstance();
    
    // ✅ VALIDATION PRODUIT UNIFIÉE (sans check database car lecture seule)
    $productValidation = $secureDb->validateProductWithError($productId, 'CART', false);
    if (!$productValidation['valid']) {
        // Pour getItem(), on retourne null au lieu d'une erreur (lecture silencieuse)
        Logger::debug('CART', 'getItem: ID produit invalide', [
            'provided_id' => $productId,
            'error' => $productValidation['error']
        ]);
        return null;
    }
    $productId = $productValidation['product_id'];
    
    // Vérifier l'intégrité si programmée
    $this->ensureIntegrityChecked();
    
    // Vérifier existence dans le panier
    if (!isset($this->items[$productId])) {
        Logger::debug('CART', 'getItem: Produit non présent dans le panier', [
            'product_id' => $productId
        ]);
        return null;
    }
    
    $item = $this->items[$productId];
    
    if (!$withDetails) {
        return $item;
    }
    
    // Enrichir avec les détails produit actuels
    try {
        $productInfo = $this->getProductInfo($productId);
        
        if ($productInfo) {
            return array_merge($item, [
                'current_price' => (float)$productInfo['price'],
                'current_stock' => (int)$productInfo['stock'],
                'stock_remaining' => max(0, (int)$productInfo['stock'] - (int)$item['quantity']),
                'is_in_stock' => ((int)$productInfo['stock'] > 0),
                'price_changed' => (abs((float)$productInfo['price'] - (float)$item['price']) > 0.01)
            ]);
        } else {
            return array_merge($item, [
                'current_price' => null,
                'current_stock' => 0,
                'stock_remaining' => 0,
                'is_in_stock' => false,
                'price_changed' => false,
                'product_unavailable' => true
            ]);
        }
        
    } catch (Exception $e) {
        Logger::error('CART', 'getItem: Erreur enrichissement détails', [
            'product_id' => $productId,
            'exception' => $e->getMessage()
        ]);
        
        return $item; // Retourner l'article de base en cas d'erreur
    }
}

    /**
     * ✅ CONSERVÉ - Vérifie la disponibilité de tous les produits du panier
     */
    public function checkAvailability() {
        Logger::debug('CART', "Vérification de la disponibilité des produits");
        
        $unavailableItems = [];
        
        foreach ($this->items as $productId => $item) {
            // ✅ ACCÈS DIRECT DB (sans cache)
            $stock = $this->getProductStock($productId);
            if ($stock < $item['quantity']) {
                $unavailableItems[] = [
                    'id' => $productId,
                    'name' => $item['name'] ?? "Produit #{$productId}",
                    'requested' => $item['quantity'],
                    'available' => $stock,
                    'status' => ($stock <= 0) ? 'out_of_stock' : 'insufficient_stock'
                ];
            }
        }
        
        if (!empty($unavailableItems)) {
            Logger::warning('CART', "Problèmes de stock détectés", [
                'issues_count' => count($unavailableItems),
                'items' => array_column($unavailableItems, 'id')
            ]);
        }
        
        return $unavailableItems;
    }

    // ================================================================================================
    // CALCULS ET TOTAUX - CONSERVÉS
    // ================================================================================================

    /**
     * ✅ CONSERVÉ - Calcule le montant des taxes avec détail par taux
     */
    public function getTaxes($detailByRate = false) {
        $this->ensureIntegrityChecked();
        
        $taxes = [];
        $totalTaxes = 0;
        
        foreach ($this->items as $item) {
            if (!isset($item['tva_rate'])) {
                continue;
            }
            
            $rate = (float)$item['tva_rate'];
            $taxAmount = $item['subtotal'] * ($rate / 100);
            
            if ($detailByRate) {
                if (!isset($taxes[$rate])) {
                    $taxes[$rate] = 0;
                }
                $taxes[$rate] += $taxAmount;
            }
            
            $totalTaxes += $taxAmount;
        }
        
        if ($detailByRate) {
            ksort($taxes);
            $taxes['total'] = round($totalTaxes, 2);
            return $taxes;
        }
        
        return round($totalTaxes, 2);
    }

    /**
     * ✅ CONSERVÉ - Récupère le nombre total d'articles dans le panier
     */
    public function getItemCount() {
        $this->ensureIntegrityChecked();
        
        $count = 0;
        foreach ($this->items as $item) {
            $count += $item['quantity'];
        }
        
        return $count;
    }

    /**
     * ✅ CONSERVÉ - Vérifie si le panier est vide
     */
    public function isEmpty() {
        $this->ensureIntegrityChecked();
        return empty($this->items);
    }

    /**
     * ✅ CONSERVÉ - Calcule le poids total du panier
     */
    public function getTotalWeight() {
        $this->ensureIntegrityChecked();
        
        $weight = 0;
        foreach ($this->items as $item) {
            if (isset($item['weight'])) {
                $weight += $item['weight'] * $item['quantity'];
            }
        }
        
        return $weight;
    }

    /**
     * ✅ CONSERVÉ - Récupère les dimensions maximales pour l'estimation de livraison
     */
    public function getMaxDimensions() {
        $this->ensureIntegrityChecked();
        
        $maxDimensions = ['largeur' => 0, 'longueur' => 0, 'hauteur' => 0];
        
        foreach ($this->items as $item) {
            foreach (['largeur', 'longueur', 'hauteur'] as $dimension) {
                if (isset($item[$dimension]) && $item[$dimension] > $maxDimensions[$dimension]) {
                    $maxDimensions[$dimension] = $item[$dimension];
                }
            }
        }
        
        return $maxDimensions;
    }

    /**
     * ✅ CONSERVÉ - Calcule le volume total approximatif
     */
    public function getTotalVolume() {
        $this->ensureIntegrityChecked();
        
        $totalVolume = 0;
        foreach ($this->items as $item) {
            if (isset($item['largeur'], $item['longueur'], $item['hauteur'])) {
                $volume = $item['largeur'] * $item['longueur'] * $item['hauteur'] * $item['quantity'];
                $totalVolume += $volume;
            }
        }
        
        return $totalVolume;
    }

    /**
     * ✅ CONSERVÉ - Récupère l'ID unique du panier
     */
    public function getCartId(): string {
        return $this->cartId;
    }

    /**
     * ✅ CONSERVÉ - Récupère la date de dernière modification
     */
    public function getLastModified($format = null) {
        if ($format === null) {
            return $this->lastModified;
        }
        return date($format, $this->lastModified);
    }

    /**
     * ✅ CONSERVÉ - Vérifie si le panier a été modifié depuis une date donnée
     */
    public function hasBeenModifiedSince($timestamp) {
        return $this->lastModified > $timestamp;
    }

    // ================================================================================================
    // SAUVEGARDE BASE DE DONNÉES - CONSERVÉE
    // ================================================================================================

    /**
     * ✅ CONSERVÉ - Sauvegarde le panier en base de données
     */
    public function saveToDatabase() {
        // Éviter sauvegardes multiples
        if ($this->savedToDatabase && !$this->hasUnsavedChanges()) {
            return true;
        }
        
        try {
            $this->db->beginTransaction();
            
            // Gérer le panier (1 requête)
            $existingCart = $this->db->queryRow(
                "SELECT cart_id FROM carts WHERE cart_id = ?",
                [$this->cartId]
            );
            
         /*   if ($existingCart) {
         $this->db->query(
                    "UPDATE carts SET updated_at = NOW(), status = ? WHERE cart_id = ?",
                    [empty($this->items) ? 'abandoned' : 'active', $this->cartId]
                );
            } */
            
            if ($existingCart) {
    $this->db->query(
        "UPDATE carts SET id_client = ?, updated_at = NOW(), status = ? WHERE cart_id = ?",
        [$this->clientId, empty($this->items) ? 'abandoned' : 'active', $this->cartId]
    );
}
            
            
            else {
                $secureDb = SecureDatabase::getInstance();
                $cartToken = $secureDb->generateCartToken($this->cartId, session_id());
                
                // Créer le cookie
                $this->setCartCookie($cartToken);
                
                $this->db->query(
                    "INSERT INTO carts (cart_id, id_client, session_id, cart_token, created_at, updated_at, status) 
                     VALUES (?, ?, ?, ?, NOW(), NOW(), ?)",
                    [$this->cartId, $this->clientId, session_id(), $cartToken, 
                     empty($this->items) ? 'abandoned' : 'active']
                );
            }
            
            // Utiliser la méthode optimisée
            $this->syncCartItemsOptimized();
            
            $this->db->commit();
            $this->savedToDatabase = true;
            $this->markChangesSaved();
            
            return true;
        } catch (Exception $e) {
            if ($this->db->inTransaction()) {
                $this->db->rollback();
            }
            Logger::error('CART', "Erreur sauvegarde: " . $e->getMessage());
            return false;
        }
    }

    /**
     * ✅ CONSERVÉ - Créer le cookie du panier
     */
    private function setCartCookie($cartToken) {
        $cookieDomain = $_SERVER['HTTP_HOST'];
        if (strpos($cookieDomain, ':') !== false) {
            $cookieDomain = explode(':', $cookieDomain)[0];
        }
        
        $cookieOptions = [
            'expires' => time() + (30 * 86400), // 30 jours
            'path' => '/',
            'domain' => $cookieDomain,
            'secure' => (defined('ENVIRONMENT') && ENVIRONMENT === 'production'),
            'httponly' => true,
            'samesite' => 'Lax'
        ];
        
        setcookie('cart_token', $cartToken, $cookieOptions);
    }

    /**
     * ✅ CONSERVÉ - Synchronisation optimisée (3 requêtes au lieu de 7)
     */
    private function syncCartItemsOptimized() {
        if (empty($this->items)) {
            // 1 seule requête pour vider
            $deleted = $this->db->query(
                "DELETE FROM cart_items WHERE cart_id = ?", 
                [$this->cartId]
            )->rowCount();
            
            Logger::debug('CART', "Panier vidé", ['deleted' => $deleted]);
            return;
        }
        
        // 1. UNE requête pour récupérer l'état actuel
        $existingItems = $this->db->queryAll(
            "SELECT product_id, quantity FROM cart_items WHERE cart_id = ?",
            [$this->cartId]
        );
        
        $existingMap = [];
        foreach ($existingItems as $item) {
            $existingMap[$item['product_id']] = (int)$item['quantity'];
        }
        
        // 2. UNE requête pour les insertions/mises à jour
        $this->db->beginTransaction();
        try {
            foreach ($this->items as $productId => $item) {
                if (isset($existingMap[$productId])) {
                    // Mise à jour si quantité différente
                    if ($existingMap[$productId] !== $item['quantity']) {
                        $this->db->query(
                            "UPDATE cart_items SET quantity = ?, updated_at = NOW() WHERE cart_id = ? AND product_id = ?",
                            [$item['quantity'], $this->cartId, $productId]
                        );
                    }
                    unset($existingMap[$productId]);
                } else {
                    // Insertion
                    $this->db->query(
                        "INSERT INTO cart_items (cart_id, product_id, quantity, price_at_addition, created_at, updated_at) 
                         VALUES (?, ?, ?, ?, NOW(), NOW())",
                        [$this->cartId, $productId, $item['quantity'], $item['price']]
                    );
                }
            }
            
            // 3. UNE requête pour les suppressions (articles supprimés)
            if (!empty($existingMap)) {
                $toDelete = array_keys($existingMap);
                $placeholders = implode(',', array_fill(0, count($toDelete), '?'));
                $this->db->query(
                    "DELETE FROM cart_items WHERE cart_id = ? AND product_id IN ($placeholders)",
                    array_merge([$this->cartId], $toDelete)
                );
            }
            
            $this->db->commit();
            
            Logger::debug('CART', "Sync optimisée (3 requêtes max)", [
                'cart_id' => $this->cartId,
                'items_count' => count($this->items)
            ]);
        } catch (Exception $e) {
            $this->db->rollback();
            throw $e;
        }
    }

    // ================================================================================================
    // GESTION CLIENT ET FUSION PANIERS - CONSERVÉE
    // ================================================================================================

    /**
     * ✅ CONSERVÉ - Associe le panier à un client connecté avec fusion intelligente
     */
public function assignToClient($clientId) {
   $secureDb = SecureDatabase::getInstance();
   
   // PROTECTION : Éviter double fusion si déjà fait
    if ($this->clientId == $clientId) {
        Logger::info('CART', 'Client déjà assigné, pas de fusion nécessaire', [
            'client_id' => $clientId
        ]);
        return true;
    }
   
   // ✅ VALIDATION CLIENT ID UNIFIÉE
   if (!is_numeric($clientId) || $clientId <= 0 || floor($clientId) != $clientId) {
       return $secureDb->handleSecureError(
           'CART',
           'invalid_client_id',
           'ID client invalide pour association',
           ['provided_client_id' => $clientId, 'type' => gettype($clientId)],
           'error'
       );
   }
   
   try {
       $this->clientId = (int)$clientId;
       
       // Chercher un panier existant pour ce client
       $existingClientCart = $this->db->queryRow(
           "SELECT cart_id FROM carts 
            WHERE id_client = ? AND status = 'active' 
            AND cart_id != ? 
            ORDER BY updated_at DESC LIMIT 1",
           [$clientId, $this->cartId]
       );
       
       if ($existingClientCart && !empty($this->items)) {
           // Fusionner avec le panier client existant
           $this->mergeWithClientCart($existingClientCart['cart_id']);
       } else if ($existingClientCart && empty($this->items)) {
           // Adopter le panier client existant
           $this->switchToCart($existingClientCart['cart_id']);
       }
       
       // Sauvegarder avec l'ID client
       $this->saveToDatabase();
       
       Logger::info('CART', "Panier associé au client", [
           'client_id' => $clientId,
           'cart_id' => $this->cartId,
           'items_count' => count($this->items),
           'had_existing_cart' => !empty($existingClientCart)
       ]);
       
       return true;
       
   } catch (Exception $e) {
       return $secureDb->handleSecureError(
           'CART',
           'client_assignment_exception',
           'Erreur lors de l\'association client',
           ['client_id' => $clientId, 'exception' => $e->getMessage()],
           'error'
       );
   }
}

    /**
     * ✅ CONSERVÉ - Fusionne le panier actuel avec un panier client existant
     */
    private function mergeWithClientCart($clientCartId) {
        Logger::info('CART', "FUSION PANIER CLIENT DÉCLENCHÉE", [
            'current_cart' => $this->cartId,
            'client_cart' => $clientCartId,
            'current_items' => count($this->items)
        ]);
        
        // Charger les articles du panier client
        $clientItems = $this->loadCartItems($clientCartId);
        
        // Sauvegarder les codes promo du panier actuel
        $currentDiscount = isset($_SESSION['discount_code']) ? $_SESSION['discount_code'] : null;
        
        // Fusionner avec le panier actuel (prendre la quantité maximale)
        foreach ($clientItems as $productId => $clientItem) {
            if (isset($this->items[$productId])) {
                // Article existe dans les deux paniers - additionner les quantités
                $totalQty = $clientItem['quantity'] + $this->items[$productId]['quantity'];
                
                // Vérifier le stock disponible (SANS cache)
                $stock = $this->getProductStock($productId);
                $finalQty = min($totalQty, $stock);
                
                $this->items[$productId]['quantity'] = $finalQty;
                $this->items[$productId]['subtotal'] = $this->items[$productId]['price'] * $finalQty;
                $this->items[$productId]['merged_from'] = 'both_carts';
                $this->items[$productId]['merged_at'] = time();
                
                Logger::debug('CART', "Article fusionné", [
                    'product_id' => $productId,
                    'client_qty' => $clientItem['quantity'],
                    'session_qty' => $this->items[$productId]['quantity'] - $clientItem['quantity'],
                    'final_qty' => $finalQty,
                    'stock_limited' => ($totalQty > $stock)
                ]);
            } else {
                // Article uniquement dans le panier client - l'ajouter
                $this->items[$productId] = $clientItem;
                $this->items[$productId]['merged_from'] = 'client_cart';
                $this->items[$productId]['merged_at'] = time();
            }
        }
        
        // Marquer l'ancien panier client comme fusionné
        $this->db->query(
            "UPDATE carts SET status = 'merged', updated_at = NOW() WHERE cart_id = ?",
            [$clientCartId]
        );
        
        // Vérifier si le code promo est toujours valide après fusion
        if ($currentDiscount) {
            $this->checkDiscountMinimumAfterUpdate();
        }
        
        // Sauvegarder le panier fusionné
        $this->save();
        
        Logger::info('CART', "Panier fusionné avec panier client", [
            'client_cart_id' => $clientCartId,
            'current_cart_id' => $this->cartId,
            'total_items' => count($this->items),
            'discount_preserved' => ($currentDiscount !== null)
        ]);
    }

    /**
     * ✅ CONSERVÉ - Fusion d'articles avec logique métier corrigée
     */
    private function mergeCartItems($existingItem, $newItem, $strategy = 'add') {
        if (!is_array($existingItem) || !is_array($newItem)) {
            throw new InvalidArgumentException("Articles invalides");
        }
        
        if ($existingItem['id'] !== $newItem['id']) {
            throw new InvalidArgumentException("IDs différents");
        }
        
        $existingQty = (int)$existingItem['quantity'];
        $newQty = (int)$newItem['quantity'];
        
        // Logique simple et claire
        switch ($strategy) {
            case 'add':
                $finalQuantity = $existingQty + $newQty; // 2 + 3 = 5
                break;
            case 'max':
                $finalQuantity = max($existingQty, $newQty);
                break;
            case 'replace':
                $finalQuantity = $newQty;
                break;
            default:
                $finalQuantity = $existingQty + $newQty; // Par défaut : additionner
        }
        
        // Vérifier le stock disponible (SANS cache)
        $stock = $this->getProductStock($existingItem['id']);
        if ($finalQuantity > $stock) {
            $finalQuantity = $stock;
            Logger::warning('CART', "Quantité fusionnée limitée par le stock", [
                'product_id' => $existingItem['id'],
                'wanted' => $existingQty + $newQty,
                'stock' => $stock
            ]);
        }
        
        // Validation quantité max
        $maxQty = defined('MAX_ITEM_QUANTITY') ? MAX_ITEM_QUANTITY : 100;
        if ($finalQuantity > $maxQty) {
            $finalQuantity = $maxQty;
        }
        
        // Log pour debug
        Logger::debug('CART', "Articles fusionnés", [
            'product_id' => $existingItem['id'],
            'existing_qty' => $existingQty,
            'new_qty' => $newQty,
            'final_qty' => $finalQuantity,
            'strategy' => $strategy
        ]);
        
        // Retourner l'article fusionné avec les bonnes quantités
        return array_merge($existingItem, [
            'quantity' => $finalQuantity,
            'subtotal' => $existingItem['price'] * $finalQuantity,
            'merged_at' => time(),
            'merge_strategy' => $strategy
        ]);
    }

    // ================================================================================================
    // RÉCAPITULATIF ET RAPPORTS - CONSERVÉS AVEC SIMPLIFICATIONS
    // ================================================================================================

    /**
     * ✅ CONSERVÉ - Génère un récapitulatif complet avec codes promo
     */
    public function getSummary($includeDetails = true) {
        $this->ensureIntegrityChecked();
        
        $subtotal = $this->getSubtotalBeforeDiscount();
        $discountInfo = $this->getDiscountInfo();
        $total = $this->getTotal();
        $itemCount = $this->getItemCount();
        $totalWeight = $this->getTotalWeight();
        
        $summary = [
            'cart_id' => $this->cartId,
            'item_count' => $itemCount,
            'subtotal' => $subtotal,
            'total' => $total,
            'total_weight' => $totalWeight,
            'last_modified' => $this->getLastModified('c'),
            'timestamp' => time()
        ];
        
        // Ajouter les informations de réduction
        if ($discountInfo) {
            $summary['discount'] = [
                'code' => $discountInfo['code'],
                'type' => $discountInfo['type'],
                'value' => $discountInfo['value'],
                'amount' => $discountInfo['amount'],
                'percentage_saved' => $subtotal > 0 ? round(($discountInfo['amount'] / $subtotal) * 100, 1) : 0
            ];
        } else {
            $summary['discount'] = null;
        }
        
        // Détails des articles si demandé
        if ($includeDetails) {
            $summary['items'] = $this->getItems(true);
            $summary['availability'] = $this->checkAvailability();
        }
        
        // Hash d'intégrité
        $summary['integrity_hash'] = $this->generateSummaryHash($summary);
        
        return $summary;
    }

    /**
     * ✅ CONSERVÉ - Génère un hash d'intégrité pour le récapitulatif
     */
    private function generateSummaryHash($summary) {
        // Exclure le hash lui-même du calcul
        $dataForHash = $summary;
        unset($dataForHash['integrity_hash']);
        
        $secureDb = SecureDatabase::getInstance();
        return $secureDb->generateHmac($dataForHash);
    }

    /**
     * ✅ CONSERVÉ - Calcule une empreinte du contenu du panier
     */
    public function getFingerprint() {
        $cartData = [
            'items' => $this->items,
            'cart_id' => $this->cartId,
            'last_modified' => $this->lastModified
        ];
        
        $secureDb = SecureDatabase::getInstance();
        return $secureDb->generateHmac($cartData);
    }

    // ================================================================================================
    // GESTION DES CHANGEMENTS - CONSERVÉE
    // ================================================================================================

    /**
     * ✅ CONSERVÉ - Vérifier s'il y a des changements non sauvegardés
     */
    private function hasUnsavedChanges() {
        return $this->hasUnsavedChanges;
    }

    /**
     * ✅ CONSERVÉ - Marquer qu'il y a des changements à sauvegarder
     */
    private function markChanges() {
        $this->hasUnsavedChanges = true;
        $this->savedToDatabase = false;
    }

    /**
     * ✅ CONSERVÉ - Marquer que les changements ont été sauvegardés
     */
    private function markChangesSaved() {
        $this->hasUnsavedChanges = false;
        $this->savedToDatabase = true;
    }

    // ================================================================================================
    // NETTOYAGE ET MAINTENANCE - SIMPLIFIÉS
    // ================================================================================================

    /**
     * ✅ SIMPLIFIÉ - Nettoie les ressources (sans cache)
     */
    public function cleanup() {
        // Effectuer la sauvegarde finale si nécessaire
        if (!empty($this->items) && !$this->savedToDatabase) {
            $this->saveToDatabase();
        }
        
        Logger::debug('CART', "Nettoyage du panier terminé (version simplifiée)", [
            'items_count' => count($this->items),
            'cart_id' => $this->cartId
        ]);
    }

    /**
     * ✅ CONSERVÉ - Nettoie les paniers abandonnés (méthode statique pour les tâches cron)
     */
    public static function cleanupAbandonedCarts() {
        if (!defined('CRON_SECURITY_TOKEN')) {
            return false;
        }
        
        try {
           // $db = Database::getInstance();
           $db = SecureDatabase::getInstance();
            
            // Définir les seuils de nettoyage
            $abandonedDays = defined('CART_DB_ABANDONED_DAYS') ? CART_DB_ABANDONED_DAYS : 30;
            $deleteDays = defined('CART_DB_DELETE_DAYS') ? CART_DB_DELETE_DAYS : 90;
            
            // Marquer comme abandonnés les paniers inactifs
            $abandonedCount = $db->query(
                "UPDATE carts SET status = 'abandoned' 
                 WHERE status = 'active' 
                 AND updated_at < DATE_SUB(NOW(), INTERVAL ? DAY)",
                [$abandonedDays]
            )->rowCount();
            
            // Supprimer les très anciens paniers
            $deletedCartsCount = $db->query(
                "DELETE FROM carts 
                 WHERE status IN ('abandoned', 'merged') 
                 AND updated_at < DATE_SUB(NOW(), INTERVAL ? DAY)",
                [$deleteDays]
            )->rowCount();
            
            Logger::info('CART', "Nettoyage des paniers effectué", [
                'abandoned_count' => $abandonedCount,
                'deleted_count' => $deletedCartsCount,
                'abandoned_threshold_days' => $abandonedDays,
                'delete_threshold_days' => $deleteDays
            ]);
            
            return [
                'abandoned' => $abandonedCount,
                'deleted' => $deletedCartsCount
            ];
        } catch (Exception $e) {
            Logger::error('CART', "Erreur nettoyage paniers: " . $e->getMessage());
            return false;
        }
    }

    // ================================================================================================
    // MÉTHODES DEBUG ET DIAGNOSTICS - CONSERVÉES
    // ================================================================================================


    /**
     * ✅ CONSERVÉ - Test de connexion DB
     */
    private function testDatabaseConnection() {
        if (!$this->db || !($this->db instanceof Database)) {
            return ['status' => 'no_instance', 'error' => 'Database instance not available'];
        }
        
        try {
            $result = $this->db->queryValue("SELECT 1");
            return ['status' => 'ok', 'result' => $result];
        } catch (Exception $e) {
            return ['status' => 'error', 'error' => $e->getMessage()];
        }
    }


}

// ================================================================================================
// FINALISATION SIMPLIFIÉE
// ================================================================================================

register_shutdown_function(function() {
    // Version simplifiée - Plus de cache local à nettoyer
    Logger::debug('CART', "Shutdown simplifié - Pas de cache à nettoyer");
});