<!DOCTYPE html>
<html lang="fr">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>🛒 Mon Panier - Boutique DecosBois</title>
    <style>
        body { 
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; 
            margin: 0; 
            padding: 20px; 
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: #333;
        }
        
        .container { 
            max-width: 1000px; 
            margin: 0 auto; 
            background: white; 
            border-radius: 15px; 
            box-shadow: 0 10px 30px rgba(0,0,0,0.2);
            overflow: hidden;
        }
        
        .header {
            background: linear-gradient(45deg, #28a745, #20c997);
            color: white;
            padding: 20px;
            text-align: center;
        }
        
        .content {
            padding: 30px;
        }
        
        /* STATUS INDICATOR */
        .status-indicator {
            padding: 5px 10px;
            border-radius: 15px;
            font-size: 12px;
            font-weight: bold;
            margin: 5px 0 20px 0;
            text-align: center;
        }
        
        .status-online { background: #d4edda; color: #155724; }
        .status-syncing { background: #fff3cd; color: #856404; }
        .status-offline { background: #f8d7da; color: #721c24; }
        
        /* SECTION CODES PROMO */
        .promo-section {
            background: white;
            border: 2px solid #28a745;
            border-radius: 10px;
            padding: 20px;
            margin-bottom: 20px;
        }
        
        .promo-title {
            display: flex;
            align-items: center;
            gap: 10px;
            margin-bottom: 15px;
            font-size: 1.2rem;
            font-weight: bold;
            color: #2c3e50;
        }
        
        .promo-form {
            display: flex;
            gap: 10px;
            margin-bottom: 15px;
        }
        
        .promo-input {
            flex: 1;
            padding: 12px 15px;
            border: 2px solid #ced4da;
            border-radius: 8px;
            font-size: 1rem;
            text-transform: uppercase;
            transition: border-color 0.3s;
        }
        
        .promo-input:focus {
            outline: none;
            border-color: #28a745;
            box-shadow: 0 0 0 3px rgba(40, 167, 69, 0.1);
        }
        
        .promo-btn {
            padding: 12px 20px;
            background: linear-gradient(135deg, #28a745, #20c997);
            color: white;
            border: none;
            border-radius: 8px;
            font-size: 1rem;
            font-weight: 600;
            cursor: pointer;
            transition: all 0.3s ease;
            white-space: nowrap;
        }
        
        .promo-btn:hover {
            transform: translateY(-2px);
            box-shadow: 0 5px 15px rgba(40, 167, 69, 0.3);
        }
        
        .promo-btn:disabled {
            background: #6c757d;
            cursor: not-allowed;
            transform: none;
        }
        
        .promo-btn.processing {
            background: #ffc107;
            color: #212529;
        }
        
        .promo-suggestions {
            font-size: 0.9rem;
            color: #6c757d;
            margin-top: 10px;
        }
        
        .promo-suggestions strong {
            color: #495057;
        }
        
        .promo-applied {
            background: #d4edda;
            border: 2px solid #28a745;
            border-radius: 8px;
            padding: 15px;
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 15px;
        }
        
        .promo-info {
            flex: 1;
        }
        
        .promo-code {
            font-weight: bold;
            color: #155724;
            font-size: 1.1rem;
            margin-bottom: 5px;
        }
        
        .promo-savings {
            color: #28a745;
            font-weight: 600;
        }
        
        .remove-promo-btn {
            background: #dc3545;
            color: white;
            border: none;
            padding: 8px 15px;
            border-radius: 5px;
            font-size: 0.9rem;
            cursor: pointer;
            transition: background 0.3s;
        }
        
        .remove-promo-btn:hover {
            background: #c82333;
        }
        
        /* PANIER PRINCIPAL */
        .cart-section {
            background: #f8f9fa;
            border-radius: 10px;
            padding: 20px;
            margin-bottom: 20px;
        }
        
        .cart-item {
            background: white;
            border: 1px solid #dee2e6;
            border-radius: 8px;
            padding: 15px;
            margin-bottom: 15px;
            display: flex;
            justify-content: space-between;
            align-items: center;
            box-shadow: 0 2px 8px rgba(0,0,0,0.1);
            transition: all 0.3s ease;
        }
        
        .cart-item.updating {
            opacity: 0.6;
            transform: scale(0.98);
        }
        
        .item-info {
            flex: 1;
            margin-right: 15px;
        }
        
        .item-info h4 {
            margin: 0 0 5px 0;
            color: #2c3e50;
        }
        
        .item-price {
            color: #e74c3c;
            font-weight: bold;
        }
        
        .item-details {
            font-size: 12px;
            color: #6c757d;
            margin-top: 5px;
        }
        
        .item-actions {
            display: flex;
            align-items: center;
            gap: 15px;
        }
        
        .quantity-controls {
            display: flex;
            align-items: center;
            gap: 10px;
        }
        
        .quantity-btn {
            width: 40px;
            height: 40px;
            border: 2px solid #007bff;
            background: white;
            color: #007bff;
            border-radius: 50%;
            cursor: pointer;
            font-size: 18px;
            font-weight: bold;
            transition: all 0.2s;
            display: flex;
            align-items: center;
            justify-content: center;
        }
        
        .quantity-btn:hover {
            background: #007bff;
            color: white;
            transform: scale(1.1);
        }
        
        .quantity-btn:disabled {
            opacity: 0.5;
            cursor: not-allowed;
            transform: none;
        }
        
        .quantity-btn.decrease {
            border-color: #dc3545;
            color: #dc3545;
        }
        
        .quantity-btn.decrease:hover {
            background: #dc3545;
            color: white;
        }
        
        .quantity-btn.processing {
            background: #ffc107;
            color: #212529;
            animation: pulse 1s infinite;
        }
        
        @keyframes pulse {
            0%, 100% { transform: scale(1); }
            50% { transform: scale(1.05); }
        }
        
        .quantity-display {
            font-size: 18px;
            font-weight: bold;
            padding: 8px 15px;
            background: #e9ecef;
            border-radius: 20px;
            min-width: 40px;
            text-align: center;
            border: 2px solid #6c757d;
            transition: all 0.3s ease;
        }
        
        .quantity-display.updated {
            background: #d4edda;
            border-color: #28a745;
            animation: highlight 0.5s ease;
        }
        
        @keyframes highlight {
            0% { background: #fff3cd; }
            100% { background: #d4edda; }
        }
        
        /* CORBEILLE */
        .delete-btn {
            width: 40px;
            height: 40px;
            border: 2px solid #dc3545;
            background: white;
            color: #dc3545;
            border-radius: 50%;
            cursor: pointer;
            font-size: 18px;
            transition: all 0.2s;
            display: flex;
            align-items: center;
            justify-content: center;
        }
        
        .delete-btn:hover {
            background: #dc3545;
            color: white;
            transform: scale(1.1);
        }
        
        .delete-btn:disabled {
            opacity: 0.5;
            cursor: not-allowed;
            transform: none;
        }
        
        .delete-btn.processing {
            background: #ffc107;
            color: #212529;
            animation: pulse 1s infinite;
        }
        
        /* TOTAUX */
        .cart-totals {
            background: white;
            border-radius: 10px;
            padding: 20px;
            margin-bottom: 20px;
        }
        
        .total-line {
            display: flex;
            justify-content: space-between;
            align-items: center;
            padding: 8px 0;
            font-size: 1.1rem;
        }
        
        .total-line.subtotal {
            border-bottom: 1px solid #dee2e6;
        }
        
        .total-line.discount {
            color: #28a745;
            font-weight: 600;
        }
        
        .total-line.final {
            border-top: 2px solid #dee2e6;
            font-size: 1.3rem;
            font-weight: bold;
            color: #2c3e50;
            margin-top: 10px;
            padding-top: 15px;
        }
        
        .cart-total.updated {
            background: #28a745;
            animation: totalUpdate 0.5s ease;
        }
        
        @keyframes totalUpdate {
            0% { transform: scale(1); }
            50% { transform: scale(1.05); }
            100% { transform: scale(1); }
        }
        
        /* ACTIONS DU PANIER */
        .cart-actions {
            display: flex;
            justify-content: space-between;
            align-items: center;
            gap: 15px;
            margin-top: 20px;
            padding: 20px;
            background: #f8f9fa;
            border-radius: 10px;
        }
        
        .cart-actions-left {
            display: flex;
            gap: 10px;
        }
        
        .cart-actions-right {
            display: flex;
            gap: 15px;
            align-items: center;
        }
        
        .action-btn {
            padding: 12px 20px;
            border: none;
            border-radius: 8px;
            font-size: 1rem;
            font-weight: 600;
            cursor: pointer;
            transition: all 0.3s ease;
            text-decoration: none;
            display: inline-flex;
            align-items: center;
            gap: 8px;
        }
        
        .action-btn.secondary {
            background: #6c757d;
            color: white;
        }
        
        .action-btn.secondary:hover {
            background: #545b62;
            transform: translateY(-2px);
        }
        
        .action-btn.danger {
            background: #dc3545;
            color: white;
        }
        
        .action-btn.danger:hover {
            background: #c82333;
            transform: translateY(-2px);
        }
        
        .action-btn.primary {
            background: linear-gradient(135deg, #007bff, #0056b3);
            color: white;
            font-size: 1.1rem;
            padding: 15px 30px;
        }
        
        .action-btn.primary:hover {
            transform: translateY(-3px);
            box-shadow: 0 8px 20px rgba(0, 123, 255, 0.3);
        }
        
        .action-btn:disabled {
            opacity: 0.6;
            cursor: not-allowed;
            transform: none;
        }
        
        .action-btn.processing {
            background: #ffc107;
            color: #212529;
        }
        
        .loading {
            opacity: 0.6;
            pointer-events: none;
            transition: opacity 0.2s;
        }
        
        .error-message {
            background: #f8d7da;
            color: #721c24;
            padding: 10px;
            border-radius: 5px;
            margin: 10px 0;
            font-size: 14px;
            text-align: center;
        }
        
        .success-message {
            background: #d4edda;
            color: #155724;
            padding: 10px;
            border-radius: 5px;
            margin: 10px 0;
            font-size: 14px;
            text-align: center;
        }
        
        .empty-cart {
            text-align: center;
            padding: 60px 20px;
            color: #6c757d;
            font-size: 1.2rem;
        }
        
        .empty-cart .icon {
            font-size: 4rem;
            margin-bottom: 20px;
        }
        
        @media (max-width: 768px) {
            .cart-item {
                flex-direction: column;
                align-items: stretch;
                gap: 15px;
            }
            
            .item-actions {
                justify-content: space-between;
            }
            
            .cart-actions {
                flex-direction: column;
                gap: 15px;
            }
            
            .cart-actions-left,
            .cart-actions-right {
                width: 100%;
                justify-content: center;
            }
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🛒 Mon Panier</h1>
            <p><strong>Boutique DecosBois</strong> - Gestion complète de votre commande</p>
        </div>
        
        <div class="content">
            <!-- STATUS INDICATOR -->
            <div class="status-indicator status-online" id="connection-status">
                🟢 Connecté - Session: <span id="session-id">loading...</span>
            </div>
            
            <!-- SECTION CODES PROMO -->
            <div class="promo-section">
                <div class="promo-title">
                    🎟️ Code Promo
                </div>
                
                <!-- État SANS code promo -->
                <div id="promo-form-container">
                    <div class="promo-form">
                        <input type="text" 
                               id="promo-input" 
                               class="promo-input" 
                               placeholder="Entrez votre code promo" 
                               maxlength="20">
                        <button id="apply-promo-btn" class="promo-btn">Appliquer</button>
                    </div>
                    <div class="promo-suggestions">
                        💡 <strong>Testez :</strong> BIENVENUE10, REDUCTION5, NOEL15
                    </div>
                </div>
                
                <!-- État AVEC code promo appliqué -->
                <div id="promo-applied-container" style="display: none;">
                    <!-- Sera rempli dynamiquement -->
                </div>
            </div>
            
            <!-- PANIER PRINCIPAL -->
            <div class="cart-section">
                <h2>📦 Articles dans votre panier</h2>
                
                <div id="cart-items">
                    <div class="loading" style="text-align: center; padding: 50px;">
                        🔄 Chargement du panier...
                    </div>
                </div>
                
                <!-- TOTAUX DÉTAILLÉS -->
                <div class="cart-totals" id="cart-totals" style="display: none;">
                    <div class="total-line subtotal">
                        <span>Sous-total:</span>
                        <span id="cart-subtotal">0,00 €</span>
                    </div>
                    <div class="total-line discount" id="discount-line" style="display: none;">
                        <span id="discount-text">Code EXEMPLE:</span>
                        <span id="discount-amount">-0,00 €</span>
                    </div>
                    <div class="total-line final">
                        <span>Total:</span>
                        <span id="cart-total">0,00 €</span>
                    </div>
                </div>
                
                <!-- ACTIONS DU PANIER -->
                <div class="cart-actions" id="cart-actions" style="display: none;">
                    <div class="cart-actions-left">
                        <button class="action-btn secondary" onclick="manualRefresh()">
                            🔄 Actualiser
                        </button>
                        <button class="action-btn danger" onclick="clearCart()" id="clear-cart-btn">
                            🗑️ Vider le panier
                        </button>
                    </div>
                    <div class="cart-actions-right">
                        <a href="login.php" class="action-btn primary" id="checkout-btn" style="display: none;">
                            ✅ Commander
                        </a>
                    </div>
                </div>
                
                <div id="message-container"></div>
            </div>
        </div>
    </div>

    <script>
        // ===== ARCHITECTURE AVEC CODES PROMO (VERSION CORRIGÉE) =====
        
        class DatabaseCartSyncWithPromo {
            constructor() {
                this.sessionId = 'promo_' + Date.now() + '_' + Math.random().toString(36).substring(2, 5);
                this.notificationKey = 'cart_db_notification';
                this.isLoading = false;
                this.csrfToken = null;
                this.apiEndpoints = {
                    getCart: 'get_cart_api.php',
                    updateQuantity: 'update_quantity_api.php',
                    addProduct: 'add_to_cart_api.php',
                    clearCart: 'clear_cart_api.php',
                    applyDiscount: 'apply_discount_api.php',
                    removeDiscount: 'remove_discount_api.php',
                    removeItem: 'remove_item_api.php'
                };
                
                this.init();
            }

            async init() {
                this.log('🚀 Database Cart Sync avec Codes Promo démarré', 'success');
                this.log('Session: ' + this.sessionId, 'info');
                
                // Afficher l'ID de session
                document.getElementById('session-id').textContent = this.sessionId;
                
                // Écouter les notifications entre onglets
                window.addEventListener('storage', (e) => {
                    if (e.key === this.notificationKey && e.newValue) {
                        this.handleNotification(e.newValue);
                    }
                });
                
                // Rechargement post-connexion
                window.addEventListener('storage', (e) => {
                    if (e.key === 'force_reload_after_login' && e.newValue) {
                        const notification = JSON.parse(e.newValue);
                        if (!window.location.href.includes('login.php')) {
                            this.log('🔄 Utilisateur connecté → Rechargement automatique', 'success');
                            this.showMessage('Connexion détectée, synchronisation...', 'info');
                            setTimeout(() => window.location.reload(), 1000);
                        }
                    }
                });
                
                // Rechargement post-déconnexion
                window.addEventListener('storage', (e) => {
                    if (e.key === 'force_reload_after_logout' && e.newValue) {
                        const notification = JSON.parse(e.newValue);
                        if (!window.location.href.includes('logout.php')) {
                            this.log('🚪 Utilisateur déconnecté → Rechargement automatique', 'success');
                            this.showMessage('Déconnexion détectée, synchronisation...', 'info');
                            setTimeout(() => window.location.reload(), 1000);
                        }
                    }
                });
                
                // Configurer les événements
                this.setupEventListeners();
                
                // Obtenir le token CSRF et charger les données
                await this.initializeCSRF();
                await this.loadFromDatabase();
                
                this.log('✅ Système initialisé avec codes promo', 'success');
            }

            // ===== ÉVÉNEMENTS =====
            
            setupEventListeners() {
                // Bouton Appliquer code promo
                document.getElementById('apply-promo-btn').addEventListener('click', () => this.applyPromoCode());
                
                // Enter dans le champ code promo
                document.getElementById('promo-input').addEventListener('keypress', (e) => {
                    if (e.key === 'Enter') {
                        this.applyPromoCode();
                    }
                });
                
                // Auto-uppercase dans le champ
                document.getElementById('promo-input').addEventListener('input', (e) => {
                    e.target.value = e.target.value.toUpperCase();
                });
                
                // Boutons quantité et suppression
                this.setupQuantityButtons();
            }

            // ===== GESTION CSRF (CORRIGÉE) =====
            
            async initializeCSRF() {
                try {
                    this.log('🔐 Récupération token CSRF...', 'info');
                    
                    const response = await fetch('get_csrf_token.php', {
                        method: 'GET',
                        credentials: 'same-origin',
                        headers: {
                            'X-Requested-With': 'XMLHttpRequest'
                        }
                    });
                    
                    if (response.ok) {
                        const data = await response.json();
                        if (data.success) {
                            this.csrfToken = data.token;
                            this.log('✅ Token CSRF obtenu: ' + data.token.substring(0, 10) + '...', 'success');
                        } else {
                            throw new Error(data.message || 'Erreur serveur token CSRF');
                        }
                    } else {
                        throw new Error(`HTTP ${response.status}: ${response.statusText}`);
                    }
                } catch (error) {
                    this.log('❌ Erreur CSRF: ' + error.message, 'error');
                    // PAS DE FALLBACK - Désactiver les fonctionnalités
                    this.csrfToken = null;
                    this.showMessage('Erreur de sécurité - Rechargez la page', 'error');
                }
            }

            // ===== CODES PROMO =====
            
            async applyPromoCode() {
                if (!this.csrfToken) {
                    this.showMessage('Erreur de sécurité - Rechargez la page', 'error');
                    return;
                }
                
                const promoInput = document.getElementById('promo-input');
                const applyBtn = document.getElementById('apply-promo-btn');
                const promoCode = promoInput.value.trim().toUpperCase();
                
                if (!promoCode) {
                    this.showMessage('Veuillez saisir un code promo', 'error');
                    return;
                }
                
                if (!/^[A-Z0-9]{2,20}$/.test(promoCode)) {
                    this.showMessage('Format de code promo invalide', 'error');
                    return;
                }
                
                this.setButtonLoading(applyBtn, true, 'Vérification...');
                
                try {
                    const response = await fetch(this.apiEndpoints.applyDiscount, {
                        method: 'POST',
                        headers: {
                            'Content-Type': 'application/x-www-form-urlencoded',
                            'X-Requested-With': 'XMLHttpRequest'
                        },
                        body: new URLSearchParams({
                            csrf_token: this.csrfToken,
                            discount_code: promoCode
                        })
                    });
                    
                    const data = await response.json();
                    
                    if (data.success) {
                        this.log(`✅ Code promo appliqué: ${promoCode}`, 'success');
                        this.showMessage(`Code ${promoCode} appliqué ! -${data.data.discount_amount.toFixed(2)}€`, 'success');
                        
                        promoInput.value = '';
                        await this.loadFromDatabase();
                        
                        this.sendNotification('discount_applied', null, {
                            code: promoCode,
                            amount: data.data.discount_amount
                        });
                        
                    } else {
                        throw new Error(data.message || 'Erreur application code promo');
                    }
                    
                } catch (error) {
                    this.log(`❌ Erreur code promo: ${error.message}`, 'error');
                    this.showMessage('Erreur: ' + error.message, 'error');
                } finally {
                    this.setButtonLoading(applyBtn, false, 'Appliquer');
                }
            }
            
            async removePromoCode() {
                if (!this.csrfToken) {
                    this.showMessage('Erreur de sécurité - Rechargez la page', 'error');
                    return;
                }
                
                this.log('🗑️ Suppression code promo...', 'warning');
                
                try {
                    const response = await fetch(this.apiEndpoints.removeDiscount, {
                        method: 'POST',
                        headers: {
                            'Content-Type': 'application/x-www-form-urlencoded',
                            'X-Requested-With': 'XMLHttpRequest'
                        },
                        body: new URLSearchParams({
                            csrf_token: this.csrfToken
                        })
                    });
                    
                    const data = await response.json();
                    
                    if (data.success) {
                        this.log('✅ Code promo supprimé', 'success');
                        this.showMessage('Code promo retiré', 'success');
                        
                        await this.loadFromDatabase();
                        
                        this.sendNotification('discount_removed', null, {
                            removed_code: data.data?.removed_code || 'unknown',
                            removed_amount: data.data?.removed_amount || 0
                        });
                        
                    } else {
                        throw new Error(data.message || 'Erreur suppression code promo');
                    }
                    
                } catch (error) {
                    this.log(`❌ Erreur suppression: ${error.message}`, 'error');
                    this.showMessage('Erreur: ' + error.message, 'error');
                }
            }

            // ===== SUPPRESSION ARTICLE =====
            
            async removeItem(productId, productName) {
                if (!confirm(`Êtes-vous sûr de vouloir supprimer "${productName}" de votre panier ?`)) {
                    return;
                }
                
                if (!this.csrfToken) {
                    this.showMessage('Erreur de sécurité - Rechargez la page', 'error');
                    return;
                }
                
                this.log(`🗑️ Suppression article ${productId}...`, 'warning');
                
                try {
                    const response = await fetch(this.apiEndpoints.removeItem, {
                        method: 'POST',
                        headers: {
                            'Content-Type': 'application/x-www-form-urlencoded',
                            'X-Requested-With': 'XMLHttpRequest'
                        },
                        body: new URLSearchParams({
                            csrf_token: this.csrfToken,
                            product_id: productId
                        })
                    });
                    
                    const data = await response.json();
                    
                    if (data.success) {
                        this.log('✅ Article supprimé', 'success');
                        this.showMessage('Article supprimé du panier', 'success');
                        
                        await this.loadFromDatabase();
                        
                        this.sendNotification('item_removed', productId, {
                            product_name: productName
                        });
                        
                    } else {
                        throw new Error(data.message || 'Erreur suppression article');
                    }
                    
                } catch (error) {
                    this.log(`❌ Erreur suppression: ${error.message}`, 'error');
                    this.showMessage('Erreur: ' + error.message, 'error');
                }
            }

            // ===== AFFICHAGE CODES PROMO =====
            
            updatePromoDisplay(discountInfo) {
                const formContainer = document.getElementById('promo-form-container');
                const appliedContainer = document.getElementById('promo-applied-container');
                
                if (!discountInfo) {
                    formContainer.style.display = 'block';
                    appliedContainer.style.display = 'none';
                    this.log('📋 Affichage: Formulaire code promo (aucun code appliqué)', 'info');
                } else {
                    formContainer.style.display = 'none';
                    appliedContainer.style.display = 'block';
                    
                    appliedContainer.innerHTML = `
                        <div class="promo-applied">
                            <div class="promo-info">
                                <div class="promo-code">✅ Code ${discountInfo.code} appliqué</div>
                                <div class="promo-savings">
                                    Économie: ${discountInfo.amount.toFixed(2)} € 
                                    ${discountInfo.type === 'percent' ? `(-${discountInfo.value}%)` : '(montant fixe)'}
                                </div>
                            </div>
                            <button class="remove-promo-btn" onclick="cartSync.removePromoCode()">
                                Retirer
                            </button>
                        </div>
                    `;
                    
                    this.log(`📋 Affichage: Code promo ${discountInfo.code} appliqué (-${discountInfo.amount.toFixed(2)}€)`, 'success');
                }
            }

            // ===== COMMUNICATION BASE DE DONNÉES =====
            
            async loadFromDatabase(source = 'initial') {
                if (this.isLoading) {
                    this.log('⏳ Chargement déjà en cours...', 'warning');
                    return;
                }
                
                this.isLoading = true;
                this.setLoadingState(true);
                
                this.log(`🔄 Chargement depuis base de données (${source})...`, 'info');
                
                try {
                    const response = await fetch(this.apiEndpoints.getCart, {
                        method: 'GET',
                        credentials: 'same-origin',
                        headers: {
                            'X-Requested-With': 'XMLHttpRequest'
                        }
                    });
                    
                    if (!response.ok) {
                        throw new Error(`HTTP ${response.status}: ${response.statusText}`);
                    }
                    
                    const data = await response.json();
                    
                    if (data.success) {
                        this.updateDisplay(data.data);
                        this.log('✅ Données chargées depuis MySQL avec codes promo', 'success');
                    } else {
                        throw new Error(data.message || 'Erreur serveur');
                    }
                    
                } catch (error) {
                    this.log('❌ Erreur chargement DB: ' + error.message, 'error');
                    this.showMessage('Erreur de connexion à la base de données', 'error');
                } finally {
                    this.isLoading = false;
                    this.setLoadingState(false);
                }
            }

            updateDisplay(serverResponse) {
                if (!serverResponse) {
                    this.log('❌ Réponse serveur invalide', 'error');
                    return;
                }
                
                const container = document.getElementById('cart-items');
                const totalsContainer = document.getElementById('cart-totals');
                const actionsContainer = document.getElementById('cart-actions');
                const checkoutBtn = document.getElementById('checkout-btn');
                
                // Reconstruire l'affichage des articles
                container.innerHTML = '';
                
                if (!serverResponse.items || Object.keys(serverResponse.items).length === 0) {
                    container.innerHTML = `
                        <div class="empty-cart">
                            <div class="icon">🛒</div>
                            <div>Votre panier est vide</div>
                            <p style="margin-top: 10px; font-size: 1rem;">
                                <a href="boutique.php" style="color: #007bff; text-decoration: none;">
                                    Découvrez nos produits
                                </a>
                            </p>
                        </div>
                    `;
                    totalsContainer.style.display = 'none';
                    actionsContainer.style.display = 'none';
                    checkoutBtn.style.display = 'none';
                    this.updatePromoDisplay(null);
                    return;
                }
                
                // Construire les articles - STRUCTURE ORIGINALE RESTAURÉE
                for (let productId in serverResponse.items) {
                    const item = serverResponse.items[productId];
                    const subtotal = item.price * item.quantity;
                    
                    const itemDiv = document.createElement('div');
                    itemDiv.className = 'cart-item';
                    itemDiv.dataset.productId = productId;
                    itemDiv.innerHTML = `
                        <div class="item-info">
                            <h4>${item.name || 'Produit #' + productId}</h4>
                            <div class="item-price">${item.price.toFixed(2)} € × ${item.quantity} = ${subtotal.toFixed(2)} €</div>
                            <div class="item-details">
                                ${item.reference ? 'Réf: ' + item.reference + ' | ' : ''}
                                Stock: ${item.stock || 'N/A'} | 
                                Poids: ${item.weight || 0}g
                            </div>
                        </div>
                        <div class="item-actions">
                            <div class="quantity-controls">
                                <button class="quantity-btn decrease" data-product-id="${productId}" data-action="decrease">−</button>
                                <span class="quantity-display">${item.quantity}</span>
                                <button class="quantity-btn increase" data-product-id="${productId}" data-action="increase">+</button>
                            </div>
                            <button class="delete-btn" data-product-id="${productId}" data-product-name="${item.name || 'Produit #' + productId}" title="Supprimer cet article">
                                🗑️
                            </button>
                        </div>
                    `;
                    
                    container.appendChild(itemDiv);
                }
                
                // Afficher et mettre à jour les totaux
                totalsContainer.style.display = 'block';
                actionsContainer.style.display = 'flex';
                this.updateTotalsDisplay(serverResponse);
                
                // Afficher le bouton commander si le panier n'est pas vide
                checkoutBtn.style.display = 'inline-flex';
                
                this.log(`🔄 Affichage mis à jour (${Object.keys(serverResponse.items).length} items)`, 'info');
            }

            updateTotalsDisplay(cartData) {
                const subtotalElement = document.getElementById('cart-subtotal');
                const discountLine = document.getElementById('discount-line');
                const discountText = document.getElementById('discount-text');
                const discountAmount = document.getElementById('discount-amount');
                const totalElement = document.getElementById('cart-total');
                
                if (!cartData.totals) return;
                
                // Sous-total
                if (subtotalElement) {
                    subtotalElement.textContent = cartData.totals.subtotal.toFixed(2) + ' €';
                }
                
                // Ligne de réduction
                if (cartData.discount_info && discountLine) {
                    discountLine.style.display = 'flex';
                    if (discountText) discountText.textContent = `Code ${cartData.discount_info.code}:`;
                    if (discountAmount) discountAmount.textContent = `-${cartData.discount_info.amount.toFixed(2)} €`;
                } else if (discountLine) {
                    discountLine.style.display = 'none';
                }
                
                // Total final
                if (totalElement) {
                    const total = cartData.totals.total_after_discount;
                    totalElement.textContent = total.toFixed(2) + ' €';
                    
                    // Animation
                    totalElement.parentElement.classList.add('updated');
                    setTimeout(() => {
                        totalElement.parentElement.classList.remove('updated');
                    }, 500);
                }
                
                // Mettre à jour l'affichage des codes promo
                this.updatePromoDisplay(cartData.discount_info);
            }

            // ===== GESTION DES NOTIFICATIONS =====
            
            sendNotification(action, productId = null, metadata = {}) {
                const notification = {
                    sessionId: this.sessionId,
                    timestamp: Date.now(),
                    action: action,
                    productId: productId,
                    metadata: metadata,
                    source: 'main_cart'
                };
                
                localStorage.setItem(this.notificationKey, JSON.stringify(notification));
                this.log(`📢 Notification envoyée: ${action}`, 'warning');
            }

            handleNotification(jsonData) {
                try {
                    const notification = JSON.parse(jsonData);
                    
                    // Ignorer nos propres notifications
                    if (notification.sessionId === this.sessionId) {
                        this.log('🛑 Notification ignorée (même session)', 'info');
                        return;
                    }
                    
                    this.log(`📨 Notification reçue: ${notification.action} de ${notification.sessionId}`, 'success');
                    
                    // Recharger depuis la base de données
                    this.loadFromDatabase('notification_received');
                    
                    // Message spécifique selon l'action
                    let message = 'Panier synchronisé';
                    if (notification.action.includes('discount')) {
                        message = 'Code promo synchronisé';
                    } else if (notification.action.includes('removed')) {
                        message = 'Article supprimé dans un autre onglet';
                    }
                    
                    this.showMessage(message, 'info');
                    
                } catch (error) {
                    this.log('❌ Erreur notification: ' + error.message, 'error');
                }
            }
            
            // ===== MÉTHODES PANIER =====
            
            async clearCartInDatabase() {
                if (!confirm('Êtes-vous sûr de vouloir vider votre panier ?')) {
                    return { success: false, cancelled: true };
                }
                
                if (!this.csrfToken) {
                    this.showMessage('Erreur de sécurité - Rechargez la page', 'error');
                    return { success: false, error: 'Pas de token CSRF' };
                }
                
                this.log('🗑️ DB CLEAR: Vidage panier', 'info');
                
                try {
                    const response = await fetch(this.apiEndpoints.clearCart, {
                        method: 'POST',
                        credentials: 'same-origin',
                        headers: {
                            'Content-Type': 'application/x-www-form-urlencoded',
                            'X-Requested-With': 'XMLHttpRequest'
                        },
                        body: new URLSearchParams({
                            csrf_token: this.csrfToken,
                            return_page: 'api'
                        })
                    });
                    
                    const data = await response.json();
                    
                    if (data.success) {
                        this.log('✅ Panier vidé en DB', 'success');
                        return { success: true };
                    } else {
                        throw new Error(data.message || 'Erreur vidage panier');
                    }
                    
                } catch (error) {
                    this.log(`❌ Erreur vidage DB: ${error.message}`, 'error');
                    return { success: false, error: error.message };
                }
            }

            async addProductToDatabase(productId) {
                if (!this.csrfToken) {
                    this.showMessage('Erreur de sécurité - Rechargez la page', 'error');
                    return { success: false, error: 'Pas de token CSRF' };
                }
                
                this.log(`➕ DB ADD: Ajout produit ${productId}`, 'info');
                
                try {
                    const response = await fetch(this.apiEndpoints.addProduct, {
                        method: 'POST',
                        credentials: 'same-origin',
                        headers: {
                            'Content-Type': 'application/x-www-form-urlencoded',
                            'X-Requested-With': 'XMLHttpRequest'
                        },
                        body: new URLSearchParams({
                            csrf_token: this.csrfToken,
                            product_id: productId,
                            quantity: 1,
                            return_page: 'api'
                        })
                    });
                    
                    const data = await response.json();
                    
                    if (data.success) {
                        this.log(`✅ Produit ajouté en DB: ${data.message}`, 'success');
                        return { success: true, data: data };
                    } else {
                        throw new Error(data.message || 'Erreur ajout produit');
                    }
                    
                } catch (error) {
                    this.log(`❌ Erreur ajout DB: ${error.message}`, 'error');
                    return { success: false, error: error.message };
                }
            }

            // ===== MÉTHODES UTILITAIRES (STRUCTURE ORIGINALE RESTAURÉE) =====
            
            setupQuantityButtons() {
                document.addEventListener('click', async (e) => {
                    // Gestion des boutons quantité - LOGIQUE ORIGINALE
                    if (e.target.matches('.quantity-btn') && 
                        e.target.dataset.productId && 
                        e.target.dataset.action) {
                        
                        e.preventDefault();
                        e.stopPropagation();
                        
                        const productId = e.target.dataset.productId;
                        const action = e.target.dataset.action;
                        
                        this.log(`👆 CLIC: ${action} produit ${productId}`, 'warning');
                        
                        // Désactiver le bouton pendant la requête
                        const itemElement = e.target.closest('.cart-item');
                        this.setItemUpdating(itemElement, true);
                        e.target.classList.add('processing');
                        e.target.disabled = true;
                        
                        try {
                            const result = await this.updateQuantityInDatabase(productId, action);
                            
                            if (result.success) {
                                await this.loadFromDatabase('quantity_update');
                                this.sendNotification(`quantity_${action}`, productId, result.data);
                                this.log(`🎯 Mise à jour complète: ${action} produit ${productId}`, 'success');
                                this.showMessage(`Quantité mise à jour avec succès`, 'success');
                            } else {
                                this.log(`❌ Échec mise à jour: ${result.error}`, 'error');
                                this.showMessage(`Erreur: ${result.error}`, 'error');
                            }
                            
                        } catch (error) {
                            this.log(`❌ Erreur critique: ${error.message}`, 'error');
                            this.showMessage(`Erreur critique: ${error.message}`, 'error');
                        } finally {
                            this.setItemUpdating(itemElement, false);
                            e.target.classList.remove('processing');
                            e.target.disabled = false;
                        }
                    }
                    
                    // Gestion des boutons suppression (corbeille)
                    if (e.target.matches('.delete-btn') && e.target.dataset.productId) {
                        e.preventDefault();
                        e.stopPropagation();
                        
                        const productId = e.target.dataset.productId;
                        const productName = e.target.dataset.productName;
                        
                        this.log(`🗑️ CLIC: Suppression produit ${productId}`, 'warning');
                        
                        // Désactiver le bouton pendant la requête
                        e.target.classList.add('processing');
                        e.target.disabled = true;
                        
                        try {
                            await this.removeItem(productId, productName);
                        } catch (error) {
                            this.log(`❌ Erreur suppression: ${error.message}`, 'error');
                            this.showMessage(`Erreur: ${error.message}`, 'error');
                        } finally {
                            e.target.classList.remove('processing');
                            e.target.disabled = false;
                        }
                    }
                });
            }

            async updateQuantityInDatabase(productId, action) {
                if (!this.csrfToken) {
                    return { success: false, error: 'Pas de token CSRF' };
                }
                
                this.log(`🗄️ DB UPDATE: ${action} produit ${productId}`, 'info');
                
                try {
                    const response = await fetch(this.apiEndpoints.updateQuantity, {
                        method: 'POST',
                        credentials: 'same-origin',
                        headers: {
                            'Content-Type': 'application/x-www-form-urlencoded',
                            'X-Requested-With': 'XMLHttpRequest'
                        },
                        body: new URLSearchParams({
                            csrf_token: this.csrfToken,
                            product_id: productId,
                            action: action,
                            return_page: 'api'
                        })
                    });
                    
                    if (!response.ok) {
                        throw new Error(`HTTP ${response.status}: ${response.statusText}`);
                    }
                    
                    const data = await response.json();
                    
                    if (data.success) {
                        this.log(`✅ DB UPDATE réussi: ${data.message}`, 'success');
                        return { success: true, data: data };
                    } else {
                        throw new Error(data.message || 'Erreur mise à jour');
                    }
                    
                } catch (error) {
                    this.log(`❌ Erreur DB UPDATE: ${error.message}`, 'error');
                    return { success: false, error: error.message };
                }
            }

            setItemUpdating(itemElement, updating) {
                if (updating) {
                    itemElement.classList.add('updating');
                } else {
                    itemElement.classList.remove('updating');
                    
                    // Animation de mise à jour réussie
                    const quantityDisplay = itemElement.querySelector('.quantity-display');
                    if (quantityDisplay) {
                        quantityDisplay.classList.add('updated');
                        setTimeout(() => {
                            quantityDisplay.classList.remove('updated');
                        }, 500);
                    }
                }
            }

            setLoadingState(loading) {
                const container = document.querySelector('.cart-section');
                const statusElement = document.getElementById('connection-status');
                const sessionElement = document.getElementById('session-id');
                
                if (loading) {
                    if (container) container.classList.add('loading');
                    if (statusElement) {
                        statusElement.className = 'status-indicator status-syncing';
                        statusElement.innerHTML = '🟡 Synchronisation... Session: ' + (sessionElement ? sessionElement.textContent : this.sessionId);
                    }
                } else {
                    if (container) container.classList.remove('loading');
                    if (statusElement) {
                        statusElement.className = 'status-indicator status-online';
                        statusElement.innerHTML = '🟢 Connecté - Session: ' + (sessionElement ? sessionElement.textContent : this.sessionId);
                    }
                }
            }

            setButtonLoading(button, loading, text = null) {
                if (loading) {
                    button.disabled = true;
                    button.classList.add('processing');
                    if (text) button.textContent = text;
                } else {
                    button.disabled = false;
                    button.classList.remove('processing');
                    if (text) button.textContent = text;
                }
            }

            showMessage(text, type = 'info') {
                const container = document.getElementById('message-container');
                const messageDiv = document.createElement('div');
                messageDiv.className = type === 'error' ? 'error-message' : 'success-message';
                messageDiv.textContent = text;
                
                container.appendChild(messageDiv);
                
                setTimeout(() => {
                    if (messageDiv.parentElement) {
                        messageDiv.remove();
                    }
                }, 5000);
            }

            log(message, type = 'info') {
                const timestamp = new Date().toLocaleTimeString();
                const prefix = `[${timestamp}] [CartSync]`;
                
                switch(type) {
                    case 'error':
                        console.error(`${prefix} ❌ ${message}`);
                        break;
                    case 'warning':
                        console.warn(`${prefix} ⚠️ ${message}`);
                        break;
                    case 'success':
                        console.log(`${prefix} ✅ ${message}`);
                        break;
                    default:
                        console.log(`${prefix} ℹ️ ${message}`);
                }
            }
        }

        // ===== FONCTIONS GLOBALES =====
        
        function manualRefresh() {
            cartSync.loadFromDatabase('manual_refresh');
        }

        async function addTestProduct() {
            cartSync.log('➕ TEST: Ajout produit test', 'warning');
            
            const result = await cartSync.addProductToDatabase(1);
            
            if (result && result.success) {
                await cartSync.loadFromDatabase('test_product_added');
                cartSync.sendNotification('product_added', 1);
                cartSync.showMessage('Produit test ajouté avec succès', 'success');
            } else {
                cartSync.showMessage('Erreur ajout produit test: ' + (result?.error || 'Inconnue'), 'error');
            }
        }

        async function clearCart() {
            cartSync.log('🗑️ Demande vidage panier', 'warning');
            
            const result = await cartSync.clearCartInDatabase();
            
            if (result && result.success) {
                await cartSync.loadFromDatabase('cart_cleared');
                cartSync.sendNotification('cart_cleared');
                cartSync.showMessage('Panier vidé avec succès', 'success');
            } else if (result && !result.cancelled) {
                cartSync.showMessage('Erreur vidage panier: ' + (result?.error || 'Inconnue'), 'error');
            }
        }

        // ===== INITIALISATION (VARIABLE ORIGINALE RESTAURÉE) =====
        
        const cartSync = new DatabaseCartSyncWithPromo();

        // Debug pour développement
        window.cartSync = cartSync;
        console.log('🔧 Database Cart Sync avec Codes Promo chargé, accessible via window.cartSync');

    </script>
</body>
</html>