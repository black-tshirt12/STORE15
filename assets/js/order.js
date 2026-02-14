// Order Form Handling – localStorage + Orders API (GitHub Pages / Vercel compatible)
// Mobile-safe: programmatic preventDefault, Store.ready before API URL, detailed logging, no redirect until request completes.
(function () {
  var submitInProgress = false;

  function log() {
    if (typeof console !== 'undefined' && console.log) {
      console.log.apply(console, ['[order]'].concat(Array.prototype.slice.call(arguments)));
    }
  }

  function logError() {
    if (typeof console !== 'undefined' && console.error) {
      console.error.apply(console, ['[order]'].concat(Array.prototype.slice.call(arguments)));
    }
  }

  window.proceedToCheckout = function () {
    var cartItems = window.getCartData && window.getCartData();
    if (!cartItems || cartItems.length === 0) {
      alert('Your cart is empty');
      return;
    }
    try {
      sessionStorage.setItem('checkoutCart', JSON.stringify(cartItems));
    } catch (e) {
      log('sessionStorage set failed', e);
    }
    window.location.href = './order.html';
  };

  function validateOrderForm() {
    var form = document.getElementById('order-form');
    if (!form) return false;

    var fullName = (form.querySelector('[name="fullName"]') || {}).value;
    var phone = (form.querySelector('[name="phone"]') || {}).value;
    var city = (form.querySelector('[name="city"]') || {}).value;

    fullName = fullName ? fullName.trim() : '';
    phone = phone ? phone.trim() : '';
    city = city ? city.trim() : '';

    if (!fullName) {
      alert('Please enter your full name');
      return false;
    }
    if (!phone) {
      alert('Please enter your phone number');
      return false;
    }
    if (!/^[0-9+\s-]+$/.test(phone)) {
      alert('Please enter a valid phone number');
      return false;
    }
    if (!city) {
      alert('Please enter your city');
      return false;
    }
    var cartRaw = '';
    try { cartRaw = sessionStorage.getItem('checkoutCart') || '[]'; } catch (e) {}
    var items = [];
    try { items = JSON.parse(cartRaw); } catch (e) {}
    if (!items || items.length === 0) {
      alert('Your cart is empty. Please add products before checkout.');
      return false;
    }
    return true;
  }

  function buildOrderPayload() {
    var form = document.getElementById('order-form');
    var formData = form ? new FormData(form) : null;
    var cartRaw = '';
    try {
      cartRaw = sessionStorage.getItem('checkoutCart') || '[]';
    } catch (e) {
      log('sessionStorage get failed', e);
    }
    var items = [];
    try {
      items = JSON.parse(cartRaw);
    } catch (e) {
      log('parse checkoutCart failed', e);
    }
    var total = (window.getCartTotal && window.getCartTotal()) || 0;

    return {
      fullName: formData ? formData.get('fullName') : '',
      phone: formData ? formData.get('phone') : '',
      city: formData ? formData.get('city') : '',
      notes: (formData && formData.get('notes')) || '',
      items: items,
      total: total,
      date: new Date().toISOString()
    };
  }

  function saveOrderToLocalStore(orderData) {
    if (typeof Store !== 'undefined' && Store.addOrder) {
      try {
        Store.addOrder(orderData);
        log('Order saved to localStorage (Store.addOrder)');
        return true;
      } catch (e) {
        logError('Store.addOrder failed', e);
      }
    } else {
      log('Store not available (store.js not loaded?)');
    }
    return false;
  }

  function finishOrderSuccess(localOnly) {
    if (window.clearCartAfterOrder) window.clearCartAfterOrder();
    try {
      sessionStorage.removeItem('checkoutCart');
    } catch (e) {}
    var msg;
    if (localOnly) {
      msg = (typeof t !== 'undefined' && t('orderSuccessLocal')) ? t('orderSuccessLocal') : 'Order saved. We will contact you to confirm. If you do not hear from us, please contact us directly.';
    } else {
      msg = (typeof t !== 'undefined' && t('orderSuccess')) ? t('orderSuccess') : 'Order submitted successfully! We will contact you soon.';
    }
    alert(msg);
    window.location.href = './';
  }

  function finishOrderFailure(msg) {
    var submitBtn = document.getElementById('submit-order-btn');
    if (submitBtn) {
      submitBtn.disabled = false;
      submitBtn.textContent = (typeof t !== 'undefined' && t('confirmOrder')) ? t('confirmOrder') : 'Confirm Order';
    }
    alert(msg || 'Unable to submit order. Please try again or contact us.');
  }

  /**
   * POST order to Orders API. Returns a promise that resolves to true on success, false on failure.
   * Uses a timeout (20s) so slow mobile networks don't hang indefinitely.
   * @param {string} apiUrl - Full API URL (must be HTTPS in production for mobile)
   * @param {object} orderData - Order payload to send
   */
  function sendOrderToApi(apiUrl, orderData) {
    var url = (apiUrl || '').replace(/\/+$/, '');
    if (!url || !/^https?:\/\//i.test(url)) {
      log('sendOrderToApi: no valid API URL', apiUrl);
      return Promise.resolve(false);
    }
    // Prefer HTTPS when page is HTTPS (avoids mixed-content block on mobile)
    if (typeof location !== 'undefined' && location.protocol === 'https:' && /^http:\/\//i.test(url)) {
      url = url.replace(/^http:\/\//i, 'https://');
      log('sendOrderToApi: upgraded to HTTPS', url);
    }

    var bodyString;
    try {
      bodyString = JSON.stringify(orderData);
    } catch (e) {
      logError('JSON.stringify(orderData) failed', e);
      return Promise.resolve(false);
    }

    log('Request: POST', url, 'Content-Type: application/json', 'body length:', bodyString.length);
    log('Request body (keys):', Object.keys(orderData || {}));

    var timeoutMs = 20000;
    var controller = null;
    if (typeof AbortController !== 'undefined') {
      controller = new AbortController();
      setTimeout(function () {
        if (controller) controller.abort();
      }, timeoutMs);
    }

    var fetchOpts = {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Accept': 'application/json'
      },
      body: bodyString
    };
    if (controller && controller.signal) fetchOpts.signal = controller.signal;

    return fetch(url, fetchOpts)
      .then(function (r) {
        var status = r.status;
        var statusText = r.statusText;
        log('Response:', status, statusText, 'Content-Type:', r.headers.get('Content-Type'));
        return r.text().then(function (text) {
          try {
            var json = text ? JSON.parse(text) : {};
            log('Response body:', json);
          } catch (e) {
            log('Response body (raw):', text ? text.slice(0, 200) : '(empty)');
          }
          if (!r.ok) {
            logError('Orders API error', status, statusText, text ? text.slice(0, 300) : '');
            return false;
          }
          log('Orders API success');
          return true;
        });
      })
      .catch(function (err) {
        var isTimeout = (err && err.name === 'AbortError') || (err && err.message && err.message.indexOf('abort') !== -1);
        if (isTimeout) logError('Orders API request timed out after', timeoutMs / 1000, 's');
        else logError('Orders API request failed (network/CORS/other)', err && err.message ? err.message : err);
        return false;
      });
  }

  /** Get fallback Orders API URL from page (meta or form data attribute) so it works even if store-data hasn't loaded. */
  function getFallbackOrdersApiUrl() {
    try {
      var raw = null;
      var meta = document.querySelector('meta[name="orders-api-url"]');
      if (meta && meta.getAttribute('content')) raw = (meta.getAttribute('content') || '').trim();
      if (!raw) {
        var form = document.getElementById('order-form');
        if (form && form.getAttribute('data-orders-api-url')) raw = (form.getAttribute('data-orders-api-url') || '').trim();
      }
      if (raw && /^https?:\/\//i.test(raw)) return raw;
      // Same-origin fallback: when site and API are on same host (e.g. Vercel static + api/, or Next.js), use /api/orders so mobile always has a URL
      if (typeof location !== 'undefined' && location.origin) {
        var sameOrigin = location.origin + '/api/orders';
        log('Fallback: using same-origin Orders API URL', sameOrigin);
        return sameOrigin;
      }
    } catch (e) {
      logError('getFallbackOrdersApiUrl error', e);
    }
    return null;
  }

  var SESSION_API_URL_KEY = 'orderApiUrlCache';

  /**
   * Resolve the Orders API URL, waiting for Store.ready so remote store-data.json
   * (which contains ordersApiUrl) has been applied. On mobile, sync can be slow or
   * fail (wrong base path); retry once and use page fallback if still missing.
   * Caches resolved URL in sessionStorage for the rest of the session so a second
   * submit or slow Store doesn't lose the URL.
   */
  function getOrdersApiUrlWhenReady() {
    return Promise.resolve().then(function () {
      try {
        var cached = sessionStorage.getItem(SESSION_API_URL_KEY);
        if (cached && /^https?:\/\//i.test(cached)) {
          log('Orders API URL from session cache');
          return cached.trim();
        }
      } catch (e) {}
      if (typeof Store === 'undefined' || !Store.getOrdersApiUrl) return getFallbackOrdersApiUrl();
      var tryGet = function () {
        var url = (Store.getOrdersApiUrl() || '').trim();
        return (url && /^https?:\/\//i.test(url)) ? url : null;
      };
      var waitStore = (Store.ready && typeof Store.ready.then === 'function') ? Store.ready : Promise.resolve();
      return waitStore.then(function () {
        var url = tryGet();
        if (url) {
          try { sessionStorage.setItem(SESSION_API_URL_KEY, url); } catch (e) {}
          return url;
        }
        // Retry once: refresh store-data (fixes slow/failed fetch on mobile) then re-check
        if (typeof Store !== 'undefined' && Store.refreshFromRemote) {
          return Store.refreshFromRemote().then(function () {
            var again = tryGet();
            if (again) {
              try { sessionStorage.setItem(SESSION_API_URL_KEY, again); } catch (e) {}
              return again;
            }
            var fallback = getFallbackOrdersApiUrl();
            if (fallback) {
              try { sessionStorage.setItem(SESSION_API_URL_KEY, fallback); } catch (e) {}
              log('Orders API URL from fallback (after retry)', fallback);
            } else {
              logError('No Orders API URL: Store, meta, form, and same-origin fallback all empty. Set meta name="orders-api-url" or data-orders-api-url on form for mobile.');
            }
            return fallback;
          });
        }
        var fallback = getFallbackOrdersApiUrl();
        if (fallback) {
          try { sessionStorage.setItem(SESSION_API_URL_KEY, fallback); } catch (e) {}
          log('Orders API URL from fallback', fallback);
        } else {
          logError('No Orders API URL available. Orders will save to localStorage only. Set meta name="orders-api-url" or data-orders-api-url for mobile.');
        }
        return fallback;
      });
    });
  }

  function handleSubmit(event) {
    if (event && event.preventDefault) event.preventDefault();

    if (submitInProgress) {
      log('Submit ignored (already in progress)');
      return;
    }
    if (!validateOrderForm()) return;

    var orderData;
    try {
      orderData = buildOrderPayload();
    } catch (e) {
      logError('buildOrderPayload failed', e);
      alert('Unable to build order. Please try again.');
      return;
    }

    log('Submitting order', orderData.fullName, orderData.total, 'MAD', (orderData.items || []).length, 'items');

    var submitBtn = document.getElementById('submit-order-btn');
    var originalText = submitBtn ? submitBtn.textContent : 'Confirm Order';
    if (submitBtn) {
      submitBtn.disabled = true;
      submitBtn.textContent = (typeof t !== 'undefined' && t('submitting')) ? t('submitting') : 'Submitting...';
    }
    submitInProgress = true;

    function done(saved, localOnly) {
      submitInProgress = false;
      if (submitBtn) {
        submitBtn.disabled = false;
        submitBtn.textContent = originalText;
      }
      if (saved) {
        finishOrderSuccess(localOnly);
      } else {
        finishOrderFailure((typeof t !== 'undefined' && t('orderSaveError')) ? t('orderSaveError') : 'Order could not be saved. Please try again or contact us directly.');
      }
    }

    getOrdersApiUrlWhenReady()
      .then(function (apiUrl) {
        if (apiUrl) {
          log('Orders API URL resolved (after Store.ready):', apiUrl);
          return sendOrderToApi(apiUrl, orderData).then(function (apiOk) {
            if (apiOk) {
              done(true, false);
            } else {
              var saved = saveOrderToLocalStore(orderData);
              done(saved, true);
            }
          });
        }
        logError('No Orders API URL configured; saving to localStorage only. Set meta name="orders-api-url" or data-orders-api-url, or deploy frontend and API on same origin (e.g. /api/orders).');
        try {
          var saved = saveOrderToLocalStore(orderData);
          done(saved, true);
        } catch (err) {
          logError('Save order failed', err);
          done(false, false);
        }
      })
      .catch(function (err) {
        logError('Submit flow error', err);
        try {
          var saved = saveOrderToLocalStore(orderData);
          done(saved, true);
        } catch (e) {
          done(false, false);
        }
      });
  }

  window.submitOrder = function () {
    handleSubmit({ preventDefault: function () {} });
  };

  function formatOrderItems(items) {
    return (items || []).map(function (item) {
      return item.name + ' - Size: ' + item.size + ', Color: ' + item.color + ', Quantity: ' + item.quantity + ', Price: ' + (item.price * item.quantity) + ' MAD';
    }).join('\n');
  }

  window.formatOrderItems = formatOrderItems;

  document.addEventListener('DOMContentLoaded', function () {
    if (!window.location.pathname.includes('order.html') && !window.location.href.includes('order.html')) return;

    var form = document.getElementById('order-form');
    if (form) {
      form.addEventListener('submit', function (e) {
        e.preventDefault();
        handleSubmit(e);
      }, false);
    }

    var cartRaw = '';
    try {
      cartRaw = sessionStorage.getItem('checkoutCart') || '[]';
    } catch (e) {}
    var cartItems = [];
    try {
      cartItems = JSON.parse(cartRaw);
    } catch (e) {}
    if (cartItems.length === 0) {
      alert('Your cart is empty. Redirecting to products...');
      window.location.href = './products.html';
      return;
    }
    renderOrderSummary(cartItems);
  });

  function renderOrderSummary(items) {
    var orderItemsEl = document.getElementById('order-items');
    var orderTotalEl = document.getElementById('order-total');
    if (!orderItemsEl) return;

    orderItemsEl.innerHTML = (items || []).map(function (item, index) {
      return (
        '<div class="order-item">' +
          '<div class="order-item-number">' + (index + 1) + '</div>' +
          '<div class="order-item-details">' +
            '<h4>' + (item.name || '') + '</h4>' +
            '<p>Size: ' + (item.size || '') + ' · Color: ' + (item.color || '') + ' · Quantity: ' + (item.quantity || 0) + '</p>' +
          '</div>' +
          '<div class="order-item-price">' + ((item.price || 0) * (item.quantity || 0)) + ' MAD</div>' +
        '</div>'
      );
    }).join('');

    if (orderTotalEl && window.getCartTotal) {
      orderTotalEl.textContent = window.getCartTotal() + ' MAD';
    }
  }

  window.renderOrderSummary = renderOrderSummary;
})();
