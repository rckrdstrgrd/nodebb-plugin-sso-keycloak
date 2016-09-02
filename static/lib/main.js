"use strict";
(function() {
    $(document).ready(function() {
        if (config.keycloak) {
            app.logout = function() {
                $.ajax(config.relative_path + '/logout', {
                    type: 'POST',
                    headers: {
                        'x-csrf-token': config.csrf_token
                    },
                    success: function() {
                        window.location.href = config.keycloak.logoutUrl + '?redirect_uri=' + encodeURIComponent(window.location.origin + '/');
                    }
                });
            };
        }
    });
}());
