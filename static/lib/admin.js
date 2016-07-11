'use strict';
/* globals $, define, socket */

define('admin/plugins/sso-keycloak', ['settings'], function(Settings) {

    var ACP = {};

    ACP.init = function() {

        var wrapper = $('#sso-keycloak-settings');
        Settings.sync('sso-keycloak', wrapper);

        $('#save').on('click', function() {
            event.preventDefault();
            Settings.persist('sso-keycloak', wrapper, function() {
                socket.emit('admin.settings.syncSsoKeycloak');
            });
        });
    };

    return ACP;
});
