"use strict";

(function() {
    /*
		This file shows how client-side javascript can be included via a plugin.
		If you check `plugin.json`, you'll see that this file is listed under "scripts".
		That array tells NodeBB which files to bundle into the minified javascript
		that is served to the end user.
		Some events you can elect to listen for:
		$(document).ready();			Fired when the DOM is ready
		$(window).on('action:ajaxify.end', function(data) { ... });			"data" contains "url"
	*/

    $(document).ready(function() {
        app.logout = function() {
            require(['csrf'], function(csrf) {
                $.ajax(config.relative_path + '/logout', {
                    type: 'POST',
                    headers: {
                        'x-csrf-token': csrf.get()
                    },
                    success: function() {
                        window.location.href = config.keycloak.logoutUrl + '?redirect_uri='+ encodeURIComponent(window.location.origin + '/');
                    }
                });
            });
        };
    });


    console.log('nodebb-plugin-sso-openidconnect: loaded');
    // Note how this is shown in the console on the first load of every page
}());


// ?redirect_uri=http%3A%2F%2Flocalhost%3A8000%2F