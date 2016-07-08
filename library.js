(function(module) {
    "use strict";

    var User = module.parent.require('./user'),
        Groups = module.parent.require('./groups'),
        meta = module.parent.require('./meta'),
        db = module.parent.require('../src/database'),
        passport = module.parent.require('passport'),
        winston = module.parent.require('winston'),
        async = module.parent.require('async'),
        _ = module.parent.require('underscore'),
        controllers = require('./lib/controllers'),
        format = require('util').format;

    var authenticationController = module.parent.require('./controllers/authentication');

    var plugin = {
        ready: false,
        settings: {
            name: 'keycloak',
            'keycloak-config': undefined,
            'admin-url': undefined,
            'callback-url': undefined
        }
    };

    plugin.init = function(params, callback) {
        var router = params.router,
            hostMiddleware = params.middleware;

        router.get('/admin/plugins/sso-keycloak', hostMiddleware.admin.buildHeader, controllers.renderAdminPage);
        router.get('/api/admin/plugins/sso-keycloak', controllers.renderAdminPage);

        plugin.reloadSettings(function(err) {
            if (err) {
                callback();
                return;
            }
            router.all(plugin.settings['admin-url'] + '/k_logout', plugin.adminLogout);
            callback();
        });
    };

    plugin.adminLogout = function(request, response) {
        var data = '';
        request.on('data', d => {
            data += d.toString();
        });

        request.on('end', function() {
            if (data === '') {
                response.send('ok');
                return;
            }
            try {
                var parts = data.split('.');
                var payload = JSON.parse(new Buffer(parts[1], 'base64').toString());
                if (payload.action === 'LOGOUT') {
                    var sessionIDs = payload.adapterSessionIds;
                    if (sessionIDs && sessionIDs.length > 0 && payload.id) {
                        let seen = 0;
                        plugin.getUidByOAuthid(payload.id, (err, uid) => {
                            if (err) {
                                response.status(500).send('User logout unsucessful.');
                            }
                            sessionIDs.forEach(sessionId => {
                                User.auth.revokeSession(sessionId, uid, (err) => {
                                    if (err) {
                                        response.status(500).send('User logout unsucessful.');
                                        return;
                                    }
                                });
                                ++seen;
                                if (seen === sessionIDs.length) {
                                    response.send('ok');
                                }
                            });
                        });

                    }
                    winston.info(payload);
                    response.send('ok');
                    return;
                }
            } catch (err) {
                response.status(500).send('User logout unsucessful.');
            }
            response.send('ok');
        });
    };

    plugin.getStrategy = function(strategies, callback) {
        if (plugin.ready) {
            var Strategy = require('passport-keycloak');
            passport.use(plugin.settings.name, new Strategy(plugin.settings['keycloak-config'], function(userData, done) {
                plugin.parseUserReturn(userData, function(err, profile) {
                    if (err) {
                        return done(err);
                    }
                    plugin.login({
                        keycloakId: profile.id,
                        handle: profile.handle || profile.displayName,
                        email: profile.email,
                        isAdmin: profile.isAdmin
                    }, function(err, user) {
                        if (err) {
                            return done(err);
                        }
                        authenticationController.onSuccessfulLogin(req, user.uid);
                        done(null, user);
                    });
                });

            }));
            strategies.push({
                name: plugin.settings.name,
                url: '/auth/' + plugin.settings.name,
                callbackURL: '/auth/' + plugin.settings.name + '/callback',
                icon: 'fa-check-square',
                scope: (plugin.settings.scope || '').split(',')
            });
            callback(null, strategies);
        } else {
            callback(new Error('[sso-keycloak] Configuration is invalid'));
        }
    };

    plugin.parseUserReturn = function(userData, callback) {
        var profile = {
            id: userData.sub,
            username: userData.preferred_username,
            displayName: userData.given_name,
            given_name: userData.given_name,
            family_name: userData.family_name,
            email: userData.email
        };
        profile.isAdmin = userData.isAdmin || false;
        callback(null, profile);
    };

    plugin.login = function(payload, callback) {
        plugin.getUidByOAuthid(payload.keycloakId, function(err, uid) {
            if (err) {
                return callback(err);
            }

            if (uid !== null) {
                // Existing User
                callback(null, {
                    uid: uid
                });
            } else {
                // New User
                var success = function(uid) {
                    // Save provider-specific information to the user
                    User.setUserField(uid, plugin.settings.name + 'Id', payload.keycloakId);
                    db.setObjectField(plugin.settings.name + 'Id:uid', payload.keycloakId, uid);

                    if (payload.isAdmin) {
                        Groups.join('administrators', uid, function(err) {
                            if (err) {
                                callback(err);
                            }
                            callback(null, {
                                uid: uid
                            });
                        });
                    } else {
                        callback(null, {
                            uid: uid
                        });
                    }
                };

                User.getUidByEmail(payload.email, function(err, uid) {
                    if (err) {
                        return callback(err);
                    }

                    if (!uid) {
                        User.create({
                            username: payload.handle,
                            email: payload.email
                        }, function(err, uid) {
                            if (err) {
                                return callback(err);
                            }
                            success(uid);
                        });
                    } else {
                        success(uid); // Existing account -- merge
                    }
                });
            }
        });
    };

    plugin.getUidByOAuthid = function(keycloakId, callback) {
        db.getObjectField(plugin.settings.name + 'Id:uid', keycloakId, function(err, uid) {
            if (err) {
                return callback(err);
            }
            callback(null, uid);
        });
    };

    plugin.deleteUserData = function(data, callback) {
        var uid = data.uid;
        async.waterfall([
            async.apply(User.getUserField, uid, plugin.settings.name + 'Id'),
            function(keycloakIdToDelete, next) {
                db.deleteObjectField(plugin.settings.name + 'Id:uid', keycloakIdToDelete, next);
            }
        ], function(err) {
            if (err) {
                winston.error('[sso-keycloak] Could not remove keycloak ID data for uid ' + uid + '. Error: ' + err);
                return callback(err);
            }
            winston.verbose('[sso-keycloak] sucessfully deleted keycloak data for  uid ' + uid);
            callback(null, uid);
        });
    };

    plugin.reloadSettings = function(callback) {
        meta.settings.get('sso-keycloak', function(err, settings) {
            if (err) {
                return callback(err);
            }
            let keycloakConfig;
            let configOK = true;
            'callback-url|keycloak-config'.split('|').forEach(key => {
                if (!settings[key]) {
                    let errorMessage = '[sso-keycloak] %s configuration value not found, sso-keycloak is disabled.';
                    winston.error(format(errorMessage, key));
                    configOK = false;
                }
                if (key === 'keycloak-config') {
                    keycloakConfig = JSON.parse(settings[key]);
                    if (!keycloakConfig || keycloakConfig.error) {
                        let errorMessage = '[sso-keycloak] invalid keycloak configuration, sso-keycloak is disabled.';
                        winston.error(errorMessage);
                        configOK = false;
                    } else {
                        settings[key] = keycloakConfig;
                    }
                }
            });
            if (!configOK) {
                return callback(new Error(errorMessage));
            }
            winston.info('[sso-keycloak] Settings OK');
            plugin.settings = _.defaults(_.pick(settings, Boolean), plugin.settings);
            plugin.ready = true;
            callback();
        });
    };

    plugin.addAdminNavigation = function(header, callback) {
        header.plugins.push({
            route: '/plugins/sso-keycloak',
            icon: 'fa-user-secret',
            name: 'SSO Keycloak'
        });

        callback(null, header);
    };

    plugin.getClientConfig = function(config, next) {
        config.keycloak = {
            logoutUrl: plugin.settings['keycloak-config']['auth-server-url'] + '/realms/' + plugin.settings['keycloak-config']['resource'] + '/protocol/openid-connect/logout'
        };
        next(null, config);
    };

    module.exports = plugin;
}(module));
