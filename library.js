(function(module) {
    "use strict";

    var User = module.parent.require('./user'),
        Groups = module.parent.require('./groups'),
        db = module.parent.require('../src/database'),
        passport = module.parent.require('passport'),
        winston = module.parent.require('winston'),
        async = module.parent.require('async'),
        controllers = require('./lib/controllers'),
        format = require('util').format,
        SocketAdmin = module.parent.require('./socket.io/admin'),
        Settings = module.parent.require('./settings'),
        Strategy = require('passport-keycloak');

    var authenticationController = module.parent.require('./controllers/authentication');

    var plugin = {
        ready: false,
        name: 'sso'
    };

    SocketAdmin.settings.syncSsoKeycloak = function() {
        if (settings) {
            settings.sync(function() {
                winston.info('[sso-keycloak] settings is reloaded');
            });
        }
    };
    var settings;
    plugin.init = function(params, callback) {

        var router = params.router,
            hostMiddleware = params.middleware;

        router.get('/admin/plugins/sso-keycloak', hostMiddleware.admin.buildHeader, controllers.renderAdminPage);
        router.get('/api/admin/plugins/sso-keycloak', controllers.renderAdminPage);

        settings = new Settings('sso-keycloak', '0.0.1', {}, function() {
            plugin.validateSettings(settings.get(), function(err) {
                if (err) {
                    callback();
                    return;
                }
                plugin.settings = settings.get();
                var adminUrl = plugin.settings['admin-url'] + 'k_logout';
                router.post(adminUrl, plugin.adminLogout);
                callback();
            });
        });
    };

    plugin.logout = function(data, callback) {
        var req = data.req;
        if (req.session) {
            delete req.session[Strategy.SESSION_KEY];
        }
        callback();
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
                    if (sessionIDs && sessionIDs.length > 0) {
                        let seen = 0;
                        sessionIDs.forEach(sessionId => {
                            db.sessionStore.get(sessionId, function(err, sessionObj) {
                                if (err) {
                                    winston.verbose('[sso-keycloak] user logout unsucessful' + err.message);
                                }
                                if (sessionObj && sessionObj.passport) {
                                    var uid = sessionObj.passport.user;
                                    async.parallel([
                                        function(next) {
                                            if (sessionObj && sessionObj.meta && sessionObj.meta.uuid) {
                                                db.deleteObjectField('uid:' + uid + ':sessionUUID:sessionId', sessionObj.meta.uuid, next);
                                            } else {
                                                next();
                                            }
                                        },
                                        async.apply(db.sortedSetRemove, 'uid:' + uid + ':sessions', sessionId),
                                        async.apply(db.sessionStore.destroy.bind(db.sessionStore), sessionId)
                                    ], function() {
                                        winston.info('Revoked user session: ' + sessionId);
                                    });
                                }
                            });
                            ++seen;
                            if (seen === sessionIDs.length) {
                                response.send('ok');
                            }
                        });
                    }
                    return;
                }
            } catch (err) {
                response.status(500).send('User logout unsucessful.');
            }
            response.send('ok');
        });
    };

    plugin.getStrategy = function(strategies, callback) {
        if (plugin.ready && plugin.keycloakConfig) {
            plugin.strategy = new Strategy({
                callbackURL: plugin.settings['callback-url'],
                keycloakConfig: plugin.keycloakConfig
            }, function(userData, req, done) {
                plugin.parseUserReturn(userData, function(err, profile) {
                    if (err) {
                        return done(err);
                    }
                    plugin.login(profile, function(err, user) {
                        if (err) {
                            return done(err);
                        }
                        authenticationController.onSuccessfulLogin(req, user.uid);
                        done(null, user);
                    });
                });
            });
            passport.use(plugin.name, plugin.strategy);
            strategies.push({
                name: plugin.name,
                url: '/auth/' + plugin.name,
                callbackURL: plugin.settings['callback-url'],
                icon: 'fa-check-square',
                scope: (plugin.settings.scope || '').split(','),
                successUrl: '/'
            });
        } else {
            winston.error('[sso-keycloak] Configuration is invalid, plugin will not be actived.');
        }
        callback(null, strategies);
    };

    plugin.parseUserReturn = function(userData, callback) {
        var profile = {};
        for (var key in plugin.tokenMapper) {
            if (plugin.tokenMapper.hasOwnProperty(key)) {
                profile[key] = userData[plugin.tokenMapper[key]];
            }
        }
        callback(null, profile);
    };

    plugin.login = function(payload, callback) {
        plugin.getUidByOAuthid(payload.id, function(err, uid) {
            if (err) {
                callback(err);
                return;
            }

            var addToAdmin = function(isAdmin, uid, cb) {
                isAdmin = isAdmin === 'true';
                if (isAdmin) {
                    Groups.join('administrators', uid, function(err) {
                        if (err) {
                            cb(err);
                        }
                        cb(null, {
                            uid: uid
                        });
                    });
                } else {
                    Groups.leave('administrators', uid, function(err) {
                        if (err) {
                            cb(err);
                        }
                        cb(null);
                    });
                }
            };

            if (uid !== null) {
                addToAdmin(payload.isAdmin, uid, function(err) {
                    if (err) {
                        callback(err);
                    }
                    callback(null, {
                        uid: uid
                    });
                });
            } else {
                // New User
                var success = function(uid) {
                    // Save provider-specific information to the user
                    User.setUserField(uid, plugin.name + 'Id', payload.id);
                    db.setObjectField(plugin.name + 'Id:uid', payload.id, uid);

                    if (payload.picture) {
                        User.setUserField(uid, 'uploadedpicture', payload.picture);
                        User.setUserField(uid, 'picture', payload.picture);
                    }

                    addToAdmin(payload.isAdmin, uid, function(err) {
                        if (err) {
                            callback(err);
                            return;
                        }
                        callback(null, {
                            uid: uid
                        });
                    });
                };

                User.getUidByEmail(payload.email, function(err, uid) {
                    if (err) {
                        callback(err);
                        return;
                    }

                    if (!uid) {
                        User.create({
                            username: payload.username,
                            email: payload.email
                        }, function(err, uid) {
                            if (err) {
                                callback(err);
                                return;
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
        db.getObjectField(plugin.name + 'Id:uid', keycloakId, function(err, uid) {
            if (err) {
                return callback(err);
            }
            callback(null, uid);
        });
    };

    plugin.deleteUserData = function(data, callback) {
        var uid = data.uid;
        async.waterfall([
            async.apply(User.getUserField, uid, plugin.name + 'Id'),
            function(keycloakIdToDelete, next) {
                db.deleteObjectField(plugin.name + 'Id:uid', keycloakIdToDelete, next);
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

    plugin.validateSettings = function(settings, callback) {
        let configOK = true;
        let errorMessage = '[sso-keycloak] %s configuration value not found, sso-keycloak is disabled.';
        let formattedErrMessage = '';
        'admin-url|callback-url|keycloak-config|token-mapper'.split('|').forEach(key => {
            if (!settings[key]) {
                formattedErrMessage = format(errorMessage, key);
                winston.error(formattedErrMessage);
                configOK = false;
            }
        });
        if (!configOK) {
            callback(new Error('failed to load settings'));
            return;
        }
        try {
            plugin.keycloakConfig = JSON.parse(settings['keycloak-config']);
        } catch (e) {
            winston.error('[sso-keycloak] invalid keycloak configuration, sso-keycloak is disabled.');
            callback(new Error('invalid keycloak configuration'));
            return;
        }

        try {
            plugin.tokenMapper = JSON.parse(settings['token-mapper']);
        } catch (e) {
            winston.error('[sso-keycloak] Token mapper, sso-keycloak is disabled.');
            callback(new Error('invalid keycloak configuration'));
            return;
        }
        'id|username|email|isAdmin'.split('|').forEach(key => {
            if (!plugin.tokenMapper[key]) {
                formattedErrMessage = format(errorMessage, key);
                winston.error(formattedErrMessage);
                configOK = false;
            }
        });

        winston.info('[sso-keycloak] Settings OK');
        plugin.settings = settings;
        plugin.ready = true;
        callback();

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
        if (plugin.keycloakConfig) {
            config.keycloak = {
                logoutUrl: plugin.keycloakConfig['auth-server-url'] + '/realms/' + plugin.keycloakConfig['realm'] + '/protocol/openid-connect/logout'
            };
        }
        next(null, config);
    };


    module.exports = plugin;
}(module));
