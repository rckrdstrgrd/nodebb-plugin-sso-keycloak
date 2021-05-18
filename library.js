(function (module) {
  "use strict";

  var User = module.parent.require("./user"),
    Groups = module.parent.require("./groups"),
    db = module.parent.require("../src/database"),
    passport = module.parent.require("passport"),
    winston = module.parent.require("winston"),
    async = module.parent.require("async"),
    controllers = require("./lib/controllers"),
    format = require("util").format,
    SocketAdmin = module.parent.require("./socket.io/admin"),
    Settings = module.parent.require("./settings"),
    Strategy = require("passport-keycloak"),
    nconf = module.parent.require("nconf");

  var authenticationController = module.parent.require(
    "./controllers/authentication"
  );

  var plugin = {
    ready: false,
    name: "keycloak",
  };

  SocketAdmin.settings.syncSsoKeycloak = function () {
    if (settings) {
      settings.sync(function () {
        winston.info("[sso-keycloak] settings is reloaded");
      });
    }
  };
  var settings;
  plugin.init = function (params, callback) {
    var router = params.router,
      hostMiddleware = params.middleware;

    router.get(
      "/admin/plugins/sso-keycloak",
      hostMiddleware.admin.buildHeader,
      controllers.renderAdminPage
    );
    router.get("/api/admin/plugins/sso-keycloak", controllers.renderAdminPage);

    settings = new Settings("sso-keycloak", "0.0.1", {}, function () {
      plugin.validateSettings(settings.get(), function (err) {
        if (err) {
          callback();
          return;
        }
        plugin.settings = settings.get();
        var adminUrl = plugin.settings["admin-url"];
        if (adminUrl[0] !== "/") {
          adminUrl = "/" + adminUrl;
        }
        if (adminUrl[adminUrl.length - 1] !== "/") {
          adminUrl += "/";
        }
        adminUrl += "k_logout";
        router.post(adminUrl, plugin.adminLogout);
        callback();
      });
    });
  };

  plugin.logout = function (data, callback) {
    var req = data.req;
    if (req.session) {
      delete req.session[Strategy.SESSION_KEY];
    }
    callback();
  };

  plugin.adminLogout = function (request, response) {
    function doLogout(data, callback) {
      if (typeof data !== "string" || data.indexOf(".") < 0) {
        return callback(new Error("invalid payload"));
      }
      try {
        var parts = data.split(".");
        var payload = JSON.parse(new Buffer(parts[1], "base64").toString());
        if (payload && payload.action && payload.action === "LOGOUT") {
          var sessionIDs = payload.adapterSessionIds;
          if (sessionIDs && sessionIDs.length > 0) {
            let seen = 0;
            sessionIDs.forEach((sessionId) => {
              db.sessionStore.get(sessionId, function (err, sessionObj) {
                if (err) {
                  winston.info(
                    "[sso-keycloak] user logout unsucessful" + err.message
                  );
                }
                if (sessionObj && sessionObj.passport) {
                  var uid = sessionObj.passport.user;
                  async.parallel(
                    [
                      function (next) {
                        if (
                          sessionObj &&
                          sessionObj.meta &&
                          sessionObj.meta.uuid
                        ) {
                          db.deleteObjectField(
                            "uid:" + uid + ":sessionUUID:sessionId",
                            sessionObj.meta.uuid,
                            next
                          );
                        } else {
                          next();
                        }
                      },
                      async.apply(
                        db.sortedSetRemove,
                        "uid:" + uid + ":sessions",
                        sessionId
                      ),
                      async.apply(
                        db.sessionStore.destroy.bind(db.sessionStore),
                        sessionId
                      ),
                    ],
                    function () {
                      winston.info("Revoked user session: " + sessionId);
                    }
                  );
                }
              });
              ++seen;
              if (seen === sessionIDs.length) {
                return callback(null, "ok");
              }
            });
          } else {
            return callback(new Error("User logout unsucessful."));
          }
        } else {
          return callback(new Error("User logout unsucessful."));
        }
      } catch (err) {
        return callback(new Error("User logout unsucessful."));
      }
    }

    var reqData = "";
    request.on("data", (d) => {
      reqData += d.toString();
    });

    request.on("end", function () {
      return doLogout(reqData, function (err, result) {
        if (err) {
          return response.send(err.message);
        }
        response.send(result);
      });
    });
  };

  plugin.getStrategy = function (strategies, callback) {
    if (plugin.ready && plugin.keycloakConfig) {
      plugin.strategy = new Strategy(
        {
          callbackURL: plugin.settings["callback-url"],
          keycloakConfig: plugin.keycloakConfig,
          validRedirectsHosts: plugin.validRedirects,
        },
        function (userData, req, done) {
          plugin.parseUserReturn(userData, function (err, profile) {
            if (err) {
              return done(err);
            }
            plugin.login(profile, function (err, user) {
              if (err) {
                return done(err);
              }
              authenticationController.onSuccessfulLogin(req, user.uid);
              done(null, user);
            });
          });
        }
      );
      passport.use(plugin.name, plugin.strategy);
      strategies.push({
        name: plugin.name,
        url: "/auth/" + plugin.name,
        callbackURL: plugin.settings["callback-url"],
        icon: "fa-check-square",
        scope: (plugin.settings.scope || "").split(","),
        successUrl: "/",
      });
    } else {
      winston.error(
        "[sso-keycloak] Configuration is invalid, plugin will not be actived."
      );
    }
    callback(null, strategies);
  };

  plugin.parseUserReturn = function (userData, callback) {
    var profile = {};
    for (var key in plugin.tokenMapper) {
      if (plugin.tokenMapper.hasOwnProperty(key)) {
        profile[key] = userData.id_token.content[plugin.tokenMapper[key]];
      }
    }
    if (plugin.clientRoleToGroupMapper) {
      profile.joinGroups = [];
      profile.leaveGroups = [];
      var access = userData.access_token.content.resource_access;
      var clients = Object.keys(plugin.clientRoleToGroupMapper);
      for (let i = 0; i < clients.length; i++) {
        var client = clients[i];
        if (access[client]) {
          profile.joinGroups = profile.joinGroups.concat(access[client].roles);
        }
      }
      profile.leaveGroups = plugin.allRoleGroups.filter(function (role) {
        return profile.joinGroups.indexOf(role) == -1;
      });
    }
    callback(null, profile);
  };

  plugin.login = function (payload, callback) {
    plugin.getUidByOAuthid(payload.id, function (err, uid) {
      if (err) {
        callback(err);
        return;
      }
      if (uid !== null) {
        async.parallel(
          [
            function (callback) {
              if (payload.isAdmin) {
                Groups.join("administrators", uid, function (err) {
                  if (err) {
                    callback(err);
                  }
                  callback(null, {
                    uid: uid,
                  });
                });
              } else {
                Groups.leave("administrators", uid, function (err) {
                  if (err) {
                    callback(err);
                  }
                  callback(null);
                });
              }
            },
            function (callback) {
              if (payload.joinGroups) {
                for (let i = 0; i < payload.joinGroups.length; i++) {
                  const group = payload.joinGroups[i];
                  Groups.join(group, uid, function (err) {
                    if (err) {
                      winston.info(
                        `[sso-keycloak] uid:${uid} unable to join ${group} on login. err: ${err}`
                      );
                    }
                  });
                }
              }
              if (payload.leaveGroups) {
                for (let i = 0; i < payload.leaveGroups.length; i++) {
                  const group = payload.leaveGroups[i];
                  Groups.leave(group, uid, function (err) {
                    if (err) {
                      winston.info(
                        `[sso-keycloak] uid:${uid} unable to leave ${group} on login. err: ${err}`
                      );
                    }
                  });
                }
              }
              callback(null);
            },
            function (callback) {
              User.getUserField(uid, "username", function (err, oldUsername) {
                if (err) {
                  return callback(err);
                }
                if (oldUsername === payload.username) {
                  return callback(null, "Username not changed");
                }
                User.updateProfile(
                  uid,
                  {
                    username: payload.username,
                  },
                  function (err, userData) {
                    if (err) {
                      return callback(err);
                    }
                    return callback(null, userData);
                  }
                );
              });
            },
          ],
          function (err, result) {
            if (err) {
              return winston.error(err);
            }
            callback(null, { uid: uid });
          }
        );
      } else {
        // New User
        var success = function (uid) {
          // Save provider-specific information to the user
          User.setUserField(uid, plugin.name + "Id", payload.id);
          db.setObjectField(plugin.name + "Id:uid", payload.id, uid);

          if (
            payload.hasOwnProperty("facebook_id") &&
            typeof payload["facebook_id"] !== "undefined"
          ) {
            payload.picture =
              "https://graph.facebook.com/v2.8/" +
              payload["facebook_id"] +
              "/picture?type=large";
          }

          if (payload.picture) {
            User.setUserField(uid, "uploadedpicture", payload.picture);
            User.setUserField(uid, "picture", payload.picture);
          }

          if (payload.joinGroups) {
            for (let i = 0; i < payload.joinGroups.length; i++) {
              const group = payload.joinGroups[i];
              Groups.join(group, uid, function (err) {
                if (err) {
                  winston.info(
                    `[sso-keycloak] uid:${uid} unable to join ${group} on login. err: ${err}`
                  );
                }
              });
            }
          }
          if (payload.leaveGroups) {
            for (let i = 0; i < payload.leaveGroups.length; i++) {
              const group = payload.leaveGroups[i];
              Groups.leave(group, uid, function (err) {
                if (err) {
                  winston.info(
                    `[sso-keycloak] uid:${uid} unable to leave ${group} on login. err: ${err}`
                  );
                }
              });
            }
          }
          callback(null, { uid: uid });
        };

        User.getUidByEmail(payload.email, function (err, uid) {
          if (err) {
            callback(err);
            return;
          }

          if (!uid) {
            User.create(
              {
                username: payload.username | `${payload.given_name}`,
                email: payload.email,
              },
              function (err, uid) {
                if (err) {
                  callback(err);
                  return;
                }
                success(uid);
              }
            );
          } else {
            success(uid); // Existing account -- merge
          }
        });
      }
    });
  };

  plugin.getUidByOAuthid = function (keycloakId, callback) {
    db.getObjectField(plugin.name + "Id:uid", keycloakId, function (err, uid) {
      if (err) {
        return callback(err);
      }
      callback(null, uid);
    });
  };

  plugin.deleteUserData = function (data, callback) {
    var uid = data.uid;
    async.waterfall(
      [
        async.apply(User.getUserField, uid, plugin.name + "Id"),
        function (keycloakIdToDelete, next) {
          db.deleteObjectField(
            plugin.name + "Id:uid",
            keycloakIdToDelete,
            next
          );
        },
      ],
      function (err) {
        if (err) {
          winston.error(
            "[sso-keycloak] Could not remove keycloak ID data for uid " +
              uid +
              ". Error: " +
              err
          );
          return callback(err);
        }
        winston.verbose(
          "[sso-keycloak] sucessfully deleted keycloak data for  uid " + uid
        );
        callback(null, uid);
      }
    );
  };

  plugin.validateSettings = function (settings, callback) {
    let configOK = true;
    let errorMessage =
      "[sso-keycloak] %s configuration value not found, sso-keycloak is disabled.";
    let formattedErrMessage = "";
    "admin-url|callback-url|keycloak-config|token-mapper"
      .split("|")
      .forEach((key) => {
        if (!settings[key]) {
          formattedErrMessage = format(errorMessage, key);
          winston.error(formattedErrMessage);
          configOK = false;
        }
      });
    if (!configOK) {
      callback(new Error("failed to load settings"));
      return;
    }
    try {
      plugin.keycloakConfig = JSON.parse(settings["keycloak-config"]);
    } catch (e) {
      winston.error(
        "[sso-keycloak] invalid keycloak configuration, sso-keycloak is disabled."
      );
      callback(new Error("invalid keycloak configuration"));
      return;
    }

    try {
      plugin.tokenMapper = JSON.parse(settings["token-mapper"]);
    } catch (e) {
      winston.error("[sso-keycloak] Token mapper, sso-keycloak is disabled.");
      callback(new Error("invalid keycloak configuration"));
      return;
    }
    "id|username|email|given_name|isAdmin".split("|").forEach((key) => {
      if (!plugin.tokenMapper[key]) {
        formattedErrMessage = format(errorMessage, key);
        winston.error(formattedErrMessage);
        configOK = false;
      }
    });

    try {
      plugin.clientRoleToGroupMapper = JSON.parse(
        settings["client-role-to-group-mapper"]
      );
      plugin.allRoleGroups = [];
      for (const client in plugin.clientRoleToGroupMapper) {
        if (plugin.clientRoleToGroupMapper.hasOwnProperty(client)) {
          const roles = plugin.clientRoleToGroupMapper[client];
          plugin.allRoleGroups = plugin.allRoleGroups.concat(roles);
        }
      }
    } catch (e) {
      winston.error(`[sso-keycloak] Client rolet to group mapper invalid`);
    }

    try {
      plugin.validRedirects = settings["valid-redirects"].split(",");
    } catch (e) {
      winston.warn("[sso-keycloak] validRedirects setting: " + e.message);
      plugin.validRedirects = [];
    }

    if (nconf.get("REALM_PUBLIC_KEY")) {
      winston.info(
        "[sso-keycloak] realm-public-key override from environment variable"
      );
      plugin.keycloakConfig["realm-public-key"] = nconf.get("REALM_PUBLIC_KEY");
    }

    if (nconf.get("REALM")) {
      winston.info("[sso-keycloak] realm override from environment variable");
      plugin.keycloakConfig["realm"] = nconf.get("REALM");
    }

    if (nconf.get("KEYCLOAK_RESOURCE")) {
      winston.info(
        "[sso-keycloak] resource override from environment variable"
      );
      plugin.keycloakConfig["resource"] = nconf.get("KEYCLOAK_RESOURCE");
    }

    if (nconf.get("AUTH_SERVER_URL")) {
      winston.info(
        "[sso-keycloak] auth-server-url override from environment variable"
      );
      plugin.keycloakConfig["auth-server-url"] = nconf.get("AUTH_SERVER_URL");
    }

    winston.info("[sso-keycloak] Settings OK");
    plugin.settings = settings;
    plugin.ready = true;
    callback();
  };

  plugin.addAdminNavigation = function (header, callback) {
    header.plugins.push({
      route: "/plugins/sso-keycloak",
      icon: "fa-user-secret",
      name: "SSO Keycloak",
    });

    callback(null, header);
  };

  plugin.getClientConfig = function (config, next) {
    if (plugin.keycloakConfig) {
      config.keycloak = {
        logoutUrl:
          plugin.keycloakConfig["auth-server-url"] +
          "/realms/" +
          plugin.keycloakConfig["realm"] +
          "/protocol/openid-connect/logout",
      };
    }
    next(null, config);
  };

  module.exports = plugin;
})(module);
