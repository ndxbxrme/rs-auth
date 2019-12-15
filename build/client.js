(function() {
  var angular, moduleName;

  angular = window.angular || require('angular');

  moduleName = 'rs-auth';

  angular.module(moduleName, ['rs-rest', 'rs-storage']).factory('auth', function($injector, $http, $timeout, $state, $q, storage, rest) {
    var checkRoles, redirectToLogin, socket, user;
    user = null;
    socket = null;
    if ($injector.has('socket')) {
      socket = $injector.get('socket');
    }
    redirectToLogin = function(promise) {
      user = null;
      $timeout(function() {
        return $state.go('login');
      });
      return promise != null ? promise.resolve(false) : void 0;
    };
    checkRoles = function(role) {
      var r;
      if (typeof role === 'string') {
        role = [role];
      }
      if (role && (user != null ? user.role : void 0)) {
        if ((function() {
          var i, len, results;
          results = [];
          for (i = 0, len = role.length; i < len; i++) {
            r = role[i];
            results.push(user.role.includes(r));
          }
          return results;
        })()) {
          return true;
        }
      }
      return false;
    };
    return {
      refreshLogin: function(promise, permittedRoles) {
        if (permittedRoles) {
          return $http.post('/api/refresh-login').then(function(res) {
            var i, len, ref, role;
            if (res.status === 401) {
              user = null;
              return promise.resolve(false);
            }
            if (res.status === 200) {
              if (res.data === 'unauthorized') {
                return redirectToLogin(promise);
              }
              user = res.data;
              if (user.role) {
                ref = user.role;
                for (i = 0, len = ref.length; i < len; i++) {
                  role = ref[i];
                  if (permittedRoles.includes(role)) {
                    return promise.resolve();
                  }
                }
                return redirectToLogin(promise);
              }
            }
            return promise.resolve();
          });
        } else {
          return promise.resolve();
        }
      },
      getToken: function(username, password) {
        var defer;
        defer = $q.defer();
        $http({
          url: '/auth/token',
          method: 'POST',
          headers: {
            Authorization: 'Basic ' + btoa(username) + ':' + btoa(password)
          }
        }).then(function(res) {
          if (res.status === 200) {
            storage.set('token', res.data);
            return defer.resolve();
          }
        });
        return defer.promise;
      },
      refreshToken: function(token) {
        var defer;
        defer = $q.defer();
        $http.post('/auth/refresh', token).then(function(res) {
          if (res.status === 200) {
            storage.set('token', res.data);
            return defer.resolve(res.data);
          }
          return defer.reject();
        }, function() {
          return defer.reject();
        });
        return defer.promise;
      },
      clearToken: function() {
        user = null;
        return storage.set('token', '');
      },
      getUser: function() {
        return user;
      },
      loggedIn: function() {
        return user || ['invited', 'forgot', 'forgotResponse'].includes($state.current.name);
      },
      isAuthorized: function(stateName) {
        var ref, ref1, role;
        if (user) {
          role = (ref = $state.get(stateName)) != null ? (ref1 = ref.data) != null ? ref1.auth : void 0 : void 0;
          checkRoles(role);
        }
        return false;
      },
      canEdit: function(stateName) {
        var ref, ref1, ref2, ref3, roles;
        if (user) {
          roles = ((ref = $state.get(stateName)) != null ? (ref1 = ref.data) != null ? ref1.edit : void 0 : void 0) || ((ref2 = $state.get(stateName)) != null ? (ref3 = ref2.data) != null ? ref3.auth : void 0 : void 0);
          return checkRoles(roles);
        }
        return false;
      }
    };
  }).run(function($rootScope, auth) {
    return $rootScope.auth = auth;
  });

  module.exports = moduleName;

}).call(this);

//# sourceMappingURL=client.js.map
