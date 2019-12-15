angular = window.angular or require 'angular'
moduleName = 'rs-auth'
angular.module moduleName, [
  'rs-rest'
  'rs-storage'
]
.factory 'auth', ($injector, $http, $timeout, $state, $q, storage, rest) ->
  user = null
  socket = null
  if $injector.has 'socket'
    socket = $injector.get 'socket'
  redirectToLogin = (promise) ->
    user = null
    $timeout ->
      $state.go 'login'
    promise?.resolve false
  checkRoles = (role) ->
    role = [role] if typeof(role) is 'string'
    if role and user?.role
      return true if user.role.includes r for r in role
    return false
  refreshLogin: (promise, permittedRoles) ->
    if permittedRoles
      $http.post '/api/refresh-login'
      .then (res) ->
        if res.status is 401
          user = null
          return promise.resolve false
        if res.status is 200
          if res.data is 'unauthorized'
            return redirectToLogin promise
          user = res.data
          if user.role
            for role in user.role
              if permittedRoles.includes role
                return promise.resolve()
            return redirectToLogin promise
        promise.resolve()
    else
      promise.resolve()
  getToken: (username, password) ->
    defer = $q.defer()
    $http
      url: '/auth/token'
      method: 'POST'
      headers:
        Authorization: 'Basic ' + btoa(username) + ':' + btoa(password)
    .then (res) ->
      if res.status is 200
        storage.set 'token', res.data
        defer.resolve()
    defer.promise
  refreshToken: (token) ->
    defer = $q.defer()
    $http.post '/auth/refresh', token
    .then (res) ->
      if res.status is 200
        storage.set 'token', res.data
        return defer.resolve res.data
      defer.reject()
    , ->
      defer.reject()
    defer.promise
  clearToken: ->
    user = null
    storage.set 'token', ''
  getUser: ->
    user
  loggedIn: ->
    user or ['invited', 'forgot', 'forgotResponse'].includes $state.current.name
  isAuthorized: (stateName) ->
    if user
      role = $state.get(stateName)?.data?.auth
      checkRoles role
    false
  canEdit: (stateName) ->
    if user
      roles = $state.get(stateName)?.data?.edit or $state.get(stateName)?.data?.auth
      return checkRoles roles
    false
.run ($rootScope, auth) ->
  $rootScope.auth = auth
module.exports = moduleName