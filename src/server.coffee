dotty = require 'dotty'

module.exports = (config) ->
  (rs) ->
    config = config or {}
    expiresHours = config.expiresHours or 5
    config.unauthorized = config.unauthorized or (res) ->
      res.status 200
      .end 'unauthorized'
    setCorsHeaders = (req, res, next) ->
      res.setHeader 'Access-Control-Allow-Origin', '*'
      res.setHeader 'Access-Control-Allow-Headers', 'Origin, X-Requested-With, Content-Type, Accept, Authorization'
      res.setHeader 'Access-Control-Allow-Methods', 'GET,PUT,POST,DELETE'
      if req.method is 'OPTIONS'
        res.end()
      else
        next()
    rs.use '/api', setCorsHeaders
    rs.use '/auth', setCorsHeaders
    rs.use '/api/*', (req, res, next) ->
      #all calls to api need an authorization token
      if req.headers and req.headers.authorization
        [scheme, token] = req.headers.authorization.split ' '
        if scheme and token and /^Bearer$/i.test scheme
          userId = rs.token.parseToken token
          if userId
            user = await rs.db.selectOne rs.config.userTable, _id: userId
            if user
              req.user = user
              req.user.serverId = rs.serverId
              req.db = rs.db.wrapUserFunctions req.user
              return next()
      config.unauthorized res
    rs.use '/api/refresh-login', (req, res) ->
      res.json req.user
    rs.post '/auth/token', (req, res) ->
      token = ''
      refreshToken = ''
      if req.headers and req.headers.authorization
        [scheme, credentials] = req.headers.authorization.split ' '
        if scheme and credentials
          if /^Basic$/i.test scheme
            [u64, p64] = credentials.split ':'
            if u64 and p64
              username = new Buffer u64, 'base64'
              .toString 'utf8'            
              password = new Buffer p64, 'base64'
              .toString 'utf8'
              opts = {}
              dotty.put opts, rs.config.userNameField, username
              user = await rs.db.selectOne rs.config.userTable, opts
              if user
                if rs.token.checkHash password, dotty.get user, rs.config.userPassField
                  token = await rs.token.generateToken user._id, expiresHours
                  refreshToken = await rs.token.generateToken 'REFRESH' + user._id, expiresHours
      if token
        res.json
          accessToken: token
          refreshToken: refreshToken
          expires: new Date(new Date().setHours(new Date().getHours() + expiresHours / 2))
      else
        config.unauthorized res
    rs.post '/auth/refresh', (req, res) ->
      userId = rs.token.parseToken req.body.refreshToken
      if /^REFRESH/.test userId
        userId = userId.replace /^REFRESH/, ''
        res.json
          accessToken: await rs.token.generateToken userId, expiresHours
          refreshToken: await rs.token.generateToken 'REFRESH' + userId, expiresHours
          expires: new Date(new Date().setHours(new Date().getHours() + expiresHours / 2))
      else
        config.unauthorized res