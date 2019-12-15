(function() {
  var dotty;

  dotty = require('dotty');

  module.exports = function(config) {
    return function(rs) {
      var expiresHours, setCorsHeaders;
      config = config || {};
      expiresHours = config.expiresHours || 5;
      config.unauthorized = config.unauthorized || function(res) {
        return res.status(200).end('unauthorized');
      };
      setCorsHeaders = function(req, res, next) {
        res.setHeader('Access-Control-Allow-Origin', '*');
        res.setHeader('Access-Control-Allow-Headers', 'Origin, X-Requested-With, Content-Type, Accept, Authorization');
        res.setHeader('Access-Control-Allow-Methods', 'GET,PUT,POST,DELETE');
        if (req.method === 'OPTIONS') {
          return res.end();
        } else {
          return next();
        }
      };
      rs.use('/api', setCorsHeaders);
      rs.use('/auth', setCorsHeaders);
      rs.use('/api/*', async function(req, res, next) {
        var scheme, token, user, userId;
        //all calls to api need an authorization token
        if (req.headers && req.headers.authorization) {
          [scheme, token] = req.headers.authorization.split(' ');
          if (scheme && token && /^Bearer$/i.test(scheme)) {
            userId = rs.token.parseToken(token);
            if (userId) {
              user = (await rs.db.selectOne(rs.config.userTable, {
                _id: userId
              }));
              if (user) {
                req.user = user;
                req.user.serverId = rs.serverId;
                req.db = rs.db.wrapUserFunctions(req.user);
                return next();
              }
            }
          }
        }
        return config.unauthorized(res);
      });
      rs.use('/api/refresh-login', function(req, res) {
        return res.json(req.user);
      });
      rs.post('/auth/token', async function(req, res) {
        var credentials, opts, p64, password, refreshToken, scheme, token, u64, user, username;
        token = '';
        refreshToken = '';
        if (req.headers && req.headers.authorization) {
          [scheme, credentials] = req.headers.authorization.split(' ');
          if (scheme && credentials) {
            if (/^Basic$/i.test(scheme)) {
              [u64, p64] = credentials.split(':');
              if (u64 && p64) {
                username = new Buffer(u64, 'base64').toString('utf8');
                password = new Buffer(p64, 'base64').toString('utf8');
                opts = {};
                dotty.put(opts, rs.config.userNameField, username);
                user = (await rs.db.selectOne(rs.config.userTable, opts));
                if (user) {
                  if (rs.token.checkHash(password, dotty.get(user, rs.config.userPassField))) {
                    token = (await rs.token.generateToken(user._id, expiresHours));
                    refreshToken = (await rs.token.generateToken('REFRESH' + user._id, expiresHours));
                  }
                }
              }
            }
          }
        }
        if (token) {
          return res.json({
            accessToken: token,
            refreshToken: refreshToken,
            expires: new Date(new Date().setHours(new Date().getHours() + expiresHours / 2))
          });
        } else {
          return config.unauthorized(res);
        }
      });
      return rs.post('/auth/refresh', async function(req, res) {
        var userId;
        userId = rs.token.parseToken(req.body.refreshToken);
        if (/^REFRESH/.test(userId)) {
          userId = userId.replace(/^REFRESH/, '');
          return res.json({
            accessToken: (await rs.token.generateToken(userId, expiresHours)),
            refreshToken: (await rs.token.generateToken('REFRESH' + userId, expiresHours)),
            expires: new Date(new Date().setHours(new Date().getHours() + expiresHours / 2))
          });
        } else {
          return config.unauthorized(res);
        }
      });
    };
  };

}).call(this);

//# sourceMappingURL=server.js.map
