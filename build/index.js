(function() {
  module.exports = typeof window === 'undefined' ? require('./server') : require('./client');

}).call(this);

//# sourceMappingURL=index.js.map
