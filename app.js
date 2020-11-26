'use strict';

module.exports = app => {
  app.rsa = require('./lib/rsa')(app.config.rsa, app);
};
