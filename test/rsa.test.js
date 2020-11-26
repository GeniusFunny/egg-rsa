'use strict';

const mock = require('egg-mock');

describe('test/rsa.test.js', () => {
  let app;
  before(() => {
    app = mock.app({
      baseDir: 'apps/rsa-test',
    });
    return app.ready();
  });

  after(() => app.close());
  afterEach(mock.restore);

  it('should GET /', () => {
    return app.httpRequest()
      .get('/')
      .expect('hi, rsa')
      .expect(200);
  });
});
