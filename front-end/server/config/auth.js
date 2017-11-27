var config =require('./config');

module.exports = {
    'githubAuth': {
        'clientID': '9d5dbdc43d80422f2238',
        'clientSecret': '9866a10038500552850d31fc8582d89405f3428f',
        'callbackURL': 'http://localhost:'+config .port+'/auth/github/callback'
    },

                }