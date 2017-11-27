var JwtStrategy = require('passport-jwt').Strategy,
    ExtractJwt = require('passport-jwt').ExtractJwt,
    GitHubStrategy = require('passport-github2').Strategy;

// load up the user model
var User = require('../app/modules/participant');
var config = require('./config'); // get db config file
var auth =require('./auth');


module.exports = function(passport) {


    var opts = {};
        opts.jwtFromRequest = ExtractJwt.fromAuthHeaderAsBearerToken();
        opts.secretOrKey = config.secret;
        passport.use(new JwtStrategy(opts, function(jwt_payload, done) {
            User.findOne({id: jwt_payload.id}, function(err, user) {
                if (err) {
                    return done(err, false);
                }
                if (user) {
                    done(null, user);
                } else {
                    done(null, false);
                }
            });
        }));


        passport.use(new GitHubStrategy({
                clientID: auth.githubAuth.clientID,
                clientSecret: auth.githubAuth.clientSecret,
                callbackURL: auth.githubAuth.callbackURL
            },
            function(accessToken, refreshToken, profile, done) {
                // asynchronous verification, for effect...
                process.nextTick(function () {

                    // To keep the example simple, the user's GitHub profile is returned to
                    // represent the logged-in user.  In a typical application, you would want
                    // to associate the GitHub account with a user record in your database,
                    // and return that user instead.
                    return done(null, profile);
                });
            }
        ));



};