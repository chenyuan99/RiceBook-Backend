const express = require('express');
const session = require('express-session');
const passport = require('passport');
const GoogleStrategy = require('passport-google-oauth').OAuth2Strategy;
const bodyParser = require('body-parser');
const cookieParser = require('cookie-parser');
const cors = require('cors');

const corsOptions = {origin: 'http://localhost:4200', credentials: true};

const app = express();
app.use(bodyParser.json());
app.use(cookieParser());
app.use(cors(corsOptions));

app.use(session({
    secret: 'doNotGuessTheSecret',
    resave: true,
    saveUninitialized: true
}));

app.use(passport.initialize());
app.use(passport.session());

passport.serializeUser(function (user, done) {
    done(null, user);
});

passport.deserializeUser(function (user, done) {
    done(null, user);
});

passport.use(new GoogleStrategy({
            clientID: '994542386146-vc4guf2s4eu511rc06ujcshp7djsb93i.apps.googleusercontent.com',
            clientSecret: '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',
            callbackURL: "/auth/google/callback"
        },
        function (accessToken, refreshToken, profile, done) {
            let user = {
                'token': accessToken
            };
            return done(null, user);
        })
);
app.get('/auth/google', passport.authenticate('google', {scope: ['https://www.googleapis.com/auth/plus.login']})); // could have a passport auth second arg {scope: 'email'}
app.get('/auth/google/callback',
    passport.authenticate('google', {
        successRedirect: 'http://localhost:4200/#/main',
        failureRedirect: '/'
    }));
const port = process.env.PORT || 3000;
const server = app.listen(port, () => {
    const addr = server.address();
    console.log(`Server listening at http://${addr.address}:${addr.port}`)
});
