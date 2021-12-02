const md5 = require('md5');
const cookieParser = require('cookie-parser')
const session = require('express-session')
const bodyParser = require('body-parser')
const mongoose = require("mongoose");
const express = require('express');
const passport = require('passport');
const GoogleStrategy = require('passport-google-oauth').OAuth2Strategy;
const cors = require('cors');
const User = require('./model.js').User
const Profiles = require('./model.js').Profiles
const connectionString = 'mongodb+srv://yc149:Lovelife098!@cluster0.hqe6q.mongodb.net/social?retryWrites=true&w=majority';
const mySecretMessage = "test yc149"
const salt = Math.random() * 1000;
const redis = require("redis");
var cookieKey = 'sid'
const fs = require("fs");
const client = redis.createClient("redis://:pecb97496a2e8074497b485fda26cbdd6aef129eb2e8451481b80e7f97698fb57@ec2-34-204-225-229.compute-1.amazonaws.com:31320", {
    tls: {
        rejectUnauthorized: false
    }
});

function isLoggedIn(req, res, next) {
    const sid = req.cookies[cookieKey]
    if (!sid) {
        return res.sendStatus(401)
    }
    client.hget(sid, "username", function (err, username) {
        if (username) {
            req.username = username
            next()
        } else {
            res.status(401).send('User session not exist')
        }
    })
}

function login(req, res) {
    const connector = mongoose.connect(connectionString, {useNewUrlParser: true, useUnifiedTopology: true});
    // console.log(userObjs);
    var username = req.body.username
    var password = req.body.password
    if (!username || !password) {
        res.status(400).send("Missing input username or password")
        return
    }
    User.find({username: username}).exec(function (err, users) {
        if (users.length == 0) {
            res.status(401).send("this username is not registered yet.")
            return
        }
        const userObj = users[0]
        if (userObj == null) {
            res.status(401).send("Username is missing in the database")
        }
        const salt = userObj.salt
        const hash = userObj.hash
        const newhash = md5(password + salt)
        if (newhash != hash) {
            res.status(401).send("Password is wrong!")
        } else {
            const sessionKey = md5(mySecretMessage + new Date().getTime() + userObj.username)
            client.hmset(sessionKey, "username", username)
            res.cookie(cookieKey, sessionKey, {maxAge: 3600 * 1000, httpOnly: true,sameSite: none,secure: true})
            const msg = {username: username, result: 'success'}
            res.send(msg)
        }
    })
}

function register(req, res) {
    const connector = mongoose.connect(connectionString, {useNewUrlParser: true, useUnifiedTopology: true});
    let username = req.body.username;
    let password = req.body.password;
    let email = req.body.email;
    let dob = new Date(req.body.dob).getTime();
    let zipcode = req.body.zipcode;
    if (!username || !password || !email || !dob || !zipcode) {
        res.status(400).send({result: "Missing inputs"});
        return;
    }
    User.find({username: username}, function (err, users) {
        if (users.length !== 0) {
            res.status(401).send("username already registered")
            return
        }
        let hash = md5(password + salt);
        let userobj = new User({username: username, salt: salt, hash: hash})
        const profileObj = new Profiles({
            username: username,
            email: email,
            dob: dob,
            zipcode: zipcode,
            headline: "dummy headline",
            following: [],
            avatar: ""
        })
        userobj.save();
        profileObj.save();
        res.status(200).send({
            result: 'success',
            username: username
        });
    })
}

function logout(req, res) {
    const sid = req.cookies[cookieKey]
    client.del(sid)
    res.clearCookie(cookieKey)
    res.status(200).send('OK')
}

const putPassword = (req, res) => {
    const newPassword = req.body.password
    const username = req.username
    if (newPassword == null) {
        res.status(400).send("Password  missing")
        return
    }
    User.find({username: username}, function (err, users) {
        const userObj = users[0]
        const salt = userObj.salt
        const newSalt = md5(salt + new Date().getTime())
        const newHash = md5(newPassword + newSalt)
        User.updateMany(
            {username: username},
            {$set: {salt: newSalt, hash: newHash}},
            {new: true},
            function (err, profile) {
                res.status(200).send("password successfully changed")
            })
    })

}

const index = (req, res) => {
    console.log(req.params.user)
    res.send({hello: 'world'})
}

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
                /*'email': profile.emails[0].value,
                'name' : profile.name.givenName + ' ' + profile.name.familyName,
                'id'   : profile.id,*/
                'token': accessToken
            };
            // You can perform any necessary actions with your user at this point,
            // e.g. internal verification against a users table,
            // creating new user entries, etc.

            return done(null, user);
            // User.findOrCreate(..., function(err, user) {
            //     if (err) { return done(err); }
            //     done(null, user);
            // });
        })
);

const link2gg = (req, res) => {
    const username = req.body.reguser;
    const password = req.body.regpw;

    if (!username || !password) {
        return res.status(400).send("missing username or password")
    }

    User.find({username: username}).exec(function (err, users) {
        if (!users || users.length == 0) {
            return res.sendStatus(400).send({result: 'User does not exist in database'})
        }

        const userObj = users[0]
        if (!userObj) {
            res.status(400).send("User does not exist in database")
        }

        function isAuthorized(req, userObj) {
            var salt = userObj.salt;
            var password = req.body.regpw;
            var hash = userObj.hash;

            var new_hash = md5(password + salt)
            return hash == new_hash
        }

        if (isAuthorized(req, userObj)) {

            Article.update({author: req.username}, {$set: {'author': username}}, {new: true, multi: true}, function () {
            })

            Article.update({'comments.author': req.username}, {$set: {'comments.$.author': username}}, {
                new: true,
                multi: true
            }, function () {
            })

            Comment.update({author: req.username}, {$set: {'author': username}}, {new: true, multi: true}, function () {
            })

            Profiles.findOne({username: req.username}).exec(function (err, profile) {
                if (profile) {
                    Profiles.findOne({username: username}).exec(function (err, newProfile) {
                        if (newProfile) {
                            const newFollowings = newProfile.following.concat(profile.following)
                            Profiles.update({username: username}, {$set: {'following': newFollowings}}, function () {
                            })
                        }
                    })
                    Profiles.update({username: req.username}, {$set: {'following': []}}, function () {
                    })
                }
            })
            User.findOne({username: username}).exec(function (err, user) {
                if (user) {
                    const usr = req.username.split('@');
                    const authObj = {}
                    authObj[`Facebook`] = usr[0]
                    User.update({username: username}, {$addToSet: {'auth': authObj}}, {new: true}, function () {
                    })
                }
            })
            res.status(200).send({username: username, result: 'success'})
        } else {
            res.status(401).send("password is not correct")
        }
    })
}

const unlinking = (req, res) => {
    const username = req.username
    User.findOne({username: username}).exec(function (err, user) {
        if (user.auth.length !== 0) {
            User.updateMany({username: username}, {$set: {auth: []}}, {new: true}, function () {
                res.status(200).send({result: 'unlink successfully'})
            })
        } else {
            res.status(400).send("cannot unlink since there is no account linking with it")
        }
    })
}


module.exports = (app) => {
    app.use(cookieParser());
    app.use(cors({origin : "http://localhost:4200"}));
    app.get('/', index);
    app.post('/register', register);
    app.post('/login', login);
    app.use(passport.initialize());
    app.get('/auth/google', passport.authenticate('google', {scope: ['https://www.googleapis.com/auth/plus.login']})); // could have a passport auth second arg {scope: 'email'}
    app.get('/auth/google/callback',
        passport.authenticate('google', {
            successRedirect: 'http://localhost:4200/main',
            failureRedirect: '/'
        }));
    app.use(isLoggedIn);
    app.put('/logout', logout);
    app.put('/password', putPassword);
}

