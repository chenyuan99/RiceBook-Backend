const Profiles = require('./model.js').Profiles
const mongoose = require("mongoose");
const connectionString = 'mongodb+srv://yc149:Lovelife098!@cluster0.hqe6q.mongodb.net/social?retryWrites=true&w=majority';
const profile = {
    username: 'DLeebron',
    headline: 'This is my headline!',
    email: 'foo@bar.com',
    zipcode: 12345,
    dob: '128999122000',
    avatar: 'https://upload.wikimedia.org/wikipedia/en/thumb/4/4e/DWLeebron.jpg/220px-DWLeebron.jpg',
}

const getHeadline = (req, res) => {
    const connector = mongoose.connect(connectionString, {useNewUrlParser: true, useUnifiedTopology: true});
    const username = req.params.user
    Profiles.find({username: username}, function (err, profiles) {
        if (profiles.length === 0) {
            res.status(400).send("users missing")
            return
        }
        res.status(200).send({
            username: username,
            headline: profiles[0].headline
        })
    })
}


const putHeadline = (req, res) => {
    const connector = mongoose.connect(connectionString, {useNewUrlParser: true, useUnifiedTopology: true});
    const username = req.username
    const headline = req.body.headline
    if (!headline) {
        res.status(400).send('Headline missing')
    }

    Profiles.updateMany(
        {username: username},
        {$set: {headline: headline}},
        {new: true},
        function (err, profiles) {
            res.status(200).send({
                username: username, headline: headline
            });
        })

}


const getEmail = (req, res) => {
    const connector = mongoose.connect(connectionString, {useNewUrlParser: true, useUnifiedTopology: true});
    const username = req.params.user
    // console.log(username)
    Profiles.find({username: username}, function (err, profiles) {
        // console.log("finding...")
        if (profiles.length == 0) {
            res.status(400).send("User not found in the database")
            return
        }
        res.status(200).send({
            username: username,
            email: profiles[0].email
        })
    })

}


const putEmail = (req, res) => {
    const connector = mongoose.connect(connectionString, {useNewUrlParser: true, useUnifiedTopology: true});
    const username = req.username
    const newEmail = req.body.email
    if (!newEmail) {
        res.status(400).send('New email missing')
    }
    Profiles.updateMany(
        {username: username},
        {$set: {email: newEmail}},
        {new: true},
        function (err, profiles) {
            res.status(200).send({
                username: username,
                email: newEmail
            })
        })
}


const getZipcode = (req, res) => {
    const connector = mongoose.connect(connectionString, {useNewUrlParser: true, useUnifiedTopology: true});
    const username = req.params.user
    Profiles.find({username: username}, function (err, profiles) {
        if (profiles.length == 0) {
            res.status(400).send("User not found in database")
            return
        }
        res.status(200).send({
            username: username,
            zipcode: profiles[0].zipcode
        })
    })
}

const putZipcode = (req, res) => {
    const connector = mongoose.connect(connectionString, {useNewUrlParser: true, useUnifiedTopology: true});
    const username = req.username
    const newZipcode = req.body.zipcode
    if (!newZipcode) {
        res.status(400).send('zipcode missing')
    }
    Profiles.updateMany(
        {username: username},
        {$set: {zipcode: newZipcode}},
        {new: true},
        function (err, profiles) {
            res.status(200).send({
                username: username,
                zipcode: newZipcode
            })
        })
}

const getAvatar = (req, res) => {
    const connector = mongoose.connect(connectionString, {useNewUrlParser: true, useUnifiedTopology: true});
    let username = req.params.user
    Profiles.find({username: username}, function (err, profiles) {
        if (profiles.length == 0) {
            res.status(400).send("user not found")
            return
        }
        res.status(200).send({
            username: username,
            avatar: profiles[0].avatar
        })
    })
}


const putAvatar = (req, res) => {
    const connector = mongoose.connect(connectionString, {useNewUrlParser: true, useUnifiedTopology: true});
    const username = req.username
    const newAvatar = req.fileurl
    if (!newAvatar) {
        res.status(400).send('avatar missing')
    }
    Profiles.updateMany(
        {username: username},
        {$set: {avatar: newAvatar}},
        {new: true},
        function (err, profiles) {
            res.status(200).send({
                username: username,
                avatar: newAvatar
            })
        })

}

const getDob = (req, res) => {
    const connector = mongoose.connect(connectionString, {useNewUrlParser: true, useUnifiedTopology: true});
    let username = req.params.user
    Profiles.find({username: username}, function (err, profiles) {
        const profileObj = profiles[0];
        res.status(200).send({
            username: username,
            dob: profileObj.dob
        })

    })
}

const getProfile = (req, res) => {
    const connector = mongoose.connect(connectionString, {useNewUrlParser: true, useUnifiedTopology: true});
    let username = req.params.user
    Profiles.find({username: username}, function (err, profiles) {
        const profileObj = profiles[0];
        res.status(200).send({
            username: username,
            profile:  JSON.stringify(profileObj)
        })

    })
}

const index = (req, res) => {
    // console.log(req.params.user)
    res.send({hello: 'world'})
}

module.exports = (app) => {
    app.get('/', index);
    app.put('/headline', putHeadline);
    app.get('/headline/:user?', getHeadline);
    app.put('/email', putEmail);
    app.get('/email/:user?', getEmail);
    app.get('/dob/:user?', getDob);
    app.put('/zipcode', putZipcode);
    app.get('/zipcode/:user?', getZipcode);
    app.put('/avatar', putAvatar);
    app.get('/avatar/:user?', getAvatar);
    app.get('/profile/:user?', getProfile);
}