require('dotenv').config()
const express = require("express");
const bodyParser = require("body-parser");
const ejs = require("ejs");
const mongoose = require("mongoose");
const session = require("express-session");
const passport = require("passport");
const passportLocalMongoose = require("passport-local-mongoose");
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const FacebookStrategy = require('passport-facebook').Strategy;
const findOrCreate = require('mongoose-findorcreate');

const app = express();

app.use(express.static("public"));
app.set('view engine', 'ejs');
app.use(bodyParser.urlencoded({
    extended: true
}));

// Tell app to use express-session package.
app.use(session({
    // Secret is not added in .env file, 'cause .env file is in .gitignore and it could be lost if .env file is deleted.
    secret: process.env.SECRET,
    resave: false,
    saveUninitialized: false
}));

// Tell app to use passport and initialize it.
app.use(passport.initialize());
// Tell app to use passport for dealing with sessions.
app.use(passport.session());

mongoose.connect(process.env.MONGODB_URI);




const userSchema = new mongoose.Schema({
    email: String,
    username: String, // To resolve error caused by findOrCreate module.
    password: String,
    googleId: {
        type: String,
        unique: true
    },
    facebookId: {
        type: String,
        unique: true
    },
    secret: [String]
});

// For using passport-local-mongoose, Add it to mongoose schema as a plugin.
userSchema.plugin(passportLocalMongoose); // This plugin is used to hash and salt a password.
userSchema.plugin(findOrCreate);

// requires the model with Passport-Local Mongoose plugged in
const User = new mongoose.model("User", userSchema);

// use static authenticate method of model in LocalStrategy
// CHANGE: USE "createStrategy" INSTEAD OF "authenticate"
passport.use(User.createStrategy());


// use static serialize and deserialize of model for passport session support
// This version of serialization code works for any stratigy e.g. local, google, etc.
passport.serializeUser(function(user, done) {
    done(null, user.id);
});

passport.deserializeUser(function(id, done) {
    User.findById(id, function(err, user) {
        done(err, user);
    });
});


passport.use(new GoogleStrategy({
        clientID: process.env.CLIENT_ID,
        clientSecret: process.env.CLIENT_SECRET,
        callbackURL: "http://localhost:3000/auth/google/secrets",
        passReqToCallback: true
    },
    function(request, accessToken, refreshToken, profile, done) {
        // console.log(profile);
        User.findOrCreate({ googleId: profile.id, }, function(err, user) {
            return done(err, user);
        });
    }
));

passport.use(new FacebookStrategy({
        clientID: process.env.FACEBOOK_APP_ID,
        clientSecret: process.env.FACEBOOK_APP_SECRET,
        callbackURL: "http://localhost:3000/auth/facebook/secrets"
    },
    function(accessToken, refreshToken, profile, cb) {
        // console.log(profile);
        User.findOrCreate({ facebookId: profile.id }, function(err, user) {
            return cb(err, user);
        });
    }
));

app.get('/', (req, res) => {
    res.render("home");
});

app.get('/auth/google', passport.authenticate('google', { scope: ["profile"] }));

app.get('/auth/google/secrets', passport.authenticate('google', {
    successRedirect: '/secrets',
    failureRedirect: '/login'
}));

app.get('/auth/facebook', passport.authenticate('facebook'));

app.get('/auth/facebook/secrets', passport.authenticate('facebook', { failureRedirect: '/login' }),
    function(req, res) {
        res.redirect('/secrets');
    });

app.get('/login', (req, res) => {
    res.render("login");
});

app.get('/register', (req, res) => {
    res.render("register");
});

app.get('/secrets', (req, res) => {
    let innerHTML = "Loading";
    let href = "/secrets";

    // Fixed: Log Out button even if user is not logged in.
    if (req.isAuthenticated()) {
        innerHTML = "Log Out";
        href = "/logout";
    } else {
        innerHTML = "Log In";
        href = "/login";
    };

    User.find({ 'secret': { $ne: null } }, (err, foundUser) => {
        if (err) {
            console.log(err);
        } else {
            if (foundUser) {
                res.render('secrets', { usersWithSecrets: foundUser, logOutBtnText: innerHTML, logOutBtnLink: href });
            }
        };
    });
});

app.get('/logout', (req, res) => {
    req.logout(() => {
        res.redirect("/");
    });

});

app.get('/submit', (req, res) => {
    if (req.isAuthenticated()) {
        res.render("submit");
    } else {
        res.redirect("/login");
    };
});

app.post('/submit', (req, res) => {
    const submittedSecret = req.body.secret;

    // console.log(req.user) //It is user object saved by passport in http 'req' object.

    User.findById(req.user.id, (err, foundUser) => {
        if (err) {
            console.log(err);
        } else {
            if (foundUser) {
                foundUser.secret.push(submittedSecret);
                foundUser.save(() => { res.redirect('/secrets'); });
            }
        }
    });
});

app.post('/register', (req, res) => {
    User.register({ username: req.body.username }, req.body.password, (err, user) => {
        if (err) {
            console.log(err);
            res.redirect("/register");
        } else {
            passport.authenticate("local")(req, res, function() {
                res.redirect("/secrets");
            });
        }
    });
});

app.post('/login', passport.authenticate('local', { failureRedirect: '/login' }), function(req, res) {
    res.redirect('/secrets');
});

let port = process.env.PORT || 3000;

app.listen(port, function() {
    console.log("Server is started on port", port);
})