require('dotenv').config();
const express = require("express");
const ejs = require("ejs");
const bodyParser = require("body-parser");
const mongoose= require("mongoose");
// const bcrypt = require('bcrypt');
// const saltRounds = 10;
const session = require('express-session');
const passport=require("passport");
const passportlocalmongoose =require("passport-local-mongoose");
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const FacebookStrategy = require('passport-facebook').Strategy;
const findOrCreate = require('mongoose-findorcreate');

const app = express();
app.set('view engine', 'ejs');

app.use(bodyParser.urlencoded({ extended: true }));
app.use(express.static("public"));
mongoose.connect("mongodb://127.0.0.1:27017/userDB",{useNewUrlParser: true});

app.use(session({
    secret: 'my little secret.',
    resave: false,
    saveUninitialized: true,
}));

app.use(passport.initialize());
app.use(passport.session());

const userSchema = new mongoose.Schema({
  email: { type: String, unique: true },
  username:String,
  password: String,
  googleId: String,
  facebookId:String,
  secret:String
});

userSchema.plugin(findOrCreate);


userSchema.plugin(passportlocalmongoose);  

 
const User =new mongoose.model("User",userSchema); 

passport.use(User.createStrategy());

passport.serializeUser(function(user, cb) {
    process.nextTick(function() {
      cb(null, { id: user.id, email: user.username, name: user.name });
    });
  });
  
  passport.deserializeUser(function(user, cb) {
    process.nextTick(function() {
      return cb(null, user);
    });
  });

  passport.use(new FacebookStrategy({
    clientID: process.env.FCLIENT_ID, 
    clientSecret: process.env.FCLIENT_SECRET, 
    callbackURL: "http://localhost:3000/auth/facebook/secrets", 
  }, function(accessToken, refreshToken, profile, cb) {
    console.log(profile); 
    User.findOrCreate({ facebookId: profile.id }, function (err, user) {
      return cb(err, user); 
    });
  }));
  

passport.use(new GoogleStrategy({
    clientID: process.env.CLIENT_ID,
    clientSecret: process.env.CLIENT_SECRET,
    callbackURL: "http://localhost:3000/auth/google/secrets"
  }
  ,
  
  function(accessToken, refreshToken, profile, cb) {
    console.log(profile);
    User.findOrCreate({ googleId: profile.id }, function (err, user) {
      return cb(err, user);
    });
  }
));

app.get("/", function (req, res) {
    res.render("home");
});

app.get("/auth/facebook",
  passport.authenticate("facebook", { scope: ["email"] }));

app.get("/auth/facebook/secrets",
  passport.authenticate("facebook", { failureRedirect: "/login" }),
  function(req, res) {
    res.redirect("/secrets");
  });

app.get("/auth/google",
  passport.authenticate("google",{ scope: ["profile email"] })
  );

  app.get("/auth/google/secrets", 
  passport.authenticate("google", { failureRedirect: "/login" }),
  function(req, res) {
    // Successful authentication, redirect secrets.
    res.redirect("/secrets");
  });

app.get("/login", function (req, res) {
    res.render("login");
});

app.get("/register", function (req, res) {
    res.render("register");
});

app.get("/secrets", function (req, res) {
  User.find({"secret": {$ne: null}})
    .then(function(foundUsers) {
      if (foundUsers) {
        res.render("secrets", { UserWithSecrets: foundUsers });
      }
    })
    .catch(function(err) {
      console.log(err);
    });
});


app.get("/submit",function(req,res){
  if (req.isAuthenticated()) {
    res.render("submit");
  }else{
  res.redirect("/login");
}  
});

app.post("/submit", function(req, res) {
  const userSecret = req.body.secret;
  const userId = req.user.id;

  // Find the user by ID and update the secret field
  User.findByIdAndUpdate(userId, { secret: userSecret }, { new: true, upsert: true })
    .then(function(updatedUser) {
      console.log("User secret assigned successfully:", updatedUser);
      res.redirect("/secrets");
    })
    .catch(function(err) {
      // Handle errors, e.g., user not found or database save error
      console.error("Error assigning user secret:", err);
      res.redirect("/secrets");
    });
});


app.get("/logout", function(req, res) {
    
    req.logout(function(err) {
        if (err) {
            console.log(err);
        }else{
        
        res.redirect("/");
        }
    });
});


app.post("/register", function(req, res) {
  const email = req.body.email;
  const username = req.body.username;
  const password = req.body.password;

  User.register({ email: email, username: username }, password, function(err, user) {
    if (err) {
      console.log(err);
      res.render("register", { errorMessage: "Registration failed. Please try again." });
    } else {
      passport.authenticate("local")(req, res, function() {
        res.redirect("/secrets");
      });
    }
  });
});




app.post("/login", function(req, res) {
    const email = req.body.username;
    const password = req.body.password;
    const username=req.body.username;

    User.authenticate()(email, password, function(err, user) {
        if (err) {
            console.log(err);
            return res.redirect("/login");
        }
        if (!user) {
            
            return res.redirect("/login");
        }
        req.logIn(user, function(err) {
            if (err) {
                console.log(err);
                return res.redirect("/login");
            }
            
            return res.redirect("/secrets");
        });
    });
  });

app.listen(3000, function () {
    console.log("Your server is started on port 3000");
});
