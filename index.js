const express = require("express");
const helmet = require("helmet");
const cors = require("cors");
const bcrypt = require("bcryptjs");
const session = require("express-session");
// const KnexSessionStore = require('KnexSessionStore')(session);

const db = require("./database/dbConfig.js");
const Users = require("./users/users-model.js");
const protected = require("./auth/protected-middleware.js");

const server = express();

const sessionConfig = {
  name: "monster", // default would be sid
  secret: "keep it secret, keep it safe!",
  cookie: {
    httpOnly: true, // true means prevent access from JS code
    maxAge: 1000 * 60 * 2, // in milliseconds
    secure: false // true means only send the cookie over https
  },
  resave: false, // resave session even if it didn't change?
  saveUninitialized: true // create new sessions automatically, make sure to comply with the law
};

server.use(session(sessionConfig));
server.use(helmet());
server.use(express.json());
server.use(cors());

// Register
server.post("/api/register", (req, res) => {
  let user = req.body;
  const hash = bcrypt.hashSync(user.password, 8);
  user.password = hash;

  Users.add(user)
    .then(saved => {
      res.status(201).json(saved);
    })
    .catch(error => {
      res.status(500).json(error);
    });
});

// Login
server.post("/api/login", (req, res) => {
  let { username, password } = req.body;

  Users.findBy({ username })
    .first()
    .then(user => {
      if (user && bcrypt.compareSync(password, user.password)) {
        req.session.username = user.username;
        // cookie is sent by express-sessions library
        res
          .status(200)
          .json({ message: `Welcome ${user.username}, here's a cookie!` });
      } else {
        res.status(401).json({ message: "Invalid Credentials" });
      }
    })
    .catch(error => {
      res.status(500).json(error);
    });
});

// GET users
server.get("/api/users", protected, (req, res) => {
  Users.find()
    .then(users => {
      res.json(users);
    })
    .catch(error => res.send(error));
});

// Logout
server.get("/api/logout", (req, res) => {
  if (req.session) {
    req.session.destroy(err => {
      if (err) {
        res.send(
          "you can checkout anytime you like, but you can never leave..."
        );
      } else {
        res.send("bye");
      }
    });
  } else {
    res.end();
    //res.send('already logged out');
  }
});

// server check
server.get("/", (req, res) => {
  const username = req.session.username || "stranger";
  res.send(`Hello ${username}!`);
});

const port = process.env.PORT || 5000;
server.listen(port, () => console.log(`\n** Running on port ${port} **\n`));
