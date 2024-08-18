import express from "express";
import bodyParser from "body-parser";
import mysql from "mysql2/promise";
import bcrypt from "bcrypt";
import session from "express-session";
import passport from "passport";
import { Strategy } from "passport-local";


const app = express();
const port = 3000;
const saltRounds = 10;

app.set("view engine", "ejs");

const db = await mysql.createConnection({
  host: 'localhost',
  user: 'root',
  password: 'Pranav@87',
  database: 'secrets',
  port: 3306,
});

app.use(bodyParser.urlencoded({ extended: true }));
app.use(express.static("public"));

app.use(session({
  secret: "RONALDOGOAT",
  resave:false,
  saveUninitialized: true,
  cookie: {
    maxAge: 1000 * 60 * 60 * 24
  }
}));

app.use(passport.initialize());
app.use(passport.session());

app.get("/secrets", (req,res) => {
  console.log(req.user);
  if (req.isAuthenticated()) {
    res.render("secrets.ejs");
  } else {
    res.redirect("/login");
  }
});

app.get("/", (req, res) => {
  res.render("home.ejs");
});

app.get("/login", (req, res) => {
  res.render("login.ejs");
});

app.get("/register", (req, res) => {
  res.render("register.ejs");
});


app.post("/register", async (req, res) => {
  const email = req.body.username;
  const password = req.body.password;

  try {
    const [checkResult] = await db.execute("SELECT * FROM USERS WHERE email = ?", [email]);

    if (checkResult.length > 0) {
      res.send("Email already exists. Try logging in or use a different email.");
    } else {
      // hashing passwords
      bcrypt.hash(password, saltRounds, async (err, hash) => {
        if (err) {
          console.log("Error hashing password:", err);
          res.status(500).send("Server Error");
        } else {
        //inserting new user
        const [result] = await db.execute(
        "INSERT INTO USERS (email, password) VALUES (?, ?)",
        [email, hash]
        );
        //Retrieve the newly inserted user.
        //below sql auery is used to get hold of newly inserted data by user.
        //and use that data with passport method to get persistance.
        const [userResult] = await db.execute(
          "SELECT * FROM USERS WHERE ID = LAST_INSERT_ID()"
        );
        const user = userResult[0]; //// This gets the newly inserted user
        //passport method to persist login
        req.login(user, (err) => {
          if (err) {
          console.error(err);
          res.status(500).send("server error.");
        }else {
          res.redirect("/secrets");
        }
      });
    }
  });
}
  } catch (err) {
    console.error('Error during registration:', err);
    res.status(500).send("Server Error");
  }
});

//direct calling passport function here with local option set
//to perform options after login attempt
app.post("/login",passport.authenticate("local",{
  successRedirect: "/secrets",
  failureRedirect: "/login",
}));
//used to validate user already in db 
//passport automatically check parameters her username,pass
//basically doesn't need bodyparser to get hold of user input data
//passport triggers when we try authenticate user 
passport.use( new Strategy(async function verify(username,password, cb) {
  try {
    // console.log(`Attempting login with email: ${email}`);

    const [rows] = await db.execute("SELECT * FROM USERS WHERE email = ?", [username]);

    // Debugging output to check the results of the query
    // console.log(`Query result: ${JSON.stringify(rows)}`);

    if (rows.length > 0) {
      const user = rows[0];
      const dbHahsedPassword = user.password; //column name is 'password'

      bcrypt.compare(password, dbHahsedPassword, (err,isValid) =>{
        //Error with password check
        if (err) {
          console.error("Error comparing passwords:", err);
          return cb(err);
        } 
          if (isValid) {
            //Passed password check
            return cb(null,user);
          } else {
            //Did not pass password check
            return cb(null,false);
          }
        });
    } else {
      return cb(err);
    }
  } catch (err) {
    console.error('Error during login:', err);
    res.status(500).send("Server Error");
  }
}))

//to save data of user that logged in to local storage
passport.serializeUser((user,cb) => {
  cb(null,user);
});

passport.deserializeUser((user,cb) => {
  cb(null,user);
});

app.listen(port, () => {
  console.log(`Server running on port ${port}`);
});
