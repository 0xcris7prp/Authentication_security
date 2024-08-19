import express from "express";
import bodyParser from "body-parser";
import mysql from "mysql2/promise";
import bcrypt from "bcrypt";
import passport from "passport";
import { Strategy as LocalStrategy } from "passport-local";
import { Strategy as GoogleStrategy } from "passport-google-oauth2";
import session from "express-session";
import env from "dotenv";

const app = express();
const port = 3000;
const saltRounds = 10;
env.config();

app.use(
  session({
    secret: process.env.SESSION_SECRET,
    resave: false,
    saveUninitialized: true,
  })
);
app.use(bodyParser.urlencoded({ extended: true }));
app.use(express.static("public"));

app.use(passport.initialize());
app.use(passport.session());

const db = await mysql.createConnection({
  host: process.env.MYSQL_HOST,
  user: process.env.MYSQL_USER,
  password: process.env.MYSQL_PASSWORD,
  database: process.env.MYSQL_DATABASE,
  port: process.env.MYSQL_PORT,
});

// Routes

app.get("/", (req, res) => {
  res.render("home.ejs");
});

app.get("/login", (req, res) => {
  res.render("login.ejs");
});

app.get("/register", (req, res) => {
  res.render("register.ejs");
});

app.get("/logout", (req, res) => {
  req.logout(function (err) {
    if (err) {
      return next(err);
    }
    res.redirect("/");
  });
});

//TODO: Update this to pull in the user secret to render in secrets.ejs
//show secrets to user who updated their own
//if not then show msg to write your secret
//need to check in db if user has any secret
app.get("/secrets", async (req, res) => {
  console.log(req.user); // Log the authenticated user's data
  if (req.isAuthenticated()) {
    try {
      const [result] = await db.query("SELECT secret FROM USERS WHERE email=?", [req.user.email]);
      console.log(result);
      const secret = result[0]?.secret;
      if (secret) {
        res.render("secrets.ejs", { secret: secret });
      } else {
        res.render("secrets.ejs", { secret: "Enter your secret here." });
      }
    } catch (error) {
      console.error("Error fetching secret:", error);
      res.status(500).send("Server Error");
    }
  } else {
    res.redirect("/login");
  }
});


// Submit route
app.get("/submit", (req, res) => {
  if (req.isAuthenticated()) {
    res.render("submit.ejs");
  } else {
    res.redirect("/login");
  }
});

app.post("/submit", async (req, res) => {
  const submittedSecret = req.body.secret;
  console.log(req.user); // Log the authenticated user's data

  if (!req.user) {
    return res.redirect("/login");
  }

  try {
    await db.query("UPDATE USERS SET secret = ? WHERE email = ?", [submittedSecret, req.user.email]);
    res.redirect("/secrets");
  } catch (error) {
    console.error("Error updating secret:", error);
    res.status(500).send("Server Error");
  }
});

// Authentication routes
app.get(
  "/auth/google",
  passport.authenticate("google", {
    scope: ["profile", "email"],
  })
);

app.get(
  "/auth/google/secrets",
  passport.authenticate("google", {
    successRedirect: "/secrets",
    failureRedirect: "/login",
  })
);

app.post(
  "/login",
  passport.authenticate("local", {
    successRedirect: "/secrets",
    failureRedirect: "/login",
  })
);

app.post("/register", async (req, res) => {
  const email = req.body.username;
  const password = req.body.password;

  try {
    const [checkResult] = await db.execute("SELECT * FROM USERS WHERE email = ?", [email]);

    if (checkResult.length > 0) {
      res.send("Email already exists. Try logging in or use a different email.");
    } else {
      const hash = await bcrypt.hash(password, saltRounds);
      await db.execute("INSERT INTO USERS (email, password) VALUES (?, ?)", [email, hash]);

      const [userResult] = await db.execute("SELECT * FROM USERS WHERE id = LAST_INSERT_ID()");
      const user = userResult[0];
      req.login(user, (err) => {
        if (err) {
          console.error("Login error:", err);
          res.status(500).send("Server Error");
        } else {
          res.redirect("/secrets");
        }
      });
    }
  } catch (err) {
    console.error("Error during registration:", err);
    res.status(500).send("Server Error");
  }
});

// Passport Configuration

passport.use(
  new LocalStrategy(async function verify(username, password, cb) {
    try {
      const [rows] = await db.execute("SELECT * FROM USERS WHERE email = ?", [username]);
      if (rows.length > 0) {
        const user = rows[0];
        const dbHashedPassword = user.password;

        const isValid = await bcrypt.compare(password, dbHashedPassword);
        if (isValid) {
          return cb(null, user);
        } else {
          return cb(null, false);
        }
      } else {
        return cb(null, false);
      }
    } catch (err) {
      console.error("Error during login:", err);
      return cb(err);
    }
  })
);

passport.use(
  new GoogleStrategy(
    {
      clientID: process.env.GOOGLE_CLIENT_ID,
      clientSecret: process.env.GOOGLE_CLIENT_SECRET,
      callbackURL: "http://localhost:3000/auth/google/secrets",
      userProfileURL: "https://www.googleapis.com/oauth2/v3/userinfo",
    },
    async (accessToken, refreshToken, profile, cb) => {
      try {
        const [result] = await db.query("SELECT * FROM USERS WHERE email = ?", [profile.email]);
        if (result.length === 0) {
          const [newUser] = await db.query("INSERT INTO USERS (email, password) VALUES (?, ?)", [
            profile.email,
            "google",
          ]);
          return cb(null, newUser[0]);
        } else {
          return cb(null, result[0]);
        }
      } catch (err) {
        console.error("Error during Google authentication:", err);
        return cb(err);
      }
    }
  )
);

passport.serializeUser((user, cb) => {
  cb(null, user.id);
});

passport.deserializeUser(async (id, cb) => {
  try {
    const [rows] = await db.execute("SELECT * FROM USERS WHERE id = ?", [id]);
    if (rows.length > 0) {
      cb(null, rows[0]);
    } else {
      cb(new Error("User not found"));
    }
  } catch (err) {
    cb(err);
  }
});

// Start the server
app.listen(port, () => {
  console.log(`Server running on port ${port}`);
});
