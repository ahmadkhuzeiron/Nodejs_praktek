const express = require('express');
const session = require('express-session');
const passport = require('passport');
const LocalStrategy = require('passport-local').Strategy;
const flash = require('connect-flash');
const User = require('./models/user');
const sequelize = require('./database/connection');

const app = express();

// Middleware
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Konfigurasi session
app.use(
  session({
    secret: 'your_session_secret',
    resave: false,
    saveUninitialized: false
  })
);

// Konfigurasi Passport.js
app.use(passport.initialize());
app.use(passport.session());
app.use(flash());

passport.use(
  new LocalStrategy(
    async (username, password, done) => {
      try {
        const user = await User.findOne({ where: { username } });

        if (!user) {
          return done(null, false, { message: 'Incorrect username.' });
        }

        if (user.password !== password) {
          return done(null, false, { message: 'Incorrect password.' });
        }

        return done(null, user);
      } catch (error) {
        return done(error);
      }
    }
  )
);

passport.serializeUser((user, done) => {
  done(null, user.id);
});

passport.deserializeUser(async (id, done) => {
  try {
    const user = await User.findByPk(id);
    done(null, user);
  } catch (error) {
    done(error);
  }
});

// Routes
app.get('/login', (req, res) => {
  res.send(`
    <h1>Login</h1>
    <form method="post" action="/login">
      <input type="text" name="username" placeholder="Username" required /><br />
      <input type="password" name="password" placeholder="Password" required /><br />
      <button type="submit">Login</button>
    </form>
  `);
});

app.post('/login', passport.authenticate('local', {
  successRedirect: '/profile',
  failureRedirect: '/login',
  failureFlash: true
}), async (req, res) => {
  try {
    const { username, password } = req.body;
    const existingUser = await User.findOne({ where: { username } });

    if (existingUser) {
      req.flash('error', 'Username already exists.');
      return res.redirect('/login');
    }

    await User.create({ username, password });
    res.redirect('/profile');
  } catch (error) {
    console.error(error);
    res.redirect('/login');
  }
});

app.get('/profile', (req, res) => {
  if (req.isAuthenticated()) {
    res.send('Profile page');
  } else {
    res.redirect('/login');
  }
});

app.get('/', (req, res) => {
  res.send('Home page');
});

// Sinkronisasi model dengan database
sequelize.sync().then(() => {
  app.listen(3000, () => {
    console.log('Server berjalan pada http://localhost:3000');
  });
});
